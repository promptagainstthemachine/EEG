"""Agent pause / start / quarantine with gateway blocklist enforcement (OSS)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import uuid4

from django.db import transaction
from django.utils import timezone as dj_tz

from apps.security.models import AITrace, ManagedAgent
from apps.security.trace_ingest import ingest_traces

CONTROL_ACTIONS = frozenset({"pause", "start", "quarantine"})
BLOCKING_STATUSES = frozenset(
    {ManagedAgent.ControlStatus.PAUSED, ManagedAgent.ControlStatus.QUARANTINED}
)


def normalize_agent_key(ref: str) -> str:
    raw = (ref or "").strip()
    if not raw:
        return ""
    return raw if raw.startswith("runtime:") else f"runtime:{raw}"


def _policy_config(org) -> dict[str, Any]:
    raw = getattr(org, "runtime_policy_config", None) or {}
    return dict(raw) if isinstance(raw, dict) else {}


def blocked_agent_keys(org) -> set[str]:
    cfg = _policy_config(org)
    keys = cfg.get("blocked_agent_keys") or []
    return {str(k).strip() for k in keys if str(k).strip()}


def agent_identities(agent: ManagedAgent) -> set[str]:
    keys = {agent.agent_key}
    meta = agent.metadata or {}
    for field in ("requester_ids", "aliases", "linked_ids"):
        vals = meta.get(field) or []
        if isinstance(vals, (list, tuple)):
            keys.update(str(v).strip() for v in vals if str(v).strip())
    for field in ("display_name", "name", "gateway_label", "requester"):
        val = meta.get(field) or getattr(agent, field, "")
        if val:
            keys.add(str(val).strip())
    if agent.agent_key.startswith("runtime:"):
        keys.add(agent.agent_key[8:])
    return {k for k in keys if k}


def is_agent_blocked(org, agent_ref: str | None) -> tuple[bool, str]:
    """Return (blocked, status) for a gateway agent identity."""
    ref = (agent_ref or "").strip()
    if not ref:
        return False, ""
    canonical = normalize_agent_key(ref)
    agent = (
        ManagedAgent.objects.filter(organization=org, agent_key=canonical)
        .only("control_status", "metadata", "agent_key", "name")
        .first()
    )
    if agent and agent.control_status in BLOCKING_STATUSES:
        return True, agent.control_status
    # Match aliases stored on any blocked agent
    for row in ManagedAgent.objects.filter(
        organization=org, control_status__in=list(BLOCKING_STATUSES)
    ):
        if ref in agent_identities(row):
            return True, row.control_status
    if ref in blocked_agent_keys(org) or f"runtime:{ref}" in blocked_agent_keys(org):
        return True, "blocklist"
    return False, ""


def ensure_agent(
    org,
    agent_key: str,
    *,
    name: str = "",
    metadata: dict[str, Any] | None = None,
) -> ManagedAgent | None:
    raw = (agent_key or "").strip()
    if not raw:
        return None
    key = normalize_agent_key(raw)[:255]
    bare = key[8:] if key.startswith("runtime:") else key
    display = (name or bare or key).strip()
    if display.startswith("runtime:"):
        display = display[8:]
    display = display[:255] or key

    defaults: dict[str, Any] = {
        "name": display,
        "last_seen_at": dj_tz.now(),
    }
    if metadata:
        defaults["metadata"] = metadata

    agent = ManagedAgent.objects.filter(organization=org, agent_key=key).first()
    created = False
    if bare and bare != key:
        legacy = ManagedAgent.objects.filter(organization=org, agent_key=bare).first()
        if legacy and agent is not None and legacy.pk != agent.pk:
            merged = dict(agent.metadata or {})
            merged.update(legacy.metadata or {})
            aliases = list(merged.get("aliases") or [])
            for alias in (bare, legacy.name, display):
                if alias and alias not in aliases:
                    aliases.append(alias)
            merged["aliases"] = aliases[:32]
            agent.metadata = merged
            if not agent.name or agent.name in (key, bare):
                agent.name = display or legacy.name
            agent.last_seen_at = dj_tz.now()
            agent.save(update_fields=["metadata", "name", "last_seen_at", "updated_at"])
            legacy.delete()
        elif legacy and agent is None:
            legacy.agent_key = key
            if not legacy.name or legacy.name in (bare, key):
                legacy.name = display
            legacy.last_seen_at = dj_tz.now()
            legacy.save(update_fields=["agent_key", "name", "last_seen_at", "updated_at"])
            agent = legacy

    if agent is None:
        agent, created = ManagedAgent.objects.get_or_create(
            organization=org,
            agent_key=key,
            defaults=defaults,
        )

    if not created and agent is not None:
        updates = ["last_seen_at", "updated_at"]
        agent.last_seen_at = dj_tz.now()
        if name and (not agent.name or agent.name in (key, bare, f"runtime:{bare}")):
            agent.name = display
            updates.append("name")
        if metadata:
            merged = dict(agent.metadata or {})
            merged.update(metadata)
            agent.metadata = merged
            updates.append("metadata")
        agent.save(update_fields=updates)

    try:
        from apps.projects.gateway_sync import ensure_gateway_project

        ensure_gateway_project(org, agent.agent_key, name=agent.name or agent.agent_key)
    except Exception:
        # Project sync must not break gateway ingest.
        pass
    return agent


def _sync_blocklist(org, agent: ManagedAgent) -> None:
    cfg = _policy_config(org)
    keys = set(str(k) for k in (cfg.get("blocked_agent_keys") or []) if str(k).strip())
    identities = agent_identities(agent)
    if agent.control_status in BLOCKING_STATUSES:
        keys |= identities
        keys |= {f"runtime:{k}" for k in identities}
    else:
        keys -= identities
        keys -= {f"runtime:{k}" for k in identities}
    cfg["blocked_agent_keys"] = sorted(keys)
    org.runtime_policy_config = cfg
    org.save(update_fields=["runtime_policy_config"])


def _emit_control_trace(org, agent: ManagedAgent, action: str) -> None:
    if not getattr(org, "realtime_telemetry_enabled", True):
        return
    now = datetime.now(timezone.utc)
    ingest_traces(
        org,
        [
            {
                "trace_id": f"ctrl-{uuid4().hex[:16]}",
                "span_id": f"span-{uuid4().hex[:12]}",
                "trace_type": "agent_control",
                "status": "success",
                "provider": "eeg",
                "model": "",
                "input_text": f"agent_control:{action}:{agent.agent_key}",
                "output_text": agent.control_status,
                "risk_score": 1.0 if action == "quarantine" else 0.4 if action == "pause" else 0.0,
                "risk_signals": ["agent_control", action],
                "latency_ms": 0,
                "started_at": now.isoformat(),
                "session_id": f"agent-{agent.agent_key}",
                "metadata": {
                    "source": "agent_control",
                    "agent_key": agent.agent_key,
                    "action": action,
                    "control_status": agent.control_status,
                    "detection_tags": ["agent_control", action],
                },
            }
        ],
    )


@transaction.atomic
def control_agent(org, agent_id: str, action: str) -> dict[str, Any]:
    action = (action or "").strip().lower()
    if action not in CONTROL_ACTIONS:
        raise ValueError("action must be pause, start, or quarantine")
    agent = ManagedAgent.objects.select_for_update().get(organization=org, pk=agent_id)
    status_map = {
        "start": ManagedAgent.ControlStatus.ACTIVE,
        "pause": ManagedAgent.ControlStatus.PAUSED,
        "quarantine": ManagedAgent.ControlStatus.QUARANTINED,
    }
    agent.control_status = status_map[action]
    agent.last_control_action = action
    agent.last_control_error = ""
    agent.save(
        update_fields=[
            "control_status",
            "last_control_action",
            "last_control_error",
            "updated_at",
        ]
    )
    _sync_blocklist(org, agent)
    _emit_control_trace(org, agent, action)
    return {
        "id": str(agent.id),
        "agent_key": agent.agent_key,
        "name": agent.name,
        "control_status": agent.control_status,
        "action": action,
        "runtime_only": True,
    }


def list_agents(org) -> list[dict[str, Any]]:
    from django.conf import settings

    rows = ManagedAgent.objects.filter(organization=org).order_by("-updated_at")
    now = dj_tz.now()
    window = int(getattr(settings, "EEG_GATEWAY_CONNECTED_WINDOW_SECONDS", 900))
    out: list[dict[str, Any]] = []
    for a in rows:
        seen = a.last_seen_at
        if seen is None:
            seen_label = "Never"
            live = False
        else:
            age = max(0, int((now - seen).total_seconds()))
            live = age <= window
            if age < 60:
                seen_label = "Just now"
            elif age < 3600:
                seen_label = f"{age // 60}m ago"
            elif age < 86400:
                seen_label = f"{age // 3600}h ago"
            else:
                seen_label = f"{age // 86400}d ago"
        status = a.control_status
        if status == ManagedAgent.ControlStatus.ACTIVE:
            status_label = "Running" if live else "Idle"
        elif status == ManagedAgent.ControlStatus.PAUSED:
            status_label = "Paused"
        else:
            status_label = "Quarantined"
        out.append(
            {
                "id": str(a.id),
                "agent_key": a.agent_key,
                "name": a.name or a.agent_key,
                "control_status": status,
                "status_label": status_label,
                "framework": a.framework,
                "last_seen_at": seen.isoformat() if seen else None,
                "last_seen_label": seen_label,
                "is_live": live,
                "last_control_action": a.last_control_action,
                "metadata": a.metadata or {},
            }
        )
    return out


def resolve_agent_ref(request, body: dict | None = None) -> str:
    """
    Resolve the gateway agent identity from headers or request body.

    Accepted locations (first match wins):
    - ``X-EEG-Agent`` / ``X-EEG-Agent-Id`` / ``X-Agent-Id`` headers
    - ``X-EEG-Gateway-Label`` header (standard for pass-through gateway clients)
    - top-level ``agent_id`` / ``agent_key`` / ``agent`` / ``user`` (OpenAI field)
    - ``metadata.agent_id`` / ``metadata.agent_key`` / ``metadata.agent``
    - ``eeg.agent_id`` extension field
    """
    body = body or {}
    header = (
        request.headers.get("X-EEG-Agent")
        or request.headers.get("X-EEG-Agent-Id")
        or request.headers.get("X-Agent-Id")
        or request.headers.get("X-EEG-Gateway-Label")
        or ""
    )
    meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    eeg = body.get("eeg") if isinstance(body.get("eeg"), dict) else {}
    raw = (
        header
        or body.get("agent_id")
        or body.get("agent_key")
        or body.get("agent")
        or body.get("user")
        or body.get("gateway_label")
        or meta.get("agent_id")
        or meta.get("agent_key")
        or meta.get("agent")
        or eeg.get("agent_id")
        or eeg.get("agent_key")
        or ""
    )
    return str(raw).strip()


def touch_agent_from_request(
    org,
    request,
    body: dict | None = None,
    *,
    name: str = "",
) -> ManagedAgent | None:
    """Auto-register / refresh a ManagedAgent whenever gateway traffic carries an identity."""
    body = body or {}
    ref = resolve_agent_ref(request, body)
    if not ref:
        return None
    key = normalize_agent_key(ref)
    meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    gateway_label = (request.headers.get("X-EEG-Gateway-Label") or ref).strip()
    display = (
        name
        or str(meta.get("name") or meta.get("display_name") or "").strip()
        or gateway_label
        or ref
    )
    framework = str(meta.get("framework") or "").strip()
    merged_meta = dict(meta) if meta else {}
    merged_meta.setdefault("source", "gateway")
    merged_meta.setdefault("gateway_label", gateway_label)
    merged_meta.setdefault("requester", display)
    aliases = list(merged_meta.get("aliases") or [])
    for alias in (display, ref, gateway_label):
        if alias and alias not in aliases:
            aliases.append(alias)
    merged_meta["aliases"] = aliases[:32]
    agent = ensure_agent(
        org,
        key,
        name=display,
        metadata=merged_meta,
    )
    if agent and framework and not agent.framework:
        agent.framework = framework[:128]
        agent.save(update_fields=["framework", "updated_at"])
    return agent
