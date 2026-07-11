"""Ingest AI observability traces from the REST API / SDK."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.models import AITrace
from eeg.runtime.policy import evaluate_policy
from eeg.runtime.risk_scorer import merge_client_and_server_risk, score_trace_content

MAX_BATCH_SIZE = 100

TRACE_TYPES = {c.value for c in AITrace.TraceType}
TRACE_STATUSES = {c.value for c in AITrace.Status}

# When policy enforcement is on, reject ingest for traces above this risk or with critical policy signals.
_POLICY_INGEST_RISK_THRESHOLD = 0.75


def _trace_json(trace: AITrace) -> dict:
    return {
        "id": str(trace.id),
        "trace_id": trace.trace_id,
        "span_id": trace.span_id,
        "parent_span_id": trace.parent_span_id,
        "trace_type": trace.trace_type,
        "status": trace.status,
        "provider": trace.provider,
        "model": trace.model,
        "session_id": trace.session_id,
        "user_id": trace.user_id,
        "input_tokens": trace.input_tokens,
        "output_tokens": trace.output_tokens,
        "latency_ms": trace.latency_ms,
        "risk_score": trace.risk_score,
        "project_id": trace.project_id,
        "started_at": trace.started_at.isoformat(),
        "completed_at": trace.completed_at.isoformat() if trace.completed_at else None,
    }


def _parse_dt(value: Any, field: str, errors: Dict[str, str]) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = parse_datetime(str(value))
    if dt is None:
        errors[field] = "Invalid ISO 8601 datetime"
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def _coerce_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_decimal(value: Any) -> Optional[Decimal]:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _resolve_agent_key(data: dict) -> str:
    """Extract gateway agent identity from top-level fields or metadata."""
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    raw = (
        data.get("agent_id")
        or data.get("agent_key")
        or data.get("agent")
        or meta.get("agent_id")
        or meta.get("agent_key")
        or meta.get("agent")
        or ""
    )
    return str(raw).strip()


def validate_trace_payload(
    data: dict,
    *,
    organization: Organization,
    index: Optional[int] = None,
) -> Tuple[Optional[dict], Dict[str, str]]:
    """Validate a single trace body. Returns (normalized_fields, errors)."""
    prefix = f"traces[{index}]." if index is not None else ""
    errors: Dict[str, str] = {}

    trace_id = (data.get("trace_id") or "").strip()
    span_id = (data.get("span_id") or "").strip()
    trace_type = (data.get("trace_type") or "").strip()
    status = (data.get("status") or AITrace.Status.SUCCESS).strip()

    if not trace_id:
        errors[f"{prefix}trace_id"] = "Required"
    if not span_id:
        errors[f"{prefix}span_id"] = "Required"
    if not trace_type:
        errors[f"{prefix}trace_type"] = "Required"
    elif trace_type not in TRACE_TYPES:
        errors[f"{prefix}trace_type"] = f"Must be one of: {', '.join(sorted(TRACE_TYPES))}"
    if status and status not in TRACE_STATUSES:
        errors[f"{prefix}status"] = f"Must be one of: {', '.join(sorted(TRACE_STATUSES))}"

    started_at = _parse_dt(data.get("started_at"), f"{prefix}started_at", errors)
    if started_at is None and f"{prefix}started_at" not in errors:
        errors[f"{prefix}started_at"] = "Required"

    completed_at = _parse_dt(data.get("completed_at"), f"{prefix}completed_at", errors)

    project = None
    project_id = data.get("project_id")
    if project_id not in (None, ""):
        try:
            project = Project.objects.get(pk=int(project_id), organization=organization)
        except (Project.DoesNotExist, TypeError, ValueError):
            errors[f"{prefix}project_id"] = "Project not found in this organization"

    metadata = data.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors[f"{prefix}metadata"] = "Must be a JSON object"

    risk_signals = data.get("risk_signals")
    if risk_signals is not None and not isinstance(risk_signals, list):
        errors[f"{prefix}risk_signals"] = "Must be a JSON array"

    if errors:
        return None, errors

    # Attach gateway traffic to the matching runtime project when project_id is absent.
    if project is None:
        agent_key = _resolve_agent_key(data)
        if agent_key:
            from apps.projects.gateway_sync import ensure_gateway_project

            project = ensure_gateway_project(
                organization,
                agent_key,
                name=str(
                    (metadata or {}).get("agent_name")
                    or (metadata or {}).get("name")
                    or agent_key
                ),
            )

    normalized = {
        "trace_id": trace_id[:128],
        "parent_span_id": (data.get("parent_span_id") or "")[:128],
        "span_id": span_id[:128],
        "trace_type": trace_type,
        "status": status or AITrace.Status.SUCCESS,
        "provider": (data.get("provider") or "")[:64],
        "model": (data.get("model") or "")[:128],
        "session_id": (data.get("session_id") or "")[:128],
        "user_id": (data.get("user_id") or "")[:128],
        "input_text": data.get("input_text") or "",
        "output_text": data.get("output_text") or "",
        "input_tokens": _coerce_int(data.get("input_tokens")),
        "output_tokens": _coerce_int(data.get("output_tokens")),
        "latency_ms": _coerce_int(data.get("latency_ms")),
        "cost_usd": _coerce_decimal(data.get("cost_usd")),
        "risk_score": _coerce_float(data.get("risk_score")),
        "risk_signals": risk_signals if isinstance(risk_signals, list) else [],
        "metadata": metadata if isinstance(metadata, dict) else {},
        "started_at": started_at,
        "completed_at": completed_at,
        "project": project,
    }
    return normalized, {}


def apply_server_risk_scoring(normalized: dict):
    """Recompute risk from trace text server-side; do not trust client scores alone."""
    server = score_trace_content(
        input_text=normalized.get("input_text") or "",
        output_text=normalized.get("output_text") or "",
        trace_type=normalized.get("trace_type") or "llm_call",
        metadata=normalized.get("metadata") if isinstance(normalized.get("metadata"), dict) else {},
    )
    score, signals = merge_client_and_server_risk(
        normalized.get("risk_score") or 0,
        normalized.get("risk_signals") or [],
        server,
    )
    normalized["risk_score"] = score
    normalized["risk_signals"] = signals
    meta = dict(normalized.get("metadata") or {})
    meta["server_risk_score"] = server.risk_score
    meta["server_risk_categories"] = server.categories
    normalized["metadata"] = meta
    return server


def trace_violates_org_policy(organization: Organization, normalized: dict) -> Optional[str]:
    """
    Apply server-side scoring and optionally block ingest when policy is enabled.
    """
    enforcement = bool(getattr(organization, "policy_enforcement_enabled", False))
    runtime = bool(getattr(organization, "runtime_protection_enabled", False))

    apply_server_risk_scoring(normalized)

    # Gateway / SDK already recorded a policy block — keep the telemetry row.
    meta = normalized.get("metadata") if isinstance(normalized.get("metadata"), dict) else {}
    if normalized.get("status") == "blocked" or meta.get("blocked_by_policy"):
        return None

    if not enforcement and not runtime:
        return None

    merged_score = float(normalized.get("risk_score") or 0)
    if merged_score >= _POLICY_INGEST_RISK_THRESHOLD:
        return (
            f"Trace risk_score {merged_score:.2f} exceeds the organization policy threshold."
        )

    server = score_trace_content(
        input_text=normalized.get("input_text") or "",
        output_text=normalized.get("output_text") or "",
        trace_type=normalized.get("trace_type") or "llm_call",
        metadata=meta,
    )
    decision = evaluate_policy(
        server,
        phase="ingest",
        enforcement_enabled=enforcement,
        runtime_protection_enabled=runtime,
        ingest_threshold=_POLICY_INGEST_RISK_THRESHOLD,
    )
    if decision.blocked:
        return decision.reason or "Trace blocked by server-side policy enforcement."
    return None


def ingest_traces(
    organization: Organization,
    payloads: List[dict],
) -> Tuple[List[AITrace], Dict[str, str]]:
    """Validate and persist traces. Returns (created_traces, field_errors).

    If field_errors is non-empty, nothing is saved.
    """
    if len(payloads) > MAX_BATCH_SIZE:
        return [], {"traces": f"Maximum {MAX_BATCH_SIZE} traces per request"}

    normalized_list: List[dict] = []
    all_errors: Dict[str, str] = {}

    for i, payload in enumerate(payloads):
        if not isinstance(payload, dict):
            all_errors[f"traces[{i}]"] = "Must be a JSON object"
            continue
        normalized, errors = validate_trace_payload(
            payload, organization=organization, index=i if len(payloads) > 1 else None
        )
        if errors:
            all_errors.update(errors)
        elif normalized:
            normalized_list.append(normalized)

    if all_errors:
        return [], all_errors

    for fields in normalized_list:
        policy_msg = trace_violates_org_policy(organization, fields)
        if policy_msg:
            return [], {"policy": policy_msg}

    created: List[AITrace] = []
    for fields in normalized_list:
        project = fields.pop("project")
        trace = AITrace.objects.create(
            organization=organization,
            project=project,
            **fields,
        )
        created.append(trace)
    return created, {}


def parse_ingest_body(body: dict) -> List[dict]:
    """Accept a single trace object or { \"traces\": [ ... ] }."""
    if "traces" in body:
        traces = body["traces"]
        if not isinstance(traces, list):
            raise ValueError("traces must be an array")
        return traces
    return [body]
