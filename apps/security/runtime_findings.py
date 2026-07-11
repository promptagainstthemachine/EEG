"""Synthesize runtime detection findings from gateway traces."""

from __future__ import annotations

from typing import Any

from apps.security.models import AITrace

_SURFACE_LABEL = {
    "llm_call": "Prompt",
    "tool_call": "Tool call",
    "retrieval": "RAG",
    "embedding": "Embedding",
    "mcp_tool": "MCP",
    "agent_control": "Agent control",
    "agent_action": "Agent action",
}


def _threat_level(trace: AITrace) -> str:
    meta = trace.metadata or {}
    if meta.get("blocked_by_policy") or trace.status == AITrace.Status.BLOCKED:
        return "critical" if trace.risk_score >= 0.85 else "high"
    if trace.risk_score >= 0.85:
        return "critical"
    if trace.risk_score >= 0.7:
        return "high"
    if trace.risk_score >= 0.4:
        return "medium"
    return "low"


def list_runtime_finding_dicts(
    org,
    *,
    limit: int = 200,
    project=None,
) -> list[dict[str, Any]]:
    """Return finding-shaped dicts derived from high-risk / blocked traces.

    When ``project`` is set, only traces for that project are included.
    When ``project`` is None, returns an empty list (no org-wide blend).
    """
    if org is None or project is None:
        return []

    qs = (
        AITrace.objects.filter(organization=org, project=project)
        .order_by("-started_at")[: max(limit * 3, 100)]
    )
    out: list[dict[str, Any]] = []
    for t in qs:
        meta = t.metadata or {}
        blocked = bool(meta.get("blocked_by_policy") or t.status == AITrace.Status.BLOCKED)
        interesting = blocked or float(t.risk_score or 0) >= 0.4 or t.trace_type in (
            AITrace.TraceType.TOOL_CALL,
            AITrace.TraceType.MCP_TOOL,
            AITrace.TraceType.RETRIEVAL,
            AITrace.TraceType.AGENT_CONTROL,
        )
        if not interesting:
            continue
        surface = _SURFACE_LABEL.get(t.trace_type, t.trace_type)
        tags = meta.get("detection_tags") or t.risk_signals or []
        # Prefer a short primary tag; avoid dumping long tag lists into the title.
        primary = ""
        for tag in tags:
            s = str(tag).strip()
            if s and s.lower() not in {t.trace_type.lower(), "agent_control", "tool", "mcp"}:
                primary = s
                break
        if not primary and tags:
            primary = str(tags[0])
        tool = str(meta.get("tool_name") or meta.get("mcp_tool") or "").strip()
        if blocked:
            title = f"Blocked {surface}"
        else:
            title = f"Runtime {surface}"
        if tool:
            title = f"{title}: {tool}"
        elif primary:
            title = f"{title}: {primary}"
        sev = _threat_level(t)
        started_display = ""
        if t.started_at:
            started_display = t.started_at.strftime("%b %d, %H:%M").replace(" 0", " ")
        from eeg.gateway.prompt_text import display_prompt_preview

        prompt_preview = display_prompt_preview(t.input_text or "")
        out.append(
            {
                "id": str(t.id),
                "rule_id": f"runtime.{t.trace_type}",
                "title": title[:160],
                "severity": sev,
                "status": "open",
                "category": f"runtime_{t.trace_type}",
                "source": "runtime",
                "file_path": "",
                "description": prompt_preview[:2000],
                "recommendation": "Review agent traffic and apply pause/quarantine if needed.",
                "trace_type": t.trace_type,
                "surface_label": surface,
                "trace_id": t.trace_id,
                "risk_score": t.risk_score,
                "provider": t.provider,
                "model": (t.model or "")[:64],
                "started_at": t.started_at.isoformat() if t.started_at else None,
                "started_display": started_display,
                "metadata": meta,
                "project_id": t.project_id,
            }
        )
        if len(out) >= limit:
            break
    return out
