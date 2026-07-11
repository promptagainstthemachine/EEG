"""Dashboard findings timeline aggregation (code + runtime detections)."""

from __future__ import annotations

from datetime import datetime, time, timedelta

from django.db.models import Q
from django.utils import timezone

from apps.security.finding_filters import exclude_vuln_intel_findings
from apps.security.models import AITrace, SecurityFinding

OPEN_STATUSES = [
    SecurityFinding.Status.OPEN,
    SecurityFinding.Status.ACKNOWLEDGED,
    SecurityFinding.Status.IN_PROGRESS,
]

TERMINAL_STATUSES = [
    SecurityFinding.Status.RESOLVED,
    SecurityFinding.Status.FALSE_POSITIVE,
    SecurityFinding.Status.DISMISSED,
]


def _all_code_findings(organization, project=None):
    qs = exclude_vuln_intel_findings(
        SecurityFinding.objects.filter(organization=organization)
    )
    if project is not None:
        qs = qs.filter(project=project)
    return qs


def _timeline_base_qs(organization, project=None):
    return _all_code_findings(organization, project=project).filter(
        status__in=OPEN_STATUSES
    )


def _end_of_day(day):
    tz = timezone.get_current_timezone()
    return timezone.make_aware(datetime.combine(day, time.max), tz)


def _active_on_day(qs, day):
    """Findings that were still open at end of the given calendar day (local TZ)."""
    end = _end_of_day(day)
    return qs.filter(first_seen_at__lte=end).filter(
        Q(status__in=OPEN_STATUSES) | Q(resolved_at__gt=end)
    )


def _runtime_severity(trace: AITrace) -> str:
    meta = trace.metadata if isinstance(trace.metadata, dict) else {}
    if meta.get("blocked_by_policy") or trace.status == AITrace.Status.BLOCKED:
        return "critical" if float(trace.risk_score or 0) >= 0.85 else "high"
    score = float(trace.risk_score or 0)
    if score >= 0.85:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _interesting_runtime_trace(trace: AITrace) -> bool:
    meta = trace.metadata if isinstance(trace.metadata, dict) else {}
    blocked = bool(
        meta.get("blocked_by_policy") or trace.status == AITrace.Status.BLOCKED
    )
    if blocked or float(trace.risk_score or 0) >= 0.4:
        return True
    return trace.trace_type in (
        AITrace.TraceType.TOOL_CALL,
        AITrace.TraceType.MCP_TOOL,
        AITrace.TraceType.RETRIEVAL,
        AITrace.TraceType.AGENT_CONTROL,
        AITrace.TraceType.LLM_CALL,
    ) and (
        blocked
        or float(trace.risk_score or 0) >= 0.4
        or trace.trace_type
        in (
            AITrace.TraceType.TOOL_CALL,
            AITrace.TraceType.MCP_TOOL,
            AITrace.TraceType.RETRIEVAL,
            AITrace.TraceType.AGENT_CONTROL,
        )
    )


def _runtime_day_counts(
    organization, *, days: int, local_today, project=None
) -> dict[object, dict[str, int]]:
    """Map local date -> {critical_high, medium_low} for interesting runtime detections."""
    if not organization or project is None:
        return {}
    start = timezone.make_aware(
        datetime.combine(local_today - timedelta(days=days - 1), time.min),
        timezone.get_current_timezone(),
    )
    qs = AITrace.objects.filter(
        organization=organization,
        project=project,
        started_at__gte=start,
    ).only("started_at", "status", "risk_score", "metadata", "trace_type")

    by_day: dict[object, dict[str, int]] = {}
    for trace in qs.iterator(chunk_size=200):
        if not _interesting_runtime_trace(trace):
            continue
        if not trace.started_at:
            continue
        day = timezone.localtime(trace.started_at).date()
        bucket = by_day.setdefault(day, {"critical_high": 0, "medium_low": 0})
        sev = _runtime_severity(trace)
        if sev in ("critical", "high"):
            bucket["critical_high"] += 1
        else:
            bucket["medium_low"] += 1
    return by_day


def build_findings_timeline(organization, *, days: int = 7, project=None) -> dict:
    """
    Daily finding activity for the dashboard chart.

    Combines open code-security findings with gateway runtime detections.
    """
    days = max(1, min(int(days), 90))
    local_today = timezone.localdate()

    base_qs = _all_code_findings(organization, project=project)
    open_total = _timeline_base_qs(organization, project=project).count()
    runtime_by_day = _runtime_day_counts(
        organization, days=days, local_today=local_today, project=project
    )

    labels: list[str] = []
    critical_high: list[int] = []
    medium_low: list[int] = []
    new_critical_high: list[int] = []
    new_medium_low: list[int] = []

    runtime_open_ch = 0
    runtime_open_ml = 0

    for i in range(days - 1, -1, -1):
        day = local_today - timedelta(days=i)
        day_qs = _active_on_day(base_qs, day)
        new_qs = base_qs.filter(first_seen_at__date=day)

        ch = day_qs.filter(severity__in=["critical", "high"]).count()
        ml = day_qs.filter(severity__in=["medium", "low", "info"]).count()
        nch = new_qs.filter(severity__in=["critical", "high"]).count()
        nml = new_qs.filter(severity__in=["medium", "low", "info"]).count()

        rt = runtime_by_day.get(day) or {"critical_high": 0, "medium_low": 0}
        # Runtime detections that day count as "new"; cumulative toward open series.
        runtime_open_ch += rt["critical_high"]
        runtime_open_ml += rt["medium_low"]
        nch += rt["critical_high"]
        nml += rt["medium_low"]
        ch += runtime_open_ch
        ml += runtime_open_ml

        critical_high.append(ch)
        medium_low.append(ml)
        new_critical_high.append(nch)
        new_medium_low.append(nml)

        if days <= 7:
            labels.append(day.strftime("%a"))
        else:
            labels.append(day.strftime("%b %d"))

    open_activity = sum(critical_high) + sum(medium_low)
    new_activity = sum(new_critical_high) + sum(new_medium_low)
    runtime_total = sum(
        (v.get("critical_high", 0) + v.get("medium_low", 0))
        for v in runtime_by_day.values()
    )
    has_data = open_activity > 0 or new_activity > 0 or runtime_total > 0

    return {
        "labels": labels,
        "critical_high": critical_high,
        "medium_low": medium_low,
        "new_critical_high": new_critical_high,
        "new_medium_low": new_medium_low,
        "has_data": has_data,
        "open_total": open_total + runtime_total,
        "days": days,
    }
