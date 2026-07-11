"""EEG OSS UI views - Dashboard, security command center, findings."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET, require_POST
from django.db.models import Count, Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from apps.projects.models import Project, ScanRun
from apps.security.finding_filters import exclude_vuln_intel_findings
from apps.security.finding_context import attach_code_context
from apps.security.models import AITrace, SecurityFinding
from apps.security.threat_categories import (
    THREAT_BUCKETS,
    count_bucket_from_qs,
    filter_findings_by_bucket,
)
from apps.security.threat_graph import build_runtime_interaction_graph, build_vulnerability_graph
from apps.api.operations import run_project_scan
from apps.ui.dashboard_charts import (
    CATEGORY_BUCKETS,
    THREAT_RADAR_BUCKETS,
    build_activity_distribution,
    build_category_distribution_from_counts,
    build_severity_distribution_from_counts,
    build_threat_radar_from_counts,
    count_runtime_buckets,
    _severity_counts,
)
from apps.ui.dashboard_context import (
    apply_dashboard_project_selection,
    scan_projects_for_org,
    set_user_dashboard_project,
)
from apps.ui.timeline import build_findings_timeline

OPEN_FINDING_STATUSES = [
    SecurityFinding.Status.OPEN,
    SecurityFinding.Status.ACKNOWLEDGED,
    SecurityFinding.Status.IN_PROGRESS,
]

_FINDINGS_FILTER_PARAMS = ("severity", "status", "category", "threat", "project")


def _parse_findings_explorer_filters(
    request: HttpRequest,
    *,
    org,
) -> tuple[dict[str, str], bool, HttpResponse | None]:
    """Validate GET filter params; return (filters, has_filters, redirect_if_invalid)."""
    severity = request.GET.get("severity", "").strip().lower()
    status = request.GET.get("status", "").strip().lower()
    category = request.GET.get("category", "").strip()
    threat = request.GET.get("threat", "").strip()
    project_raw = request.GET.get("project", "").strip()

    valid_severities = {c.value for c in SecurityFinding.Severity}
    valid_statuses = {c.value for c in SecurityFinding.Status}

    if severity and severity not in valid_severities:
        severity = ""
    if status and status not in valid_statuses:
        status = ""

    project_pk: int | None = None
    if project_raw:
        try:
            project_pk = int(project_raw)
        except (ValueError, TypeError):
            project_pk = None
        if project_pk is not None and not Project.objects.filter(
            organization=org, pk=project_pk
        ).exists():
            project_pk = None

    filters = {
        "severity": severity,
        "status": status,
        "category": category,
        "threat": threat,
        "project": str(project_pk) if project_pk is not None else "",
    }
    has_filters = any(filters.values())

    if any(k in request.GET for k in _FINDINGS_FILTER_PARAMS) and not has_filters:
        return filters, False, redirect("ui:findings_explorer")

    if project_raw and project_pk is None:
        q = request.GET.copy()
        q.pop("project", None)
        remaining = {k: q.get(k, "").strip() for k in _FINDINGS_FILTER_PARAMS if k in q}
        if any(remaining.values()):
            return filters, has_filters, redirect(
                f"{reverse('ui:findings_explorer')}?{q.urlencode()}"
            )
        return filters, False, redirect("ui:findings_explorer")

    return filters, has_filters, None


def open_code_findings_qs(organization, project=None):
    """Open code-security findings for dashboard + threat radar."""
    qs = exclude_vuln_intel_findings(
        SecurityFinding.objects.filter(
            organization=organization,
            status__in=OPEN_FINDING_STATUSES,
        ).select_related("project")
    )
    if project is not None:
        qs = qs.filter(project=project)
    return qs


def _runtime_severity_counts(organization, project=None) -> dict[str, int]:
    """Severity histogram from gateway runtime detections for one project."""
    from apps.security.runtime_findings import list_runtime_finding_dicts

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if project is None:
        return counts
    for row in list_runtime_finding_dicts(organization, limit=200, project=project):
        sev = (row.get("severity") or "low").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _empty_dashboard_chart_payloads() -> dict:
    return {
        "timeline": {
            "labels": [],
            "critical_high": [],
            "medium_low": [],
            "new_critical_high": [],
            "new_medium_low": [],
            "has_data": False,
            "open_total": 0,
            "days": 7,
        },
        "severity_distribution": {
            "labels": [],
            "values": [],
            "keys": [],
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "has_data": False,
            "total": 0,
        },
        "category_distribution": {
            "labels": [],
            "values": [],
            "keys": [],
            "has_data": False,
            "total": 0,
        },
        "scan_distribution": {
            "labels": [],
            "values": [],
            "keys": [],
            "kinds": [],
            "has_data": False,
            "total": 0,
            "days": 90,
            "scan_total": 0,
            "gateway_total": 0,
        },
        "threat_radar": {
            "labels": [label for _, label in THREAT_RADAR_BUCKETS],
            "values": [0 for _ in THREAT_RADAR_BUCKETS],
            "keys": [key for key, _ in THREAT_RADAR_BUCKETS],
            "has_data": False,
            "scale_max": 5,
        },
    }


def compute_security_score(
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
) -> int:
    """Weighted posture score from combined code + runtime severities."""
    base = 100
    base -= critical * 15
    base -= high * 8
    base -= medium * 3
    base -= low * 1
    return max(0, min(100, base))


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    """Main dashboard view with charts and threat intelligence.

    Findings and charts are scoped to the active project only. With no project
    selected, the page shows an empty select state (no org-wide blend).
    """
    org = request.organization

    if not org:
        return redirect("accounts:create_organization")

    active_project, dashboard_projects = apply_dashboard_project_selection(
        request, org
    )

    now = timezone.now()
    from apps.security.runtime_findings import list_runtime_finding_dicts

    empty_charts = _empty_dashboard_chart_payloads()

    if active_project is None:
        ctx = {
            "active_project": None,
            "dashboard_projects": dashboard_projects,
            "requires_project": True,
            "is_runtime_project": False,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "code_critical_count": 0,
            "code_high_count": 0,
            "runtime_critical_count": 0,
            "runtime_high_count": 0,
            "runtime_detection_count": 0,
            "runtime_signals_24h": 0,
            "total_findings": 0,
            "recent_scans": [],
            "prompt_injection_count": 0,
            "command_injection_count": 0,
            "secrets_count": 0,
            "mcp_count": 0,
            "supply_chain_count": 0,
            "exfil_count": 0,
            "config_count": 0,
            "owasp_count": 0,
            "security_score": 100,
            "last_scan_time": "—",
            "active_scans": 0,
            "total_scans_24h": 0,
            "critical_pct": 0,
            "high_pct": 0,
            "medium_pct": 0,
            "low_pct": 0,
            **empty_charts,
        }
        return render(request, "ui/dashboard.html", ctx)

    is_runtime_project = active_project.is_gateway_app

    code_findings_qs = exclude_vuln_intel_findings(
        SecurityFinding.objects.filter(organization=org, project=active_project)
    )
    open_findings_qs = open_code_findings_qs(org, project=active_project)

    findings_by_severity = open_findings_qs.values("severity").annotate(
        count=Count("id")
    )
    severity_map = {row["severity"]: row["count"] for row in findings_by_severity}

    findings_by_category = open_findings_qs.values("category").annotate(
        count=Count("id")
    )
    category_map = {row["category"]: row["count"] for row in findings_by_category}

    scan_runs = ScanRun.objects.filter(project=active_project)
    recent_scans = scan_runs.order_by("-created_at")[:5]

    code_critical = severity_map.get("critical", 0)
    code_high = severity_map.get("high", 0)
    code_medium = severity_map.get("medium", 0)
    code_low = severity_map.get("low", 0)

    runtime_rows = list_runtime_finding_dicts(
        org, limit=200, project=active_project
    )
    runtime_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in runtime_rows:
        sev = (row.get("severity") or "low").lower()
        if sev in runtime_sev:
            runtime_sev[sev] += 1
    runtime_critical = runtime_sev["critical"]
    runtime_high = runtime_sev["high"]
    runtime_medium = runtime_sev["medium"]
    runtime_low = runtime_sev["low"]
    runtime_total = runtime_critical + runtime_high + runtime_medium + runtime_low

    # Static projects: code findings. Runtime projects: gateway detections.
    if is_runtime_project:
        critical_count = runtime_critical
        high_count = runtime_high
        medium_count = runtime_medium
        low_count = runtime_low
    else:
        critical_count = code_critical + runtime_critical
        high_count = code_high + runtime_high
        medium_count = code_medium + runtime_medium
        low_count = code_low + runtime_low
    total_findings = critical_count + high_count + medium_count + low_count

    day_ago = now - timedelta(hours=24)
    active_scans = scan_runs.filter(status=ScanRun.Status.RUNNING).count()
    total_scans_24h = scan_runs.filter(created_at__gte=day_ago).count()
    last_scan = scan_runs.order_by("-created_at").first()
    if last_scan:
        delta = now - last_scan.created_at
        if delta.total_seconds() < 60:
            last_scan_time = "Just now"
        elif delta.total_seconds() < 3600:
            last_scan_time = f"{int(delta.total_seconds() / 60)} min ago"
        else:
            last_scan_time = f"{int(delta.total_seconds() / 3600)} hours ago"
    else:
        last_scan_time = "Never"

    security_score = compute_security_score(
        critical=critical_count,
        high=high_count,
        medium=medium_count,
        low=low_count,
    )
    max_sev = max(critical_count, high_count, medium_count, low_count, 1)

    runtime_signals_24h = AITrace.objects.filter(
        organization=org,
        project=active_project,
        started_at__gte=day_ago,
    ).filter(Q(status=AITrace.Status.BLOCKED) | Q(risk_score__gte=0.4)).count()

    blended_sev = _severity_counts(open_findings_qs)
    for key, value in runtime_sev.items():
        blended_sev[key] = blended_sev.get(key, 0) + value

    bucket_counts = {
        bucket_id: count_bucket_from_qs(open_findings_qs, bucket_id)
        for bucket_id, _ in CATEGORY_BUCKETS
    }
    for bucket_id, value in count_runtime_buckets(runtime_rows).items():
        bucket_counts[bucket_id] = bucket_counts.get(bucket_id, 0) + value

    radar_counts = {
        bucket_id: count_bucket_from_qs(open_findings_qs, bucket_id)
        for bucket_id, _ in THREAT_RADAR_BUCKETS
    }
    for bucket_id, value in count_runtime_buckets(runtime_rows).items():
        if bucket_id in radar_counts:
            radar_counts[bucket_id] = radar_counts.get(bucket_id, 0) + value

    timeline = build_findings_timeline(org, days=7, project=active_project)
    severity_distribution = build_severity_distribution_from_counts(blended_sev)
    category_distribution = build_category_distribution_from_counts(bucket_counts)
    scan_distribution = build_activity_distribution(
        org, scan_runs, project=active_project
    )
    threat_radar = build_threat_radar_from_counts(radar_counts)

    ctx = {
        "active_project": active_project,
        "dashboard_projects": dashboard_projects,
        "requires_project": False,
        "is_runtime_project": is_runtime_project,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "code_critical_count": code_critical,
        "code_high_count": code_high,
        "runtime_critical_count": runtime_critical,
        "runtime_high_count": runtime_high,
        "runtime_detection_count": runtime_total,
        "runtime_signals_24h": runtime_signals_24h,
        "total_findings": total_findings,
        "recent_scans": recent_scans,
        "prompt_injection_count": bucket_counts.get("prompt_injection", 0),
        "command_injection_count": bucket_counts.get("command_injection", 0),
        "secrets_count": bucket_counts.get("secrets", 0),
        "mcp_count": bucket_counts.get("mcp", 0),
        "supply_chain_count": bucket_counts.get("supply_chain", 0),
        "exfil_count": category_map.get("exfiltration", 0) + category_map.get("data_leak", 0),
        "config_count": category_map.get("config", 0) + category_map.get("configuration", 0),
        "owasp_count": category_map.get("owasp", 0),
        "timeline": timeline,
        "severity_distribution": severity_distribution,
        "category_distribution": category_distribution,
        "scan_distribution": scan_distribution,
        "threat_radar": threat_radar,
        "security_score": security_score,
        "last_scan_time": last_scan_time,
        "active_scans": active_scans,
        "total_scans_24h": total_scans_24h,
        "critical_pct": int((critical_count / max_sev) * 100) if max_sev else 0,
        "high_pct": int((high_count / max_sev) * 100) if max_sev else 0,
        "medium_pct": int((medium_count / max_sev) * 100) if max_sev else 0,
        "low_pct": int((low_count / max_sev) * 100) if max_sev else 0,
    }

    return render(request, "ui/dashboard.html", ctx)


@login_required
@require_POST
def set_dashboard_project(request: HttpRequest) -> HttpResponse:
    """Persist active project selection and return to the projects page."""
    org = request.organization
    if not org:
        return redirect("accounts:create_organization")

    projects_url = reverse("ui:projects:list")
    project_raw = (request.POST.get("project_id") or "").strip()
    if not project_raw:
        set_user_dashboard_project(request.user, None)
        return redirect(projects_url)

    try:
        project_id = int(project_raw)
    except (TypeError, ValueError):
        set_user_dashboard_project(request.user, None)
        return redirect(projects_url)

    project = scan_projects_for_org(org).filter(pk=project_id).first()
    if project:
        set_user_dashboard_project(request.user, project)
        return redirect(f"{projects_url}?project={project.pk}")

    set_user_dashboard_project(request.user, None)
    return redirect(projects_url)


@login_required
def security_command_center(request: HttpRequest) -> HttpResponse:
    """Legacy URL — security overview is integrated into the dashboard."""
    return redirect("ui:dashboard")


@login_required
def findings_explorer(request: HttpRequest) -> HttpResponse:
    """Findings explorer with filtering and pagination (static code lens)."""
    from django.core.paginator import Paginator
    
    org = request.organization
    source = (request.GET.get("source") or "code").strip().lower()
    if source == "runtime":
        return findings_runtime(request)
    
    if not org:
        return render(
            request,
            "ui/findings_explorer.html",
            {"filters": {}, "source": "code", "lens": "code"},
        )
    
    filters, has_filters, filter_redirect = _parse_findings_explorer_filters(
        request, org=org
    )
    if filter_redirect is not None:
        return filter_redirect

    severity = filters["severity"]
    status = filters["status"]
    category = filters["category"]
    threat = filters["threat"]
    project_id = filters["project"]

    page_num = request.GET.get("page", "1")
    try:
        page_num = int(page_num)
    except ValueError:
        page_num = 1

    qs = exclude_vuln_intel_findings(
        SecurityFinding.objects.filter(organization=org).select_related("project")
    )

    if severity:
        qs = qs.filter(severity=severity)
    if status:
        qs = qs.filter(status=status)
    if threat and threat in THREAT_BUCKETS:
        qs = filter_findings_by_bucket(qs, threat)
    elif category:
        qs = qs.filter(category__icontains=category)
    if project_id:
        qs = qs.filter(project_id=int(project_id))
    
    qs = qs.order_by("-first_seen_at")
    
    paginator = Paginator(qs, 25)
    page_obj = paginator.get_page(page_num)

    projects = Project.objects.filter(organization=org)

    finding_rows = attach_code_context(list(page_obj.object_list))

    ctx = {
        "filters": filters,
        "has_filters": has_filters,
        "findings": page_obj,
        "finding_rows": finding_rows,
        "total_count": qs.count(),
        "projects": projects,
        "source": "code",
        "lens": "code",
    }
    
    if request.headers.get("HX-Request"):
        return render(request, "ui/partials/findings_table.html", ctx)
    return render(request, "ui/findings_explorer.html", ctx)


@login_required
def findings_runtime(request: HttpRequest) -> HttpResponse:
    """Runtime detection findings synthesized from gateway traces."""
    from apps.security.runtime_findings import list_runtime_finding_dicts

    org = request.organization
    if not org:
        return redirect("accounts:create_organization")

    active_project, dashboard_projects = apply_dashboard_project_selection(request, org)
    rows = (
        list_runtime_finding_dicts(org, limit=200, project=active_project)
        if active_project
        else []
    )
    severity = (request.GET.get("severity") or "").strip().lower()
    if severity:
        rows = [r for r in rows if (r.get("severity") or "").lower() == severity]
    q = (request.GET.get("q") or "").strip().lower()
    if q:
        from apps.ui.dashboard_charts import runtime_threat_bucket

        filtered = []
        for r in rows:
            blob = " ".join(
                [
                    str(r.get("title") or ""),
                    str(r.get("category") or ""),
                    str(r.get("trace_type") or ""),
                    str(r.get("rule_id") or ""),
                ]
            ).lower()
            bucket = (runtime_threat_bucket(r) or "").lower()
            if q in blob or q == bucket or q.replace("_", " ") in blob:
                filtered.append(r)
        rows = filtered
    return render(
        request,
        "ui/findings_runtime.html",
        {
            "findings": rows,
            "total_count": len(rows),
            "source": "runtime",
            "lens": "runtime",
            "filters": {"severity": severity, "q": q},
            "active_project": active_project,
            "dashboard_projects": dashboard_projects,
            "requires_project": active_project is None,
        },
    )

@login_required
def dashboard_timeline(request: HttpRequest) -> JsonResponse:
    """JSON: findings activity per day for dashboard timeline chart."""
    org = request.organization
    if not org:
        return JsonResponse(
            {
                "labels": [],
                "critical_high": [],
                "medium_low": [],
                "new_critical_high": [],
                "new_medium_low": [],
                "has_data": False,
                "open_total": 0,
                "days": 7,
            }
        )
    try:
        days = int(request.GET.get("days", "7"))
    except (TypeError, ValueError):
        days = 7
    active_project, _ = apply_dashboard_project_selection(request, org)
    return JsonResponse(
        build_findings_timeline(org, days=days, project=active_project)
    )


@login_required
def threat_graph(request: HttpRequest) -> HttpResponse:
    """Full-page 3D vulnerability relationship graph (static code lens)."""
    org = request.organization
    if not org:
        return redirect("accounts:create_organization")
    source = (request.GET.get("source") or "code").strip().lower()
    if source == "runtime":
        return threat_graph_runtime(request)
    return render(
        request,
        "ui/threat_graph.html",
        {
            "graph_api_url": reverse("ui:threat_vulnerability_graph") + "?limit=150&source=code",
            "source": "code",
            "lens": "code",
        },
    )


@login_required
def threat_graph_runtime(request: HttpRequest) -> HttpResponse:
    """Agentic interaction graph from runtime traces."""
    org = request.organization
    if not org:
        return redirect("accounts:create_organization")
    return render(
        request,
        "ui/threat_graph.html",
        {
            "graph_api_url": reverse("ui:threat_vulnerability_graph")
            + "?limit=150&source=runtime",
            "source": "runtime",
            "lens": "runtime",
        },
    )


@login_required
def threat_vulnerability_graph(request: HttpRequest) -> JsonResponse:
    """JSON graph of vulnerability relationships for the 3D Threat Radar view."""
    org = request.organization
    if not org:
        return JsonResponse({"nodes": [], "links": [], "meta": {}})
    try:
        limit = min(max(int(request.GET.get("limit", "150")), 1), 300)
    except (TypeError, ValueError):
        limit = 150
    source = (request.GET.get("source") or "code").strip().lower()
    if source == "runtime":
        return JsonResponse(build_runtime_interaction_graph(org, limit=limit))
    return JsonResponse(build_vulnerability_graph(org, limit=limit))


@login_required
@require_POST
def run_redteam(request: HttpRequest) -> HttpResponse:
    """Execute auto red-team probe via HTMX."""
    org = request.organization
    
    if not org:
        return HttpResponse("<p class='muted'>Create an organization first.</p>")
    
    if not getattr(org, "auto_redteam_enabled", False):
        return HttpResponse(
            "<div class='panel' style='border-color:var(--accent-critical);'>"
            "<p>Auto red-team is disabled. Enable it in "
            '<a href="/accounts/settings/">organization settings</a>.</p></div>'
        )

    project_id = request.POST.get("project") or request.GET.get("project")
    target_endpoint = (request.POST.get("endpoint") or "").strip()

    if project_id:
        project = get_object_or_404(Project, pk=project_id, organization=org)
        if target_endpoint:
            project.api_endpoint = target_endpoint
            project.save(update_fields=["api_endpoint"])
        result = run_project_scan(org, project.pk, "redteam")
        probe_data = (result.get("probe_results") or {}).get("auto_redteam", {})
        if not probe_data:
            probe_data = {
                "success": result.get("success", False),
                "probes": [],
                "errors": result.get("errors"),
            }
    else:
        from eeg.probes import run_probe as eeg_run_probe

        dry_run = not bool(target_endpoint)
        probe_data = eeg_run_probe(
            "auto_redteam",
            target_endpoint or "dry-run://test",
            options={
                "enabled": True,
                "dry_run": dry_run,
                "max_probes_per_category": 5,
            },
        ).to_dict()

    return render(request, "ui/partials/redteam_results.html", {"probe_result": probe_data})


@login_required
@require_POST
def run_probe(request: HttpRequest) -> HttpResponse:
    """Execute endpoint probes (MCP, gateway, HTTP surface) via HTMX."""
    org = request.organization

    if not org:
        return HttpResponse("<p class='muted'>Create an organization first.</p>")

    project_id = request.POST.get("project") or request.GET.get("project")
    if not project_id:
        return HttpResponse("<p class='muted'>Project ID required for probes.</p>")

    from apps.api.operations import run_project_probe

    project = get_object_or_404(Project, pk=project_id, organization=org)
    probe_id = request.POST.get("probe_id", "").strip()

    result = run_project_probe(org, project.pk, probe_id=probe_id)
    if result.get("status") == 404:
        result = {
            "success": False,
            "error": result.get("error", "Project not found"),
            "findings": [],
            "probe_results": {},
            "summary": {},
        }
    else:
        result.pop("status", None)

    return render(
        request,
        "ui/partials/probe_results.html",
        {"result": result, "project": project},
    )


@login_required
def traces_dashboard(request: HttpRequest) -> HttpResponse:
    """AI traces dashboard with surface-type filters."""
    org = request.organization
    type_filter = (request.GET.get("type") or "").strip().lower()
    verdict_filter = (request.GET.get("verdict") or "").strip().lower()
    if verdict_filter not in ("blocked", "accepted", ""):
        verdict_filter = ""

    surface_defs = [
        ("", "All", "all"),
        ("llm_call", "Prompt", "prompt"),
        ("tool_call", "Tool", "tool"),
        ("retrieval", "RAG", "rag"),
        ("mcp_tool", "MCP", "mcp"),
        ("agent_control", "Control", "control"),
        ("embedding", "Embedding", "embed"),
    ]
    surface_label = {
        "llm_call": "Prompt",
        "tool_call": "Tool",
        "retrieval": "RAG",
        "mcp_tool": "MCP",
        "agent_control": "Control",
        "embedding": "Embedding",
        "agent_action": "Agent",
    }
    surface_tone = {
        "llm_call": "prompt",
        "tool_call": "tool",
        "retrieval": "rag",
        "mcp_tool": "mcp",
        "agent_control": "control",
        "embedding": "embed",
    }

    def _chip_href(value: str, verdict: str = "") -> str:
        params = []
        if value:
            params.append(f"type={value}")
        if verdict:
            params.append(f"verdict={verdict}")
        return "/traces/" + (("?" + "&".join(params)) if params else "")

    def _empty_chips():
        return [
            {
                "value": v,
                "label": l,
                "count": 0,
                "tone": t,
                "href": _chip_href(v),
            }
            for v, l, t in surface_defs
        ]

    empty_ctx = {
        "traces": [],
        "trace_rows": [],
        "type_filter": type_filter,
        "verdict_filter": verdict_filter,
        "surface_chips": _empty_chips(),
        "active_label": next(
            (l for v, l, _t in surface_defs if v == type_filter), "All"
        ),
        "verdict_summary": {"blocked": 0, "accepted": 0, "total": 0},
        "show_verdict_filters": type_filter == "llm_call",
    }

    if not org:
        return render(request, "ui/traces.html", empty_ctx)

    base_qs = AITrace.objects.filter(organization=org)
    qs = base_qs.order_by("-started_at")
    if type_filter:
        qs = qs.filter(trace_type=type_filter)

    # Pull a wider window so we can count blocked/accepted before slicing display
    candidates = list(qs[:300])

    def _is_blocked(trace) -> bool:
        meta = trace.metadata if isinstance(trace.metadata, dict) else {}
        return bool(
            trace.status == AITrace.Status.BLOCKED
            or meta.get("blocked_by_policy")
            or meta.get("blocked")
        )

    blocked_n = sum(1 for t in candidates if _is_blocked(t))
    accepted_n = len(candidates) - blocked_n
    verdict_summary = {
        "blocked": blocked_n,
        "accepted": accepted_n,
        "total": len(candidates),
    }

    if verdict_filter == "blocked":
        candidates = [t for t in candidates if _is_blocked(t)]
    elif verdict_filter == "accepted":
        candidates = [t for t in candidates if not _is_blocked(t)]

    # Prompt view: show blocked first so denials are obvious
    if type_filter == "llm_call" and not verdict_filter:
        candidates.sort(key=lambda t: (0 if _is_blocked(t) else 1, -(t.started_at.timestamp() if t.started_at else 0)))

    traces = candidates[:100]
    type_counts = {
        row["trace_type"]: row["c"]
        for row in base_qs.values("trace_type").annotate(c=Count("id"))
    }
    surface_chips = [
        {
            "value": v,
            "label": l,
            "tone": t,
            "count": (
                sum(type_counts.values())
                if not v
                else type_counts.get(v, 0)
            ),
            "href": _chip_href(v),
        }
        for v, l, t in surface_defs
    ]

    trace_rows = []
    for trace in traces:
        meta = trace.metadata if isinstance(trace.metadata, dict) else {}
        tool = meta.get("tool_name") or meta.get("mcp_tool") or ""
        from eeg.gateway.prompt_text import display_prompt_preview

        raw_preview = (trace.input_text or "").strip()
        preview = display_prompt_preview(raw_preview)
        if len(preview) > 180:
            preview = preview[:177] + "…"
        risk = float(trace.risk_score or 0)
        blocked = _is_blocked(trace)
        verdict = "blocked" if blocked else "accepted"
        tags = meta.get("detection_tags") or trace.risk_signals or []
        tag_preview = ", ".join(str(x) for x in list(tags)[:3] if x)
        trace_rows.append(
            {
                "tone": surface_tone.get(trace.trace_type, "all"),
                "surface_label": surface_label.get(
                    trace.trace_type, trace.get_trace_type_display()
                ),
                "trace_short": f"{trace.trace_id[:8]}…",
                "preview": preview,
                "provider": trace.provider or "—",
                "model_or_tool": tool or trace.model or "—",
                "status": trace.status,
                "verdict": verdict,
                "verdict_label": "Blocked" if blocked else "Accepted",
                "reason": tag_preview
                or (
                    meta.get("policy_action")
                    if blocked
                    else ""
                ),
                "latency": f"{trace.latency_ms} ms",
                "risk": risk,
                "risk_display": f"{risk:.2f}",
                "risk_pct": max(0, min(100, int(round(risk * 100)))),
                "when": trace.started_at.strftime("%b %d, %H:%M").replace(" 0", " ")
                if trace.started_at
                else "—",
            }
        )

    return render(
        request,
        "ui/traces.html",
        {
            "traces": traces,
            "trace_rows": trace_rows,
            "type_filter": type_filter,
            "verdict_filter": verdict_filter,
            "surface_chips": surface_chips,
            "active_label": next(
                (l for v, l, _t in surface_defs if v == type_filter), "All"
            ),
            "verdict_summary": verdict_summary,
            "show_verdict_filters": type_filter == "llm_call",
            "prompt_blocked_href": _chip_href("llm_call", "blocked"),
            "prompt_accepted_href": _chip_href("llm_call", "accepted"),
            "prompt_all_href": _chip_href("llm_call"),
        },
    )


@login_required
def compliance_dashboard(request: HttpRequest) -> HttpResponse:
    """Compliance posture from findings + gateway traces."""
    from eeg.compliance import (
        build_posture_dashboard,
        evaluate,
        run_realtime_compliance_audit,
    )

    org = request.organization
    if not org:
        return render(
            request,
            "ui/compliance.html",
            {"evaluate": {}, "posture": {}, "audit": {}},
        )

    findings = [
        {
            "title": f.title,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "category": f.category,
            "status": f.status,
            "source": "finding",
        }
        for f in exclude_vuln_intel_findings(
            SecurityFinding.objects.filter(organization=org)
        ).order_by("-first_seen_at")[:500]
    ]
    traces = []
    for t in AITrace.objects.filter(organization=org).order_by("-started_at")[:500]:
        meta = t.metadata or {}
        traces.append(
            {
                "trace_type": t.trace_type,
                "status": t.status,
                "risk_score": t.risk_score,
                "threat_level": (
                    "critical"
                    if t.risk_score >= 0.85 or t.status == "blocked"
                    else "high"
                    if t.risk_score >= 0.7
                    else "medium"
                    if t.risk_score >= 0.4
                    else "low"
                ),
                "blocked_by_policy": bool(
                    meta.get("blocked_by_policy") or t.status == "blocked"
                ),
                "detection_tags": meta.get("detection_tags") or t.risk_signals or [],
                "model_name": t.model,
                "metadata": meta,
            }
        )

    evaluate_payload = evaluate(findings=findings, traces=traces)
    posture = build_posture_dashboard(findings=findings, traces=traces)
    audit = run_realtime_compliance_audit(findings=findings, traces=traces)
    return render(
        request,
        "ui/compliance.html",
        {
            "evaluate": evaluate_payload,
            "posture": posture,
            "audit": audit,
            "gaps": evaluate_payload.get("gaps") or [],
            "assessments": evaluate_payload.get("assessments") or [],
        },
    )


@login_required
def agents_dashboard(request: HttpRequest) -> HttpResponse:
    from apps.security.agent_control import list_agents

    org = request.organization
    if not org:
        return render(request, "ui/agents.html", {"agents": []})

    return render(request, "ui/agents.html", {"agents": list_agents(org)})


@login_required
@require_POST
def agent_control_action(request: HttpRequest, agent_id) -> HttpResponse:
    from apps.security.agent_control import control_agent

    org = request.organization
    if not org:
        return redirect("accounts:create_organization")
    action = (request.POST.get("action") or "").strip().lower()
    try:
        result = control_agent(org, str(agent_id), action)
        messages.success(
            request,
            f"Agent {result['agent_key']} → {result['control_status']}.",
        )
    except Exception as exc:  # noqa: BLE001
        messages.error(request, str(exc))
    return redirect("ui:agents")


@login_required
@require_POST
def runtime_lattice_inspect_gone(request: HttpRequest) -> JsonResponse:
    """Legacy Runtime UI endpoints retired — use Compliance / gateway APIs."""
    return JsonResponse(
        {
            "error": "Runtime inspector UI removed. Use /compliance/ and /api/v1/gateway/lattice/.",
            "redirect": "/compliance/",
        },
        status=410,
    )


@login_required
def findings_feed(request: HttpRequest) -> HttpResponse:
    """Real-time findings feed (HTMX partial) — code + runtime detections."""
    from apps.security.runtime_findings import list_runtime_finding_dicts
    from django.utils.dateparse import parse_datetime

    org = request.organization
    findings = []
    layout = (request.GET.get("layout") or "").strip().lower()

    if org:
        active_project, _ = apply_dashboard_project_selection(request, org)
        if active_project is None:
            return render(
                request,
                "ui/partials/findings_feed.html",
                {"findings": [], "layout": layout},
            )

        findings_qs = exclude_vuln_intel_findings(
            SecurityFinding.objects.filter(organization=org, project=active_project)
        ).order_by("-created_at")[:25]

        for f in findings_qs:
            findings.append(
                {
                    "severity": f.severity,
                    "rule_id": f.rule_id,
                    "title": f.title or f.rule_id,
                    "file_path": f.file_path or "—",
                    "timestamp": f.created_at,
                    "source": "code",
                }
            )

        for row in list_runtime_finding_dicts(
            org, limit=40, project=active_project
        ):
            ts = None
            raw = row.get("started_at")
            if raw:
                ts = parse_datetime(str(raw))
            if ts is None:
                ts = timezone.now()
            elif timezone.is_naive(ts):
                ts = timezone.make_aware(ts, timezone.get_current_timezone())
            surface = row.get("surface_label") or row.get("trace_type") or "runtime"
            findings.append(
                {
                    "severity": row.get("severity") or "low",
                    "rule_id": row.get("rule_id") or "runtime",
                    "title": row.get("title") or "Runtime detection",
                    "file_path": f"Runtime · {surface}",
                    "timestamp": ts,
                    "source": "runtime",
                }
            )

        findings.sort(key=lambda item: item["timestamp"] or timezone.now(), reverse=True)
        findings = findings[:25]

    return render(
        request,
        "ui/partials/findings_feed.html",
        {"findings": findings, "layout": layout},
    )


def _vulnerability_doc_url(vid: str) -> str:
    """Return a canonical documentation URL for a vulnerability id."""
    v = (vid or "").strip().upper()
    if v.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{v}"
    if v.startswith("GHSA-"):
        lower = (vid or "").strip()
        return f"https://github.com/advisories/{lower}"
    if v.startswith("OSV-") or "PYSEC-" in v or "GO-" in v:
        enc = (vid or "").strip()
        return f"https://osv.dev/vulnerability/{quote(enc, safe='')}"
    return "https://owasp.org/www-project-top-10-for-large-language-model-applications/"


def build_vulnerability_intel_entries(org) -> list:
    """Rows for the threat intel feed (dependency/CVE style findings)."""
    from apps.security.finding_filters import vuln_intel_findings_qs

    if not org:
        return []

    if not Project.objects.filter(organization=org).exists():
        return []

    vulns = []
    vuln_findings = vuln_intel_findings_qs(org).order_by("-first_seen_at")[:15]

    for f in vuln_findings:
        rid = f.rule_id.upper()
        if rid.startswith("CVE-") or "/CVE-" in rid:
            source_label = "NVD"
        else:
            source_label = "GitHub"
        vulns.append(
            {
                "id": f.rule_id,
                "severity": f.severity,
                "summary": f.title,
                "package": (
                    f.file_path.replace("dependency:", "")
                    if (f.file_path or "").startswith("dependency:")
                    else None
                ),
                "fixed_version": None,
                "source": source_label,
                "published": f.first_seen_at.strftime("%Y-%m-%d")
                if f.first_seen_at
                else None,
                "doc_url": _vulnerability_doc_url(rid),
            }
        )

    return vulns


@login_required
def threat_intel(request: HttpRequest) -> HttpResponse:
    """Threat intelligence feed — only exposed as this dedicated page (not Command Center)."""
    org = request.organization
    if not org:
        return redirect("accounts:create_organization")
    active_project, dashboard_projects = apply_dashboard_project_selection(
        request, org
    )
    has_projects = Project.objects.filter(organization=org).exists()
    vulns = build_vulnerability_intel_entries(org)
    active_refresh_scan = None
    if active_project:
        active_refresh_scan = (
            ScanRun.objects.filter(
                project=active_project,
                scan_type=ScanRun.ScanType.DEPENDENCY,
                status__in=(ScanRun.Status.QUEUED, ScanRun.Status.RUNNING),
            )
            .order_by("-created_at")
            .first()
        )
    return render(
        request,
        "ui/threat_intel.html",
        {
            "vulns": vulns,
            "has_projects": has_projects,
            "active_project": active_project,
            "dashboard_projects": dashboard_projects,
            "active_refresh_scan": active_refresh_scan,
        },
    )


def _render_vuln_feed(
    request: HttpRequest,
    org,
    *,
    scan_message: str | None = None,
    scan_error: str | None = None,
) -> HttpResponse:
    has_projects = Project.objects.filter(organization=org).exists()
    vulns = build_vulnerability_intel_entries(org)
    return render(
        request,
        "ui/partials/vuln_feed.html",
        {
            "vulns": vulns,
            "has_projects": has_projects,
            "scan_message": scan_message,
            "scan_error": scan_error,
        },
    )


@login_required
def vuln_feed(request: HttpRequest) -> HttpResponse:
    """HTMX partial: threat intel feed from persisted findings (no live CVE fetch)."""
    org = request.organization
    if not org:
        return render(request, "ui/partials/vuln_feed.html", {"vulns": [], "has_projects": False})
    return _render_vuln_feed(request, org)


@login_required
@require_POST
def refresh_threat_intel(request: HttpRequest) -> HttpResponse:
    """Queue CVE fetch (NVD + GHSA) and return a polling partial (non-blocking)."""
    from apps.api.operations import refresh_threat_intel as queue_threat_intel

    org = request.organization
    if not org:
        return render(request, "ui/partials/vuln_feed.html", {"vulns": [], "has_projects": False})

    active_project, _ = apply_dashboard_project_selection(request, org)
    if not active_project:
        return _render_vuln_feed(
            request,
            org,
            scan_error=(
                "Select a project on the Projects page (project selector) "
                "before refreshing CVE data."
            ),
        )

    result = queue_threat_intel(org, active_project.pk)
    if result.get("status") == 404:
        return _render_vuln_feed(
            request, org, scan_error=result.get("error", "Project not found")
        )
    if result.get("code") == "scan_in_progress":
        return _render_vuln_feed(request, org, scan_error=result.get("error"))
    if not result.get("success"):
        return _render_vuln_feed(
            request,
            org,
            scan_error=result.get("error") or "Threat intel refresh failed",
        )

    response = render(
        request,
        "ui/partials/threat_intel_refresh_poll.html",
        {
            "scan_run_id": result["scan_run_id"],
            "active_project": active_project,
        },
    )
    response["HX-Trigger"] = '{"threatIntelRefreshStarted": true}'
    return response


@login_required
@require_GET
def threat_intel_scan_status(request: HttpRequest) -> HttpResponse:
    """Poll CVE refresh progress; returns feed when complete."""
    from apps.api.operations import get_scan_run_status

    org = request.organization
    if not org:
        return render(request, "ui/partials/vuln_feed.html", {"vulns": [], "has_projects": False})

    active_project, _ = apply_dashboard_project_selection(request, org)
    scan_run_id = request.GET.get("scan_run")
    if not scan_run_id:
        return _render_vuln_feed(request, org, scan_error="Missing scan run id")

    status = get_scan_run_status(org, int(scan_run_id))
    if status.get("status") == 404:
        return _render_vuln_feed(request, org, scan_error=status.get("error"))

    if not status.get("completed"):
        return render(
            request,
            "ui/partials/threat_intel_refresh_poll.html",
            {
                "scan_run_id": scan_run_id,
                "active_project": active_project,
            },
        )

    scan_message = None
    scan_error = None
    if status.get("status") == ScanRun.Status.FAILED:
        scan_error = status.get("error") or "Threat intel refresh failed"
    else:
        summary = status.get("result_summary") or {}
        count = status.get("findings_count", summary.get("total_findings", 0))
        packages = summary.get("packages_found", 0)
        name = status.get("project_name", "")
        scan_message = (
            f"Refreshed {name}: {count} advisories from NVD/GitHub "
            f"({packages} dependencies checked)."
        )
        note = summary.get("note")
        if note:
            scan_message += f" {note}"

    response = _render_vuln_feed(
        request, org, scan_message=scan_message, scan_error=scan_error
    )
    response["HX-Trigger"] = '{"threatIntelRefreshDone": true}'
    return response
