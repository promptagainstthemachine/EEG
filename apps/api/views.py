"""EEG OSS API views."""
import json
from pathlib import Path

from django.http import HttpResponse, JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from apps.accounts.models import Organization
from apps.projects.models import Project, ScanRun
from apps.projects.utils import unique_project_slug
from apps.security.models import AITrace, SecurityFinding
from apps.security.trace_ingest import (
    _trace_json,
    ingest_traces,
    parse_ingest_body,
)


def _project_json(project: Project) -> dict:
    return {
        "id": project.id,
        "uuid": str(project.uuid),
        "name": project.name,
        "slug": project.slug,
        "description": project.description,
        "project_type": project.project_type,
        "status": project.status,
        "connection_status": project.connection_status,
        "is_gateway_app": project.is_gateway_app,
        "gateway_agent_key": project.gateway_agent_key or "",
        "repository_url": project.repository_url,
        "local_path": project.local_path,
        "api_endpoint": project.api_endpoint,
        "cloud_resource_id": project.cloud_resource_id,
        "auto_scan_enabled": project.auto_scan_enabled,
        "last_scan_at": project.last_scan_at.isoformat() if project.last_scan_at else None,
        "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(),
    }


def _finding_json(finding: SecurityFinding, *, detailed: bool = False) -> dict:
    data = {
        "id": str(finding.id),
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "category": finding.category,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "first_seen_at": finding.first_seen_at.isoformat(),
        "last_seen_at": finding.last_seen_at.isoformat(),
    }
    if detailed:
        data.update({
            "description": finding.description,
            "recommendation": finding.recommendation,
            "code_snippet": finding.code_snippet,
            "cwe": finding.cwe,
            "owasp_llm": finding.owasp_llm,
            "project_id": finding.project_id,
            "metadata": finding.metadata,
        })
    return data


def require_api_auth(view_func):
    """Decorator to require API authentication."""
    def wrapper(request, *args, **kwargs):
        if not getattr(request, "api_authenticated", False):
            return JsonResponse(
                {
                    "error": "Valid API key required. Use Authorization: Bearer <key> or X-EEG-API-Key.",
                    "code": "auth_required",
                },
                status=401,
            )
        return view_func(request, *args, **kwargs)
    return wrapper


@method_decorator(csrf_exempt, name="dispatch")
class OpenApiSchemaView(View):
    """OpenAPI document for Swagger UI."""

    def get(self, request):
        from apps.api.openapi_schema import build_openapi_schema

        return JsonResponse(build_openapi_schema(request=request))


@method_decorator(csrf_exempt, name="dispatch")
class HealthView(View):
    """Health check endpoint."""
    
    def get(self, request):
        from eeg.scans import get_all_scans
        from eeg.probes import get_all_probes
        from eeg.rules.catalog_loader import validate_catalog

        catalog_status = validate_catalog()

        return JsonResponse({
            "status": "ok",
            "service": "eeg-oss",
            "engine": {
                "scans_registered": len(get_all_scans()),
                "probes_registered": len(get_all_probes()),
                "scan_ids": sorted(get_all_scans().keys()),
                "probe_ids": sorted(get_all_probes().keys()),
            },
            "catalog": catalog_status,
        })


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ProjectListView(View):
    """List and create projects."""
    
    def get(self, request):
        org = request.organization
        from apps.projects.gateway_sync import sync_gateway_projects

        sync_gateway_projects(org)
        projects = Project.objects.filter(organization=org)

        return JsonResponse({
            "projects": [_project_json(p) for p in projects],
        })
    
    def post(self, request):
        org = request.organization
        
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        
        if not org.can_add_project():
            return JsonResponse(
                {"error": "Maximum projects limit reached", "code": "limit_reached"},
                status=400,
            )
        
        name = data.get("name", "Unnamed Project")
        slug = unique_project_slug(org, name, data.get("slug", ""))
        local_path_raw = (data.get("local_path") or "").strip()
        repository_url = (data.get("repository_url") or "").strip()
        from apps.projects.path_utils import is_file_url, resolve_local_source_path

        if local_path_raw or (repository_url and is_file_url(repository_url)):
            resolved = resolve_local_source_path(
                local_path=local_path_raw,
                repository_url=repository_url,
            )
            if resolved is None:
                return JsonResponse(
                    {
                        "error": (
                            "local_path is invalid, missing, or outside allowed scan roots. "
                            "Use a path under the app directory, or set EEG_ALLOWED_SCAN_ROOTS."
                        ),
                        "code": "invalid_local_path",
                    },
                    status=400,
                )
            local_path_raw = str(resolved)
            if repository_url and is_file_url(repository_url):
                repository_url = ""

        project = Project.objects.create(
            organization=org,
            name=name,
            slug=slug,
            description=data.get("description", ""),
            project_type=data.get("project_type", Project.ProjectType.REPOSITORY),
            repository_url=repository_url,
            local_path=local_path_raw,
            api_endpoint=data.get("api_endpoint", ""),
        )
        
        return JsonResponse({
            "id": project.id,
            "name": project.name,
            "slug": project.slug,
        }, status=201)


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ProjectDetailView(View):
    """Get, update, or delete a single project."""

    def _get_project(self, request, project_id: int) -> Project:
        return Project.objects.get(pk=project_id, organization=request.organization)

    def get(self, request, project_id: int):
        try:
            project = self._get_project(request, project_id)
        except Project.DoesNotExist:
            return JsonResponse({"error": "Project not found"}, status=404)
        return JsonResponse(_project_json(project))

    def patch(self, request, project_id: int):
        try:
            project = self._get_project(request, project_id)
        except Project.DoesNotExist:
            return JsonResponse({"error": "Project not found"}, status=404)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        for field in (
            "name",
            "slug",
            "description",
            "project_type",
            "status",
            "repository_url",
            "local_path",
            "api_endpoint",
            "cloud_resource_id",
            "auto_scan_enabled",
        ):
            if field in data:
                setattr(project, field, data[field])

        # Harden local_path / file:// repository updates (block arbitrary FS roots).
        if "local_path" in data or "repository_url" in data:
            from apps.projects.path_utils import is_file_url, resolve_local_source_path

            local_path_raw = (project.local_path or "").strip()
            repository_url = (project.repository_url or "").strip()
            if local_path_raw or (repository_url and is_file_url(repository_url)):
                resolved = resolve_local_source_path(
                    local_path=local_path_raw,
                    repository_url=repository_url,
                )
                if resolved is None:
                    return JsonResponse(
                        {
                            "error": (
                                "local_path is invalid, missing, or outside allowed scan roots."
                            ),
                            "code": "invalid_local_path",
                        },
                        status=400,
                    )
                project.local_path = str(resolved)
                if repository_url and is_file_url(repository_url):
                    project.repository_url = ""

        project.save()
        return JsonResponse(_project_json(project))

    def delete(self, request, project_id: int):
        try:
            project = self._get_project(request, project_id)
        except Project.DoesNotExist:
            return JsonResponse({"error": "Project not found"}, status=404)
        gateway_key = (project.gateway_agent_key or "").strip()
        if gateway_key:
            from apps.security.models import ManagedAgent

            ManagedAgent.objects.filter(
                organization=request.organization, agent_key=gateway_key
            ).delete()
        project.delete()
        return HttpResponse(status=204)


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ProjectScansView(View):
    """List scan runs for a project."""

    def get(self, request, project_id: int):
        org = request.organization
        try:
            project = Project.objects.get(pk=project_id, organization=org)
        except Project.DoesNotExist:
            return JsonResponse({"error": "Project not found"}, status=404)

        limit = min(int(request.GET.get("limit", "25")), 100)
        scans = ScanRun.objects.filter(project=project).order_by("-created_at")[:limit]
        return JsonResponse({
            "project_id": project.id,
            "scans": [
                {
                    "id": s.id,
                    "scan_type": s.scan_type,
                    "status": s.status,
                    "findings_count": s.findings_count,
                    "critical_count": s.critical_count,
                    "high_count": s.high_count,
                    "medium_count": s.medium_count,
                    "low_count": s.low_count,
                    "result_summary": s.result_summary,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                    "created_at": s.created_at.isoformat(),
                }
                for s in scans
            ],
        })


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ScanTypesView(View):
    """Catalog of scan types, registered scanners, and probes."""

    def get(self, request):
        from apps.security.services import ProbeService, ScanningService

        return JsonResponse({
            "scan_types": [
                "code",
                "full",
                "comprehensive",
                "agent",
                "model",
                "dependency",
                "vuln_intel",
                "redteam",
            ],
            "scans": ScanningService.get_available_scans(),
            "probes": ProbeService.get_available_probes(),
        })


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ScanView(View):
    """Trigger security scans via ScanningService (persists findings)."""

    def post(self, request):
        org = request.organization

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        scan_type = data.get("scan_type", "code")
        project_id = data.get("project_id")

        if not project_id:
            return JsonResponse({"error": "project_id is required"}, status=400)

        from apps.api.operations import run_project_scan

        payload = run_project_scan(org, int(project_id), scan_type)
        if payload.get("status") == 404:
            return JsonResponse({"error": payload.get("error", "Not found")}, status=404)
        if payload.get("code") == "scan_in_progress":
            return JsonResponse(
                {
                    "error": payload.get("error", "Scan already in progress"),
                    "code": "scan_in_progress",
                },
                status=409,
            )
        payload.pop("status", None)
        if payload.get("async"):
            return JsonResponse(payload, status=202)
        return JsonResponse(payload)


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ProbeView(View):
    """Trigger dynamic security probes against project endpoints."""

    def post(self, request):
        org = request.organization

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        project_id = data.get("project_id")
        probe_id = data.get("probe_id", "").strip()
        dry_run = data.get("dry_run")

        if not project_id:
            return JsonResponse({"error": "project_id is required"}, status=400)

        from apps.api.operations import run_project_probe

        payload = run_project_probe(
            org,
            int(project_id),
            probe_id=probe_id,
            dry_run=dry_run,
        )
        if payload.get("status") == 404:
            return JsonResponse({"error": payload.get("error", "Not found")}, status=404)
        if payload.get("code") == "scan_in_progress":
            return JsonResponse(
                {
                    "error": payload.get("error", "Scan already in progress"),
                    "code": "scan_in_progress",
                },
                status=409,
            )
        payload.pop("status", None)
        if payload.get("async"):
            return JsonResponse(payload, status=202)
        return JsonResponse(payload)

    def get(self, request):
        """List available probes."""
        from apps.security.services import ProbeService
        return JsonResponse({"probes": ProbeService.get_available_probes()})


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class FindingsView(View):
    """List security findings."""
    
    def get(self, request):
        org = request.organization
        source = (request.GET.get("source") or "code").strip().lower()
        if source == "runtime":
            from apps.security.runtime_findings import list_runtime_finding_dicts

            rows = list_runtime_finding_dicts(org, limit=min(int(request.GET.get("limit", "100")), 500))
            severity = request.GET.get("severity", "")
            if severity:
                rows = [r for r in rows if r.get("severity") == severity]
            return JsonResponse(
                {
                    "total": len(rows),
                    "limit": len(rows),
                    "offset": 0,
                    "source": "runtime",
                    "findings": rows,
                }
            )

        severity = request.GET.get("severity", "")
        status = request.GET.get("status", "")
        category = request.GET.get("category", "")
        project_id = request.GET.get("project_id", "")
        limit = min(int(request.GET.get("limit", "100")), 500)
        offset = int(request.GET.get("offset", "0"))

        from apps.security.finding_filters import exclude_vuln_intel_findings

        qs = exclude_vuln_intel_findings(SecurityFinding.objects.filter(organization=org))

        if severity:
            qs = qs.filter(severity=severity)
        if status:
            qs = qs.filter(status=status)
        if category:
            qs = qs.filter(category__icontains=category)
        if project_id:
            qs = qs.filter(project_id=project_id)

        total = qs.count()
        findings = qs.order_by("-first_seen_at")[offset:offset + limit]

        return JsonResponse({
            "total": total,
            "limit": limit,
            "offset": offset,
            "source": "code",
            "findings": [_finding_json(f) for f in findings],
        })


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class FindingDetailView(View):
    """Get or update a single finding."""

    def get(self, request, finding_id):
        org = request.organization
        try:
            finding = SecurityFinding.objects.get(pk=finding_id, organization=org)
        except (SecurityFinding.DoesNotExist, ValueError):
            return JsonResponse({"error": "Finding not found"}, status=404)
        return JsonResponse(_finding_json(finding, detailed=True))

    def patch(self, request, finding_id):
        org = request.organization
        try:
            finding = SecurityFinding.objects.get(pk=finding_id, organization=org)
        except (SecurityFinding.DoesNotExist, ValueError):
            return JsonResponse({"error": "Finding not found"}, status=404)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        new_status = data.get("status")
        valid = {c.value for c in SecurityFinding.Status}
        if new_status not in valid:
            return JsonResponse({"error": "Invalid status"}, status=400)

        from django.utils import timezone

        finding.status = new_status
        if new_status == SecurityFinding.Status.RESOLVED:
            finding.resolved_at = timezone.now()
        elif finding.resolved_at:
            finding.resolved_at = None
        finding.save(update_fields=["status", "resolved_at", "last_seen_at"])
        return JsonResponse(_finding_json(finding, detailed=True))


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ThreatIntelView(View):
    """CVE / dependency vulnerability intelligence."""

    def get(self, request):
        from apps.ui.views import build_vulnerability_intel_entries

        org = request.organization
        limit = min(int(request.GET.get("limit", "50")), 200)
        offset = int(request.GET.get("offset", "0"))

        entries = build_vulnerability_intel_entries(org)
        total = len(entries)
        page = entries[offset:offset + limit]
        return JsonResponse({"total": total, "limit": limit, "offset": offset, "entries": page})

    def post(self, request):
        """Fetch CVEs from NVD + GitHub GHSA for a project and persist findings."""
        from apps.api.operations import refresh_threat_intel
        from apps.ui.views import build_vulnerability_intel_entries

        org = request.organization
        try:
            data = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        project_id = data.get("project_id") or request.GET.get("project_id")
        if not project_id:
            return JsonResponse({"error": "project_id is required"}, status=400)

        result = refresh_threat_intel(org, int(project_id))
        if result.get("status") == 404:
            return JsonResponse({"error": result.get("error", "Not found")}, status=404)
        if result.get("code") == "scan_in_progress":
            return JsonResponse(
                {"error": result.get("error"), "code": "scan_in_progress"},
                status=409,
            )
        if not result.get("success"):
            return JsonResponse(
                {"error": result.get("error", "Threat intel refresh failed")},
                status=400,
            )

        if result.get("async"):
            return JsonResponse(
                {
                    "success": True,
                    "async": True,
                    "scan_run_id": result.get("scan_run_id"),
                    "project_id": result.get("project_id"),
                    "message": result.get("message", "CVE refresh queued"),
                },
                status=202,
            )

        entries = build_vulnerability_intel_entries(org)
        return JsonResponse(
            {
                "success": True,
                "findings_count": result.get("findings_count", 0),
                "packages_found": result.get("packages_found", 0),
                "sources_queried": result.get("sources_queried", {}),
                "errors": result.get("errors"),
                "note": result.get("note"),
                "entries": entries[:50],
                "total": len(entries),
            }
        )


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class TracesView(View):
    """List and ingest AI observability traces."""

    def get(self, request):
        org = request.organization
        project_id = request.GET.get("project_id", "")
        trace_type = request.GET.get("trace_type", "")
        limit = min(int(request.GET.get("limit", "50")), 200)
        offset = int(request.GET.get("offset", "0"))

        qs = AITrace.objects.filter(organization=org)
        if project_id:
            qs = qs.filter(project_id=project_id)
        if trace_type:
            qs = qs.filter(trace_type=trace_type)

        total = qs.count()
        traces = qs.order_by("-started_at")[offset:offset + limit]
        return JsonResponse({
            "total": total,
            "limit": limit,
            "offset": offset,
            "traces": [_trace_json(t) for t in traces],
        })

    def post(self, request):
        org = request.organization

        if not org.realtime_telemetry_enabled:
            return JsonResponse(
                {
                    "error": "Trace telemetry is disabled for this organization.",
                    "code": "telemetry_disabled",
                },
                status=403,
            )

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        if not isinstance(body, dict):
            return JsonResponse({"error": "Request body must be a JSON object"}, status=400)

        try:
            payloads = parse_ingest_body(body)
        except ValueError as exc:
            return JsonResponse({"error": str(exc)}, status=400)

        if not payloads:
            return JsonResponse({"error": "No traces provided"}, status=400)

        created, errors = ingest_traces(org, payloads)
        if errors:
            if "policy" in errors:
                return JsonResponse(
                    {
                        "error": errors["policy"],
                        "code": "policy_enforcement_blocked",
                    },
                    status=403,
                )
            return JsonResponse({"error": "Validation failed", "fields": errors}, status=400)

        if len(created) == 1:
            return JsonResponse({"trace": _trace_json(created[0])}, status=201)

        return JsonResponse(
            {
                "created": len(created),
                "traces": [_trace_json(t) for t in created],
            },
            status=201,
        )


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class OrganizationView(View):
    """Get organization info."""
    
    def get(self, request):
        org = request.organization
        
        return JsonResponse({
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "settings": {
                "auto_redteam_enabled": org.auto_redteam_enabled,
                "model_scanning_enabled": org.model_scanning_enabled,
                "realtime_telemetry_enabled": org.realtime_telemetry_enabled,
                "realtime_monitoring_enabled": org.realtime_monitoring_enabled,
                "policy_enforcement_enabled": org.policy_enforcement_enabled,
                "runtime_protection_enabled": org.runtime_protection_enabled,
            },
            "project_count": org.project_count(),
            "can_add_project": org.can_add_project(),
        })
    
    def patch(self, request):
        org = request.organization
        
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        
        settings = data.get("settings", {})
        update_fields = []
        
        valid_settings = [
            "auto_redteam_enabled",
            "model_scanning_enabled",
            "realtime_telemetry_enabled",
            "realtime_monitoring_enabled",
            "policy_enforcement_enabled",
            "runtime_protection_enabled",
        ]
        
        for field in valid_settings:
            if field in settings:
                setattr(org, field, bool(settings[field]))
                update_fields.append(field)
        
        if update_fields:
            org.save(update_fields=update_fields)
        
        return JsonResponse({"status": "updated", "fields": update_fields})


def _compliance_signals(org):
    from apps.security.finding_filters import exclude_vuln_intel_findings

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
            }
        )
    return findings, traces


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ComplianceEvaluateView(View):
    def get(self, request):
        from eeg.compliance import evaluate

        findings, traces = _compliance_signals(request.organization)
        return JsonResponse(evaluate(findings=findings, traces=traces))


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class CompliancePostureView(View):
    def get(self, request):
        from eeg.compliance import build_posture_dashboard

        findings, traces = _compliance_signals(request.organization)
        return JsonResponse(build_posture_dashboard(findings=findings, traces=traces))


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class ComplianceAuditView(View):
    def get(self, request):
        from eeg.compliance import run_realtime_compliance_audit

        findings, traces = _compliance_signals(request.organization)
        return JsonResponse(run_realtime_compliance_audit(findings=findings, traces=traces))


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class AgentsView(View):
    def get(self, request):
        from apps.security.agent_control import list_agents

        return JsonResponse({"agents": list_agents(request.organization)})

    def post(self, request):
        from apps.security.agent_control import ensure_agent

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        key = str(body.get("agent_key") or "").strip()
        if not key:
            return JsonResponse({"error": "agent_key is required"}, status=400)
        agent = ensure_agent(
            request.organization,
            key,
            name=str(body.get("name") or key),
            metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else None,
        )
        return JsonResponse(
            {
                "agent": {
                    "id": str(agent.id),
                    "agent_key": agent.agent_key,
                    "name": agent.name,
                    "control_status": agent.control_status,
                }
            },
            status=201,
        )


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class AgentControlView(View):
    def post(self, request, agent_id):
        from apps.security.agent_control import control_agent
        from apps.security.models import ManagedAgent

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        action = str(body.get("action") or "").strip().lower()
        try:
            result = control_agent(request.organization, str(agent_id), action)
        except ManagedAgent.DoesNotExist:
            return JsonResponse({"error": "Agent not found"}, status=404)
        except ValueError as exc:
            return JsonResponse({"error": str(exc)}, status=400)
        return JsonResponse(result)
