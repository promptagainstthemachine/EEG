"""EEG OSS project views."""
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from apps.accounts.activity_log import record_user_activity
from apps.accounts.models import UserActivityLog
from apps.ui.dashboard_context import (
    apply_dashboard_project_selection,
    set_user_dashboard_project,
)

from apps.security.scan_concurrency import (
    SCAN_FAMILY_FULL,
    get_active_scan_run,
    project_has_active_scan_in_family,
)

from .forms import ProjectForm
from .models import Project, ScanRun


@login_required
def project_list(request: HttpRequest) -> HttpResponse:
    """List all projects for the user's organization."""
    org = request.organization
    projects = []
    can_add = False

    active_project = None
    dashboard_projects = Project.objects.none()
    full_scan_in_progress = False
    active_full_scan = None

    if org:
        from apps.projects.gateway_sync import sync_gateway_projects

        sync_gateway_projects(org)
        projects = list(Project.objects.filter(organization=org))
        can_add = org.can_add_project()
        active_project, dashboard_projects = apply_dashboard_project_selection(
            request, org
        )
        if active_project:
            full_scan_in_progress = project_has_active_scan_in_family(
                active_project, SCAN_FAMILY_FULL
            )
            active_full_scan = get_active_scan_run(active_project, SCAN_FAMILY_FULL)

    return render(
        request,
        "projects/list.html",
        {
            "projects": projects,
            "can_add": can_add,
            "current_count": len(projects),
            "active_project": active_project,
            "dashboard_projects": dashboard_projects,
            "full_scan_in_progress": full_scan_in_progress,
            "active_full_scan": active_full_scan,
        },
    )


@login_required
def project_create(request: HttpRequest) -> HttpResponse:
    """Create a new project."""
    org = request.organization
    
    if not org:
        messages.error(request, "You need to create an organization first.")
        return redirect("accounts:create_organization")

    if not org.can_add_project():
        max_projects = int(getattr(settings, "EEG_MAX_PROJECTS_PER_ORG", 0) or 0)
        current_count = Project.objects.filter(organization=org).count()
        record_user_activity(
            user=request.user,
            organization=org,
            event_type=UserActivityLog.EventType.PROJECT_CREATE_BLOCKED,
            metadata={
                "max_projects": max_projects,
                "current_count": current_count,
            },
            request=request,
        )
        messages.error(
            request,
            f"Maximum of {max_projects} projects reached. Remove a project to add a new one.",
        )
        return redirect("ui:projects:list")

    if request.method == "POST":
        form = ProjectForm(request.POST, organization=org)
        if form.is_valid():
            project = form.save()
            n = Project.objects.filter(organization=org).count()
            record_user_activity(
                user=request.user,
                organization=org,
                event_type=UserActivityLog.EventType.PROJECT_CREATED,
                metadata={
                    "project_id": project.pk,
                    "project_name": project.name,
                    "project_slug": project.slug,
                    "projects_in_org": n,
                },
                request=request,
            )
            messages.success(
                request,
                f"Project '{project.name}' created (ID {project.uuid}). "
                "Repository files are copying in the background if a local path was set.",
            )
            return redirect("ui:projects:detail", project_id=project.pk)
    else:
        form = ProjectForm(organization=org)

    return render(
        request,
        "projects/form.html",
        {
            "form": form,
            "is_create": True,
        },
    )


@login_required
def project_detail(request: HttpRequest, project_id: int) -> HttpResponse:
    """Project detail view with recent scans."""
    org = request.organization
    
    if not org:
        messages.error(request, "Organization not found.")
        return redirect("ui:dashboard")

    project = get_object_or_404(Project, pk=project_id, organization=org)
    recent_scans = ScanRun.objects.filter(project=project)[:10]
    
    from apps.security.models import SecurityFinding
    findings_summary = {
        "critical": SecurityFinding.objects.filter(
            project=project, severity="critical", status="open"
        ).count(),
        "high": SecurityFinding.objects.filter(
            project=project, severity="high", status="open"
        ).count(),
        "medium": SecurityFinding.objects.filter(
            project=project, severity="medium", status="open"
        ).count(),
        "low": SecurityFinding.objects.filter(
            project=project, severity="low", status="open"
        ).count(),
    }

    full_scan_in_progress = project_has_active_scan_in_family(project, SCAN_FAMILY_FULL)
    active_full_scan = get_active_scan_run(project, SCAN_FAMILY_FULL)

    return render(
        request,
        "projects/detail.html",
        {
            "project": project,
            "recent_scans": recent_scans,
            "findings_summary": findings_summary,
            "full_scan_in_progress": full_scan_in_progress,
            "active_full_scan": active_full_scan,
        },
    )


@login_required
def project_edit(request: HttpRequest, project_id: int) -> HttpResponse:
    """Edit an existing project."""
    org = request.organization
    
    if not org:
        messages.error(request, "Organization not found.")
        return redirect("ui:dashboard")

    project = get_object_or_404(Project, pk=project_id, organization=org)

    if request.method == "POST":
        form = ProjectForm(request.POST, instance=project, organization=org)
        if form.is_valid():
            form.save()
            messages.success(request, f"Project '{project.name}' updated.")
            return redirect("ui:projects:detail", project_id=project.pk)
    else:
        form = ProjectForm(instance=project, organization=org)

    return render(
        request,
        "projects/form.html",
        {"form": form, "project": project, "is_create": False},
    )


@login_required
@require_POST
def project_delete(request: HttpRequest, project_id: int) -> HttpResponse:
    """Delete a project and all of its static/runtime findings and traces.

    Gateway app projects are re-created from ManagedAgent on the projects list,
    so deleting one also removes the linked agent identity. New gateway traffic
    with the same key will register again automatically.
    """
    org = request.organization

    if not org:
        messages.error(request, "Organization not found.")
        return redirect("ui:dashboard")

    project = get_object_or_404(Project, pk=project_id, organization=org)
    project_name = project.name
    project_pk = project.pk
    gateway_key = (project.gateway_agent_key or "").strip()
    record_user_activity(
        user=request.user,
        organization=org,
        event_type=UserActivityLog.EventType.PROJECT_DELETED,
        metadata={
            "project_id": project_pk,
            "project_name": project_name,
            "gateway_agent_key": gateway_key,
            "deleted_by_username": request.user.username,
        },
        request=request,
    )
    if request.user.dashboard_project_id == project_pk:
        set_user_dashboard_project(request.user, None)

    from apps.security.models import AITrace, ManagedAgent, SecurityFinding

    # Explicit cleanup (CASCADE also covers project-linked rows).
    SecurityFinding.objects.filter(organization=org, project=project).delete()
    AITrace.objects.filter(organization=org, project=project).delete()

    if gateway_key:
        ManagedAgent.objects.filter(
            organization=org, agent_key=gateway_key
        ).delete()
        # Orphan org-level traces tagged with this agent (pre-scoping data).
        AITrace.objects.filter(
            organization=org,
            project__isnull=True,
        ).filter(
            Q(metadata__agent_key=gateway_key)
            | Q(metadata__agent_id=gateway_key)
            | Q(session_id=f"agent-{gateway_key}")
        ).delete()
        SecurityFinding.objects.filter(
            organization=org, project__isnull=True
        ).delete()

    project.delete()

    # If the org has no projects left, drop remaining project-less runtime rows.
    if not Project.objects.filter(organization=org).exists():
        AITrace.objects.filter(organization=org, project__isnull=True).delete()
        SecurityFinding.objects.filter(organization=org, project__isnull=True).delete()

    messages.success(
        request,
        f"Project '{project_name}' and its findings were deleted.",
    )

    return redirect("ui:projects:list")


@login_required
@require_POST
def project_scan(request: HttpRequest, project_id: int) -> HttpResponse:
    """Trigger a security scan for a project."""
    org = request.organization
    
    if not org:
        return HttpResponse(
            '<div class="panel" style="border-color: var(--accent-danger);">'
            '<p style="margin:0; color: var(--accent-danger);">Organization not found.</p>'
            '</div>'
        )

    project = get_object_or_404(Project, pk=project_id, organization=org)
    scan_type = request.POST.get("scan_type", "full")

    if project.is_gateway_app:
        msg = (
            "Full Scan is not available for gateway apps. "
            "Monitor this app via Traces and Agents."
        )
        if request.headers.get("HX-Request"):
            return HttpResponse(
                '<div class="panel" style="border-color: var(--border-default);">'
                f'<p style="margin:0; color: var(--text-secondary);">{msg}</p>'
                "</div>"
            )
        messages.info(request, msg)
        return redirect("ui:projects:detail", project_id=project.pk)

    from apps.api.operations import run_project_probe, run_project_scan

    if scan_type in ("probe", "redteam"):
        result = run_project_probe(
            org,
            project.pk,
            probe_id="auto_redteam" if scan_type == "redteam" else "",
            dry_run=not bool(project.api_endpoint) if scan_type == "redteam" else None,
        )
    else:
        result = run_project_scan(org, project.pk, scan_type)

    if result.get("status") == 404:
        result = {
            "success": False,
            "error": result.get("error", "Project not found"),
            "findings": [],
            "summary": {"total_findings": 0, "by_severity": {}},
            "probe_results": {},
        }
    else:
        result.pop("status", None)

    if result.get("code") == "scan_in_progress" and request.headers.get("HX-Request"):
        return HttpResponse(
            '<div class="panel" style="border-color: var(--accent-warning);">'
            '<p style="margin:0; color: var(--text-primary);">'
            f'{result.get("error", "A scan is already running for this project.")}'
            "</p></div>"
        )

    if request.headers.get("HX-Request"):
        if result.get("async") and result.get("scan_run_id"):
            scan_run = ScanRun.objects.get(pk=result["scan_run_id"])
            response = render(
                request,
                "projects/partials/scan_async_poll.html",
                {"scan_run": scan_run, "project": project},
            )
            response["HX-Trigger"] = '{"projectScanQueued": true}'
            return response
        if scan_type in ("probe", "redteam"):
            return render(
                request,
                "ui/partials/probe_results.html",
                {"result": result, "project": project},
            )
        if scan_type in ("full", "comprehensive"):
            return render(
                request,
                "projects/partials/scan_complete_notice.html",
                {"result": result, "project": project},
            )
        return render(
            request,
            "projects/partials/scan_results.html",
            {
                "result": result,
                "project": project,
                "scan_type": scan_type,
            },
        )

    if result.get("async"):
        messages.info(request, result.get("message", "Scan queued."))
        return redirect("ui:projects:detail", project_id=project.pk)

    if result["success"]:
        messages.success(
            request,
            f"Scan completed: {result.get('summary', {}).get('total_findings', 0)} findings detected.",
        )
    else:
        messages.error(request, f"Scan failed: {result.get('error', 'Unknown error')}")

    return redirect("ui:projects:detail", project_id=project.pk)


@login_required
@require_GET
def project_scan_status(request: HttpRequest, project_id: int) -> HttpResponse:
    """Poll async scan progress for HTMX project detail."""
    from apps.api.operations import get_scan_run_status

    org = request.organization
    if not org:
        return HttpResponse("")

    project = get_object_or_404(Project, pk=project_id, organization=org)
    scan_run_id = request.GET.get("scan_run")
    if not scan_run_id:
        return HttpResponse('<p style="margin:0;color:var(--accent-danger);">Missing scan run.</p>')

    status = get_scan_run_status(org, int(scan_run_id))
    if status.get("status") == 404:
        return HttpResponse(
            f'<p style="margin:0;color:var(--accent-danger);">{status.get("error")}</p>'
        )

    if not status.get("completed"):
        scan_run = ScanRun.objects.get(pk=status["scan_run_id"])
        return render(
            request,
            "projects/partials/scan_async_poll.html",
            {"scan_run": scan_run, "project": project},
        )

    scan_run = ScanRun.objects.get(pk=status["scan_run_id"])
    if status.get("status") == ScanRun.Status.FAILED:
        return render(
            request,
            "projects/partials/scan_results.html",
            {
                "project": project,
                "scan_type": scan_run.scan_type,
                "result": {
                    "success": False,
                    "error": status.get("error") or "Scan failed",
                    "summary": status.get("result_summary") or {},
                    "findings": [],
                },
            },
        )

    summary = status.get("result_summary") or {}
    return render(
        request,
        "projects/partials/scan_complete_notice.html",
        {
            "project": project,
            "result": {
                "success": True,
                "summary": summary,
                "findings": [],
            },
        },
    )


@login_required
def project_toggle_status(request: HttpRequest, project_id: int) -> HttpResponse:
    """Toggle project active/paused status."""
    org = request.organization
    
    if not org:
        return HttpResponse("")

    project = get_object_or_404(Project, pk=project_id, organization=org)
    
    if project.status == Project.Status.ACTIVE:
        project.status = Project.Status.PAUSED
    else:
        project.status = Project.Status.ACTIVE
    
    project.save(update_fields=["status"])
    
    if request.headers.get("HX-Request"):
        return render(request, "projects/partials/project_status_badge.html", {"project": project})
    
    return redirect("ui:projects:detail", project_id=project.pk)
