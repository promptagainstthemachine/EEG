"""Dashboard active project selection (persisted per user)."""

from __future__ import annotations

from typing import Optional

from django.db.models import Q, QuerySet
from django.http import HttpRequest

from apps.accounts.models import User
from apps.projects.models import Project


def scan_projects_for_org(organization) -> QuerySet:
    if not organization:
        return Project.objects.none()
    return Project.objects.filter(
        organization=organization,
        status=Project.Status.ACTIVE,
    ).order_by("name")


def get_user_dashboard_project(user: User, organization) -> Optional[Project]:
    if not organization or not user.dashboard_project_id:
        return None
    try:
        return Project.objects.get(
            pk=user.dashboard_project_id,
            organization=organization,
        )
    except Project.DoesNotExist:
        return None


def set_user_dashboard_project(user: User, project: Optional[Project]) -> None:
    new_id = project.pk if project else None
    if user.dashboard_project_id == new_id:
        return
    user.dashboard_project_id = new_id
    user.save(update_fields=["dashboard_project_id", "updated_at"])


def apply_dashboard_project_selection(
    request: HttpRequest,
    organization,
) -> tuple[Optional[Project], QuerySet]:
    """
    Resolve active dashboard project from ?project= or the user's saved preference.
    Persists to the user row when a valid project id is supplied.
    """
    projects = scan_projects_for_org(organization)
    if not organization:
        return None, projects

    user = request.user
    requested = (request.GET.get("project") or "").strip()

    if requested:
        try:
            project_id = int(requested)
        except (TypeError, ValueError):
            project_id = None
        if project_id:
            project = projects.filter(pk=project_id).first()
            if project:
                set_user_dashboard_project(user, project)
                return project, projects
        set_user_dashboard_project(user, None)
        return None, projects

    saved = get_user_dashboard_project(user, organization)
    if saved and not projects.filter(pk=saved.pk).exists():
        set_user_dashboard_project(user, None)
        saved = None

    if saved is None and not requested:
        from apps.projects.models import Project
        from apps.security.models import AITrace

        gateway_projects = projects.filter(
            project_type=Project.ProjectType.GATEWAY,
        ).exclude(gateway_agent_key="")
        for gw in gateway_projects.order_by("-updated_at"):
            keys = {gw.gateway_agent_key}
            bare = gw.gateway_agent_key[8:] if gw.gateway_agent_key.startswith("runtime:") else gw.gateway_agent_key
            keys.add(bare)
            keys.add(f"runtime:{bare}")
            has_traces = AITrace.objects.filter(organization=organization).filter(
                Q(project=gw)
                | Q(project__isnull=True, metadata__agent_key__in=list(keys))
                | Q(project__isnull=True, session_id__in=[f"agent-{k}" for k in keys])
            ).exists()
            if has_traces:
                set_user_dashboard_project(user, gw)
                return gw, projects

    return saved, projects
