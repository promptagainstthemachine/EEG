"""Dashboard active project selection (persisted per user)."""

from __future__ import annotations

from typing import Optional

from django.db.models import QuerySet
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
        return None, projects
    return saved, projects
