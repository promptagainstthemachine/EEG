"""Sync gateway-connected apps into Project rows."""

from __future__ import annotations

from typing import Any

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.projects.utils import unique_project_slug


def ensure_gateway_project(
    org: Organization,
    agent_key: str,
    *,
    name: str = "",
) -> Project | None:
    """Create or return the Project that represents a gateway-connected app."""
    key = (agent_key or "").strip()[:255]
    if not key or org is None:
        return None

    existing = Project.objects.filter(organization=org, gateway_agent_key=key).first()
    display = (name or key).strip()[:255] or key
    if existing:
        updates: list[str] = []
        if name and existing.name in ("", existing.gateway_agent_key) and display != existing.name:
            existing.name = display
            updates.append("name")
        if existing.project_type != Project.ProjectType.GATEWAY:
            existing.project_type = Project.ProjectType.GATEWAY
            updates.append("project_type")
        if updates:
            updates.append("updated_at")
            existing.save(update_fields=updates)
        return existing

    slug = unique_project_slug(org, display, f"gw-{key}")
    return Project.objects.create(
        organization=org,
        name=display,
        slug=slug,
        description=f"Gateway-connected app ({key})",
        project_type=Project.ProjectType.GATEWAY,
        gateway_agent_key=key,
        auto_scan_enabled=False,
        status=Project.Status.ACTIVE,
    )


def sync_gateway_projects(org: Organization) -> int:
    """Ensure every ManagedAgent for the org has a matching Project. Returns created count."""
    from apps.security.models import ManagedAgent

    if org is None:
        return 0
    created = 0
    for agent in ManagedAgent.objects.filter(organization=org).only(
        "agent_key", "name"
    ):
        before = Project.objects.filter(
            organization=org, gateway_agent_key=agent.agent_key
        ).exists()
        ensure_gateway_project(org, agent.agent_key, name=agent.name or agent.agent_key)
        if not before:
            created += 1
    return created


def project_connection_payload(project: Project) -> dict[str, Any]:
    return {
        "connection_status": project.connection_status,
        "is_gateway_app": project.is_gateway_app,
        "gateway_agent_key": project.gateway_agent_key or "",
    }
