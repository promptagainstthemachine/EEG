"""Sync gateway-connected apps into Project rows."""

from __future__ import annotations

from typing import Any

from django.db import transaction
from django.db.models import Q

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.projects.utils import unique_project_slug


def _canonical_agent_key(agent_key: str) -> str:
    """Match ManagedAgent / gateway identity: bare labels become ``runtime:<label>``."""
    from apps.security.agent_control import normalize_agent_key

    return normalize_agent_key(agent_key)[:255]


def _display_name(name: str, key: str) -> str:
    raw = (name or key or "").strip()
    if raw.startswith("runtime:"):
        raw = raw[8:]
    return (raw or key)[:255]


def _merge_legacy_gateway_project(org: Organization, canonical: str, bare: str) -> Project | None:
    """
    If both ``runtime:X`` and ``X`` projects exist, keep canonical and retarget traces.
    """
    if not bare or bare == canonical:
        return None
    canonical_row = Project.objects.filter(organization=org, gateway_agent_key=canonical).first()
    legacy = Project.objects.filter(organization=org, gateway_agent_key=bare).first()
    if not legacy:
        return canonical_row
    if not canonical_row:
        legacy.gateway_agent_key = canonical
        if legacy.name in ("", bare) or legacy.name == canonical:
            legacy.name = _display_name(legacy.name, bare)
        legacy.project_type = Project.ProjectType.GATEWAY
        legacy.save(update_fields=["gateway_agent_key", "name", "project_type", "updated_at"])
        return legacy

    # Prefer the canonical row; move traces / findings off the legacy duplicate.
    from apps.security.models import AITrace, SecurityFinding

    AITrace.objects.filter(project=legacy).update(project=canonical_row)
    try:
        SecurityFinding.objects.filter(project=legacy).update(project=canonical_row)
    except Exception:
        pass
    if (not canonical_row.name or canonical_row.name in (canonical, bare)) and legacy.name:
        canonical_row.name = _display_name(legacy.name, bare)
        canonical_row.save(update_fields=["name", "updated_at"])
    legacy.delete()
    return canonical_row


def ensure_gateway_project(
    org: Organization,
    agent_key: str,
    *,
    name: str = "",
) -> Project | None:
    """Create or return the Project that represents a gateway-connected app."""
    if not (agent_key or "").strip() or org is None:
        return None

    key = _canonical_agent_key(agent_key)
    if not key:
        return None
    bare = key[8:] if key.startswith("runtime:") else key
    display = _display_name(name, bare or key)

    with transaction.atomic():
        existing = _merge_legacy_gateway_project(org, key, bare)
        if existing is None:
            existing = (
                Project.objects.filter(organization=org)
                .filter(Q(gateway_agent_key=key) | Q(gateway_agent_key=bare))
                .order_by("-id")
                .first()
            )
            if existing and existing.gateway_agent_key != key:
                existing.gateway_agent_key = key
                existing.save(update_fields=["gateway_agent_key", "updated_at"])

        if existing:
            updates: list[str] = []
            if name and existing.name in ("", existing.gateway_agent_key, key, bare, f"runtime:{bare}"):
                if display != existing.name:
                    existing.name = display
                    updates.append("name")
            if existing.project_type != Project.ProjectType.GATEWAY:
                existing.project_type = Project.ProjectType.GATEWAY
                updates.append("project_type")
            if existing.gateway_agent_key != key:
                existing.gateway_agent_key = key
                updates.append("gateway_agent_key")
            if updates:
                updates.append("updated_at")
                existing.save(update_fields=updates)
            return existing

        slug = unique_project_slug(org, display, f"gw-{bare or key}")
        return Project.objects.create(
            organization=org,
            name=display,
            slug=slug,
            description=f"Gateway-connected app ({bare or key})",
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
    for agent in ManagedAgent.objects.filter(organization=org).only("agent_key", "name"):
        key = _canonical_agent_key(agent.agent_key)
        bare = key[8:] if key.startswith("runtime:") else key
        before = Project.objects.filter(organization=org).filter(
            Q(gateway_agent_key=key) | Q(gateway_agent_key=bare)
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
