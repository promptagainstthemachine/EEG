"""Project helpers shared by UI and API."""

from __future__ import annotations

from django.utils.text import slugify

from apps.accounts.models import Organization
from apps.projects.models import Project


def unique_project_slug(organization: Organization, name: str, slug: str = "") -> str:
    base = slugify(slug or name) or "project"
    candidate = base
    counter = 1
    while Project.objects.filter(organization=organization, slug=candidate).exists():
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate
