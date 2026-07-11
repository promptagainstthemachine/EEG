"""Project lifecycle hooks for managed repository storage."""

from __future__ import annotations

import shutil

from django.db import transaction
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.dispatch import receiver

from apps.projects.models import Project
from apps.projects.path_utils import resolve_local_source_path
from apps.projects.repo_storage import (
    is_managed_repo_path,
    project_repo_path,
    remove_project_repository,
    repo_storage_root,
    schedule_project_repository_sync,
    should_sync_repository,
)


@receiver(pre_delete, sender=Project)
def cancel_background_scans_before_delete(sender, instance: Project, **kwargs) -> None:
    from apps.security.scan_workers import cancel_scans_for_project

    cancel_scans_for_project(instance.pk)


@receiver(post_delete, sender=Project)
def cleanup_project_repository(sender, instance: Project, **kwargs) -> None:
    remove_project_repository(instance)


@receiver(pre_save, sender=Project)
def capture_project_change_state(sender, instance: Project, **kwargs) -> None:
    instance._eeg_previous_slug = None  # type: ignore[attr-defined]
    instance._eeg_previous_repository_url = None  # type: ignore[attr-defined]
    instance._eeg_previous_local_path = None  # type: ignore[attr-defined]
    if not instance.pk:
        return
    try:
        old = Project.objects.only("slug", "repository_url", "local_path").get(pk=instance.pk)
    except Project.DoesNotExist:
        return
    instance._eeg_previous_slug = old.slug  # type: ignore[attr-defined]
    instance._eeg_previous_repository_url = old.repository_url  # type: ignore[attr-defined]
    instance._eeg_previous_local_path = old.local_path  # type: ignore[attr-defined]


@receiver(post_save, sender=Project)
def sync_repository_after_save(sender, instance: Project, created: bool, **kwargs) -> None:
    """Clone or refresh managed repo; relocate tree if slug changed."""
    previous_slug = getattr(instance, "_eeg_previous_slug", None)
    if previous_slug and previous_slug != instance.slug:
        old_path = (
            repo_storage_root()
            / "org"
            / instance.organization.slug
            / previous_slug
        )
        new_path = project_repo_path(instance)
        if old_path.is_dir() and is_managed_repo_path(old_path) and not new_path.exists():
            new_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old_path), str(new_path))

    repo_changed = (
        getattr(instance, "_eeg_previous_repository_url", None) != instance.repository_url
    )
    local_changed = getattr(instance, "_eeg_previous_local_path", None) != instance.local_path
    managed_exists = project_repo_path(instance).is_dir()

    has_local_source = bool(
        resolve_local_source_path(
            local_path=instance.local_path or "",
            repository_url=instance.repository_url or "",
        )
    )
    needs_sync = (
        should_sync_repository(instance)
        or repo_changed
        or local_changed
        or (created and has_local_source)
    )
    if not needs_sync:
        return

    project_id = instance.pk
    force = created or repo_changed or local_changed

    def _after_commit() -> None:
        try:
            project = Project.objects.select_related("organization").get(pk=project_id)
        except Project.DoesNotExist:
            return
        schedule_project_repository_sync(project, force=force)

    transaction.on_commit(_after_commit)
