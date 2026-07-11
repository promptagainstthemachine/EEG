"""Persistent org-scoped repository storage for scans and finding code context."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from django.conf import settings

from apps.projects.models import Project
from apps.projects.path_utils import is_file_url, resolve_local_source_path

logger = logging.getLogger(__name__)


def repo_storage_root() -> Path:
    root = Path(getattr(settings, "EEG_REPO_STORAGE_ROOT", settings.BASE_DIR / "data" / "repos"))
    return root.expanduser().resolve()


def project_repo_path(project: Project) -> Path:
    """Managed path: {root}/org/{org_slug}/{project_slug}/"""
    org_slug = project.organization.slug
    return repo_storage_root() / "org" / org_slug / project.slug


def is_managed_repo_path(path: str | Path) -> bool:
    if not path:
        return False
    try:
        Path(path).expanduser().resolve().relative_to(repo_storage_root())
        return True
    except (ValueError, OSError):
        return False


def should_sync_repository(project: Project) -> bool:
    if project.repository_url and not is_file_url(project.repository_url):
        return True
    source = resolve_local_source_path(
        local_path=project.local_path or "",
        repository_url=project.repository_url or "",
    )
    return source is not None and not is_managed_repo_path(source)


def sync_project_repository(project: Project, *, force: bool = False) -> Optional[Path]:
    """Clone, pull, or copy sources into the managed org/project directory."""
    dest = project_repo_path(project)
    source = resolve_local_source_path(
        local_path=project.local_path or "",
        repository_url=project.repository_url or "",
    )

    if source is not None and not is_managed_repo_path(source):
        dest.parent.mkdir(parents=True, exist_ok=True)
        _copy_local_tree(source, dest)
        return dest

    if not should_sync_repository(project):
        return dest if dest.is_dir() else None

    dest.parent.mkdir(parents=True, exist_ok=True)

    if project.repository_url and not is_file_url(project.repository_url):
        return _git_sync(project.repository_url.strip(), dest, force=force)

    return dest if dest.is_dir() else None


def persist_project_repository(project: Project, *, force: bool = False) -> Optional[Path]:
    """Sync repo files and store absolute path on project.local_path."""
    path = sync_project_repository(project, force=force)
    if not path or not path.is_dir():
        return None

    resolved = str(path.resolve())
    if project.local_path != resolved:
        Project.objects.filter(pk=project.pk).update(local_path=resolved)
        project.local_path = resolved
    return path


def schedule_project_repository_sync(project: Project, *, force: bool = False) -> None:
    """Copy/clone repository in a background thread (non-blocking HTTP)."""
    from apps.security.background import run_in_background

    project_id = project.pk

    def _run() -> None:
        try:
            fresh = Project.objects.select_related("organization").get(pk=project_id)
        except Project.DoesNotExist:
            return
        persist_project_repository(fresh, force=force)

    run_in_background(_run, name=f"repo-sync-{project_id}")


def remove_project_repository(project: Project) -> None:
    """Delete managed project tree only (org folder is kept)."""
    path = project_repo_path(project)
    if not path.exists():
        return
    if not is_managed_repo_path(path):
        logger.warning("Refusing to remove path outside storage root: %s", path)
        return
    shutil.rmtree(path, ignore_errors=True)


def _copy_local_tree(src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(
        src,
        dest,
        symlinks=False,
        ignore_dangling_symlinks=True,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", ".venv"),
    )


def _git_sync(url: str, dest: Path, *, force: bool = False) -> Optional[Path]:
    if is_file_url(url):
        logger.warning("Refusing git sync for file:// URL; use local path instead: %s", url)
        return dest if dest.is_dir() else None

    git_dir = dest / ".git"
    try:
        if git_dir.is_dir() and not force:
            result = subprocess.run(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if result.returncode == 0:
                return dest
            logger.info("git pull failed for %s, re-cloning: %s", dest, result.stderr.strip())

        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)

        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        return dest
    except (subprocess.SubprocessError, OSError, FileNotFoundError) as exc:
        logger.warning("Failed to sync repository %s -> %s: %s", url, dest, exc)
        return dest if dest.is_dir() else None
