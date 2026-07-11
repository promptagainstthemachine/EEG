"""Resolve local repository paths from user input (paths, file:// URLs).

Security: absolute paths outside allowed roots are rejected to prevent
arbitrary filesystem read/scan (LFI) when the OSS app is hosted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlparse

from django.conf import settings


def is_file_url(value: str) -> bool:
    return (value or "").strip().lower().startswith("file://")


def allowed_scan_roots() -> list[Path]:
    """Directories under which local_path / scan_root may resolve."""
    roots: list[Path] = [
        Path(settings.BASE_DIR).resolve(),
        Path(
            getattr(
                settings,
                "EEG_REPO_STORAGE_ROOT",
                Path(settings.BASE_DIR) / "data" / "repos",
            )
        ).resolve(),
    ]
    extra = (getattr(settings, "EEG_ALLOWED_SCAN_ROOTS", None) or "").strip()
    if not extra:
        extra = (os.environ.get("EEG_ALLOWED_SCAN_ROOTS") or "").strip()
    for part in extra.replace(",", os.pathsep).split(os.pathsep):
        raw = part.strip()
        if not raw:
            continue
        try:
            roots.append(Path(raw).expanduser().resolve())
        except OSError:
            continue
    # De-dupe while preserving order
    seen: set[str] = set()
    out: list[Path] = []
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def is_under_allowed_roots(path: Path | str) -> bool:
    """True when *path* resolves inside an allowed scan root."""
    try:
        resolved = Path(path).expanduser().resolve()
    except OSError:
        return False
    for root in allowed_scan_roots():
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def resolve_local_source_path(
    *,
    local_path: str = "",
    repository_url: str = "",
) -> Optional[Path]:
    """
    Resolve a directory path from local_path and/or a file:// repository_url.

    Relative paths are resolved under Django BASE_DIR
    (e.g. fixtures/vulnerable-apps/ai-goat). Absolute paths must stay under
    BASE_DIR, EEG_REPO_STORAGE_ROOT, or EEG_ALLOWED_SCAN_ROOTS.
    """
    candidates: list[str] = []
    if local_path and local_path.strip():
        candidates.append(local_path.strip())
    if repository_url and is_file_url(repository_url):
        candidates.append(repository_url.strip())

    for raw in candidates:
        path = _raw_to_path(raw)
        if path is None or not path.is_dir():
            continue
        if not is_under_allowed_roots(path):
            continue
        return path
    return None


def _raw_to_path(raw: str) -> Optional[Path]:
    raw = raw.strip()
    if not raw:
        return None

    if is_file_url(raw):
        parsed = urlparse(raw)
        if parsed.netloc and parsed.netloc not in ("localhost", ""):
            # file://fixtures/vulnerable-apps/ai-goat -> fixtures/vulnerable-apps/ai-goat
            combined = f"{parsed.netloc}{parsed.path or ''}"
        else:
            combined = parsed.path or ""
        path = Path(unquote(combined))
    else:
        path = Path(raw).expanduser()

    if not path.is_absolute():
        path = (Path(settings.BASE_DIR) / path).resolve()
    else:
        path = path.resolve()

    return path
