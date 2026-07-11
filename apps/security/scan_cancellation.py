"""Cooperative cancellation for background scans (e.g. when a project is deleted)."""

from __future__ import annotations

import threading
from typing import Set

_lock = threading.Lock()
_cancelled_projects: Set[int] = set()
_cancelled_scan_runs: Set[int] = set()


class ScanCancelled(Exception):
    """Raised when a scan should stop because the project was removed."""


def mark_project_cancelled(project_id: int, *, scan_run_ids: Set[int] | None = None) -> None:
    with _lock:
        _cancelled_projects.add(project_id)
        if scan_run_ids:
            _cancelled_scan_runs.update(scan_run_ids)


def is_scan_cancelled(*, project_id: int | None = None, scan_run_id: int | None = None) -> bool:
    with _lock:
        if project_id is not None and project_id in _cancelled_projects:
            return True
        if scan_run_id is not None and scan_run_id in _cancelled_scan_runs:
            return True
    return False


def clear_project_cancellation(project_id: int) -> None:
    with _lock:
        _cancelled_projects.discard(project_id)


def clear_all_cancellations() -> None:
    """Test helper: reset in-memory cancellation state."""
    with _lock:
        _cancelled_projects.clear()
        _cancelled_scan_runs.clear()


def should_cancel_factory(*, project_id: int, scan_run_id: int | None = None):
    """Return a callable suitable for long-running scan loops."""

    def check() -> bool:
        return is_scan_cancelled(project_id=project_id, scan_run_id=scan_run_id)

    return check
