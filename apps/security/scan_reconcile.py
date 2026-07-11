"""Reconcile scan runs left active after server restart or worker crash."""

from __future__ import annotations

import logging

from django.utils import timezone as django_tz

from apps.projects.models import ScanRun

logger = logging.getLogger(__name__)

_ORPHAN_MESSAGE = "Interrupted: application restarted (no background worker running)"


def reconcile_orphaned_scan_runs() -> int:
    """
    Mark QUEUED/RUNNING scans as failed.

    Background work uses in-process daemon threads, so a process exit leaves
    no worker for those rows. Call on application startup.
    """
    now = django_tz.now()
    updated = ScanRun.objects.filter(
        status__in=(ScanRun.Status.QUEUED, ScanRun.Status.RUNNING),
    ).update(
        status=ScanRun.Status.FAILED,
        completed_at=now,
        error_message=_ORPHAN_MESSAGE,
    )
    if updated:
        logger.info("Reconciled %s orphaned scan run(s) after startup", updated)
    return updated
