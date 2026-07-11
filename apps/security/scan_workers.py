"""Background scan execution (NVD, full scan, probes, etc.)."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from django.utils import timezone as django_tz

from apps.projects.models import Project, ScanRun
from apps.security.background import run_in_background
from apps.security.scan_cancellation import (
    ScanCancelled,
    clear_project_cancellation,
    is_scan_cancelled,
    mark_project_cancelled,
    should_cancel_factory,
)

logger = logging.getLogger(__name__)

SCAN_TYPE_ALIASES: Dict[str, str] = {
    "full": ScanRun.ScanType.FULL,
    "comprehensive": ScanRun.ScanType.FULL,
    "code": ScanRun.ScanType.CODE_SECURITY,
    "code_security": ScanRun.ScanType.CODE_SECURITY,
    "model": ScanRun.ScanType.MODEL_ARTIFACT,
    "model_artifact": ScanRun.ScanType.MODEL_ARTIFACT,
    "dependency": ScanRun.ScanType.DEPENDENCY,
    "vuln_intel": ScanRun.ScanType.DEPENDENCY,
    "redteam": ScanRun.ScanType.REDTEAM,
    "probe": ScanRun.ScanType.REDTEAM,
    "cloud": ScanRun.ScanType.CODE_SECURITY,
}

_CANCEL_MESSAGE = "Cancelled: project was deleted"


def resolve_scan_type(scan_type: str) -> str:
    key = (scan_type or "code").strip().lower()
    return SCAN_TYPE_ALIASES.get(key, ScanRun.ScanType.CODE_SECURITY)


def cancel_scans_for_project(project_id: int) -> int:
    """Stop queued/running scans for a project (call before deleting the project)."""
    active = ScanRun.objects.filter(
        project_id=project_id,
        status__in=(ScanRun.Status.QUEUED, ScanRun.Status.RUNNING),
    )
    scan_run_ids = set(active.values_list("pk", flat=True))
    mark_project_cancelled(project_id, scan_run_ids=scan_run_ids)
    now = django_tz.now()
    return active.update(
        status=ScanRun.Status.FAILED,
        completed_at=now,
        error_message=_CANCEL_MESSAGE,
    )


def enqueue_project_scan(
    project: Project,
    scan_type: str,
    *,
    options: Optional[Dict[str, Any]] = None,
) -> ScanRun:
    """Create a queued ScanRun and execute it in a background thread."""
    if not Project.objects.filter(pk=project.pk).exists():
        raise ScanCancelled(_CANCEL_MESSAGE)

    opts = dict(options or {})
    scan_run = ScanRun.objects.create(
        project=project,
        scan_type=resolve_scan_type(scan_type),
        status=ScanRun.Status.QUEUED,
    )
    run_in_background(
        lambda: execute_scan_run(scan_run.pk, scan_type, opts),
        name=f"scan-{scan_run.pk}-{scan_type}",
    )
    return scan_run


def execute_scan_run(
    scan_run_id: int,
    scan_type: str,
    options: Optional[Dict[str, Any]] = None,
) -> None:
    """Run the scan synchronously on a worker thread (updates *scan_run*)."""
    from apps.security.services import (
        CloudAuthService,
        ProbeService,
        ScanningService,
        VulnIntelService,
    )

    opts = options or {}
    scan_run = (
        ScanRun.objects.select_related("project", "project__organization")
        .filter(pk=scan_run_id)
        .first()
    )
    if not scan_run:
        return

    project = scan_run.project
    project_id = project.pk
    should_cancel = should_cancel_factory(
        project_id=project_id,
        scan_run_id=scan_run_id,
    )

    try:
        if _abort_if_cancelled(scan_run_id, project_id):
            return

        scan_run.status = ScanRun.Status.RUNNING
        scan_run.started_at = django_tz.now()
        scan_run.error_message = ""
        scan_run.save(update_fields=["status", "started_at", "error_message"])

        kind = (scan_type or "").strip().lower()

        if kind in ("full", "comprehensive"):
            result = ScanningService.run_comprehensive_scan(
                project,
                scan_run=scan_run,
                include_vuln_intel=opts.get("include_vuln_intel", True),
                include_probes=opts.get("include_probes", True),
                include_cloud_auth=opts.get("include_cloud_auth", True),
                github_token=opts.get("github_token"),
                options=opts.get("scan_options"),
                should_cancel=should_cancel,
            )
            _finalize_from_service_result(scan_run, result)
            return

        if kind in ("dependency", "vuln_intel"):
            result = VulnIntelService.scan_dependencies(
                project,
                enable_nvd=opts.get("enable_nvd", True),
                enable_ghsa=opts.get("enable_ghsa", True),
                github_token=opts.get("github_token"),
                persist=True,
                scan_run=scan_run,
                should_cancel=should_cancel,
            )
            _finalize_vuln_intel_scan(scan_run, result)
            return

        if kind == "cloud":
            result = CloudAuthService.run_cloud_scan(
                project, scan_run=scan_run, persist=True
            )
            _check_cancelled(should_cancel)
            _finalize_from_service_result(scan_run, result)
            return

        if kind in ("probe", "redteam"):
            probe_ids = opts.get("probe_ids")
            if probe_ids is None and kind == "redteam":
                probe_ids = ["auto_redteam"]
            result = ProbeService.run_project_probes(
                project,
                probe_ids=probe_ids,
                persist=True,
                dry_run=opts.get("dry_run"),
                scan_run=scan_run,
            )
            _check_cancelled(should_cancel)
            _finalize_from_service_result(scan_run, result)
            return

        result = ScanningService.run_project_scan(
            project,
            scan_type=kind,
            options=opts.get("scan_options"),
            scan_run=scan_run,
            should_cancel=should_cancel,
        )
        _finalize_from_service_result(scan_run, result)

    except ScanCancelled:
        _mark_scan_cancelled(scan_run_id)
    except Exception as exc:
        logger.exception("Scan run %s failed", scan_run_id)
        if not _abort_if_cancelled(scan_run_id, project_id):
            ScanRun.objects.filter(pk=scan_run_id).update(
                status=ScanRun.Status.FAILED,
                completed_at=django_tz.now(),
                error_message=str(exc),
            )
    finally:
        clear_project_cancellation(project_id)


def _check_cancelled(should_cancel: Optional[Callable[[], bool]]) -> None:
    if should_cancel and should_cancel():
        raise ScanCancelled(_CANCEL_MESSAGE)


def _abort_if_cancelled(scan_run_id: int, project_id: int) -> bool:
    if is_scan_cancelled(project_id=project_id, scan_run_id=scan_run_id):
        _mark_scan_cancelled(scan_run_id)
        return True
    if not Project.objects.filter(pk=project_id).exists():
        _mark_scan_cancelled(scan_run_id)
        return True
    return False


def _mark_scan_cancelled(scan_run_id: int) -> None:
    ScanRun.objects.filter(pk=scan_run_id).update(
        status=ScanRun.Status.FAILED,
        completed_at=django_tz.now(),
        error_message=_CANCEL_MESSAGE,
    )


def _finalize_from_service_result(scan_run: ScanRun, result: Dict[str, Any]) -> None:
    """ScanningService paths usually update scan_run; ensure terminal state for probes/cloud."""
    if not ScanRun.objects.filter(pk=scan_run.pk).exists():
        return
    scan_run.refresh_from_db()
    if scan_run.status in (ScanRun.Status.COMPLETED, ScanRun.Status.FAILED):
        return
    if result.get("cancelled"):
        _mark_scan_cancelled(scan_run.pk)
        return

    summary = result.get("summary") or {}
    by_sev = summary.get("by_severity") or {}

    if result.get("success"):
        scan_run.status = ScanRun.Status.COMPLETED
    else:
        scan_run.status = ScanRun.Status.FAILED
        scan_run.error_message = result.get("error") or scan_run.error_message

    scan_run.completed_at = django_tz.now()
    scan_run.findings_count = summary.get(
        "total_findings",
        summary.get("active_findings", scan_run.findings_count),
    )
    scan_run.critical_count = by_sev.get("CRITICAL", scan_run.critical_count)
    scan_run.high_count = by_sev.get("HIGH", scan_run.high_count)
    scan_run.medium_count = by_sev.get("MEDIUM", scan_run.medium_count)
    scan_run.low_count = by_sev.get("LOW", scan_run.low_count)
    if summary:
        scan_run.result_summary = summary
    scan_run.save()


def _finalize_vuln_intel_scan(scan_run: ScanRun, result: Dict[str, Any]) -> None:
    if not ScanRun.objects.filter(pk=scan_run.pk).exists():
        return
    if result.get("cancelled"):
        _mark_scan_cancelled(scan_run.pk)
        return

    summary = result.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    scan_run.status = (
        ScanRun.Status.COMPLETED if result.get("success") else ScanRun.Status.FAILED
    )
    scan_run.completed_at = django_tz.now()
    scan_run.error_message = result.get("error") or ""
    scan_run.findings_count = summary.get("total_findings", len(result.get("findings") or []))
    scan_run.critical_count = by_sev.get("CRITICAL", 0)
    scan_run.high_count = by_sev.get("HIGH", 0)
    scan_run.medium_count = by_sev.get("MEDIUM", 0)
    scan_run.low_count = by_sev.get("LOW", 0)
    scan_run.result_summary = summary
    scan_run.save()
    if scan_run.status == ScanRun.Status.COMPLETED and Project.objects.filter(
        pk=scan_run.project_id
    ).exists():
        project = scan_run.project
        project.last_scan_at = django_tz.now()
        project.save(update_fields=["last_scan_at"])
