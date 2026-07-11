"""Shared scan/probe execution logic for REST API and server-rendered UI (BFF)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from apps.accounts.models import Organization
from apps.projects.models import Project, ScanRun
from apps.security.scan_concurrency import (
    SCAN_FAMILY_DEPENDENCY,
    SCAN_FAMILY_PROBE,
    project_has_active_scan_in_family,
    scan_family,
)


def get_scan_run_status(
    organization: Organization,
    scan_run_id: int,
) -> Dict[str, Any]:
    """Return scan run progress for polling clients."""
    try:
        scan_run = ScanRun.objects.select_related("project").get(
            pk=scan_run_id,
            project__organization=organization,
        )
    except ScanRun.DoesNotExist:
        return {"success": False, "error": "Scan run not found", "status": 404}

    terminal = scan_run.status in (ScanRun.Status.COMPLETED, ScanRun.Status.FAILED)
    return {
        "success": True,
        "scan_run_id": scan_run.pk,
        "project_id": scan_run.project_id,
        "project_name": scan_run.project.name,
        "scan_type": scan_run.scan_type,
        "status": scan_run.status,
        "completed": terminal,
        "error": scan_run.error_message or None,
        "findings_count": scan_run.findings_count,
        "result_summary": scan_run.result_summary or {},
    }


def run_project_scan(
    organization: Organization,
    project_id: int,
    scan_type: str,
) -> Dict[str, Any]:
    """Queue a scan for one project; returns immediately with scan_run_id."""
    try:
        project = Project.objects.get(pk=project_id, organization=organization)
    except Project.DoesNotExist:
        return {"success": False, "error": "Project not found", "status": 404}

    family = scan_family(scan_type)
    if project_has_active_scan_in_family(project, family):
        return {
            "success": False,
            "error": (
                f"A {family} scan is already running or queued for this project. "
                "Wait for it to finish before starting another of the same type."
            ),
            "code": "scan_in_progress",
            "findings": [],
            "summary": {},
            "errors": ["scan_in_progress"],
            "scan_run_id": None,
            "probe_results": {},
        }

    if scan_type in ("probe", "redteam"):
        if scan_type == "redteam" and not getattr(
            project.organization, "auto_redteam_enabled", False
        ):
            return {
                "success": False,
                "error": (
                    "Auto red-team is disabled for this organization. "
                    "Enable it under Profile → Security."
                ),
                "findings": [],
                "summary": {},
                "errors": ["auto_redteam_disabled"],
                "scan_run_id": None,
                "probe_results": {},
            }

    from apps.security.scan_workers import enqueue_project_scan

    scan_run = enqueue_project_scan(project, scan_type)
    return {
        "success": True,
        "async": True,
        "status": "accepted",
        "message": "Scan queued",
        "findings": [],
        "summary": {},
        "errors": None,
        "scan_run_id": scan_run.pk,
        "probe_results": {},
    }


def refresh_threat_intel(
    organization: Organization,
    project_id: int,
) -> Dict[str, Any]:
    """Queue NVD + GitHub GHSA fetch for project dependencies."""
    try:
        project = Project.objects.get(pk=project_id, organization=organization)
    except Project.DoesNotExist:
        return {"success": False, "error": "Project not found", "status": 404}

    if project_has_active_scan_in_family(project, SCAN_FAMILY_DEPENDENCY):
        return {
            "success": False,
            "error": (
                "A CVE refresh is already running for this project. "
                "Wait for it to finish before starting another."
            ),
            "code": "scan_in_progress",
        }

    from apps.security.scan_workers import enqueue_project_scan

    scan_run = enqueue_project_scan(project, "vuln_intel")
    return {
        "success": True,
        "async": True,
        "status": "accepted",
        "scan_run_id": scan_run.pk,
        "project_id": project.pk,
        "project_name": project.name,
        "message": "CVE refresh queued",
    }


def run_project_probe(
    organization: Organization,
    project_id: int,
    *,
    probe_id: str = "",
    dry_run: Optional[bool] = None,
) -> Dict[str, Any]:
    try:
        project = Project.objects.get(pk=project_id, organization=organization)
    except Project.DoesNotExist:
        return {"success": False, "error": "Project not found", "status": 404}

    if project_has_active_scan_in_family(project, SCAN_FAMILY_PROBE):
        return {
            "success": False,
            "error": (
                "A probe run is already in progress for this project. "
                "Wait for it to finish before starting another."
            ),
            "code": "scan_in_progress",
            "findings": [],
            "probe_results": {},
            "summary": {},
            "errors": ["scan_in_progress"],
            "scan_run_id": None,
        }

    from apps.security.scan_workers import enqueue_project_scan

    options: Dict[str, Any] = {"dry_run": dry_run}
    scan_type = "redteam" if probe_id == "auto_redteam" else "probe"
    if probe_id:
        options["probe_ids"] = [probe_id]

    scan_run = enqueue_project_scan(project, scan_type, options=options)
    return {
        "success": True,
        "async": True,
        "status": "accepted",
        "message": "Probe run queued",
        "findings": [],
        "probe_results": {},
        "summary": {},
        "errors": None,
        "scan_run_id": scan_run.pk,
    }
