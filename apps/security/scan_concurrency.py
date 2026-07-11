"""Per-scan-family concurrency (CVE refresh vs full scan can run together)."""

from __future__ import annotations

from typing import Optional

from apps.projects.models import Project, ScanRun

SCAN_FAMILY_FULL = "full"
SCAN_FAMILY_DEPENDENCY = "dependency"
SCAN_FAMILY_CODE = "code"
SCAN_FAMILY_PROBE = "probe"

_FAMILY_SCAN_TYPES = {
    SCAN_FAMILY_FULL: {ScanRun.ScanType.FULL},
    SCAN_FAMILY_DEPENDENCY: {ScanRun.ScanType.DEPENDENCY},
    SCAN_FAMILY_CODE: {
        ScanRun.ScanType.CODE_SECURITY,
        ScanRun.ScanType.MODEL_ARTIFACT,
        ScanRun.ScanType.AGENT_FORENSICS,
    },
    SCAN_FAMILY_PROBE: {ScanRun.ScanType.REDTEAM},
}

_ACTIVE = (ScanRun.Status.QUEUED, ScanRun.Status.RUNNING)

_TYPE_TO_FAMILY = {
    "full": SCAN_FAMILY_FULL,
    "comprehensive": SCAN_FAMILY_FULL,
    "dependency": SCAN_FAMILY_DEPENDENCY,
    "vuln_intel": SCAN_FAMILY_DEPENDENCY,
    "code": SCAN_FAMILY_CODE,
    "code_security": SCAN_FAMILY_CODE,
    "model": SCAN_FAMILY_CODE,
    "model_artifact": SCAN_FAMILY_CODE,
    "cloud": SCAN_FAMILY_CODE,
    "agent": SCAN_FAMILY_CODE,
    "probe": SCAN_FAMILY_PROBE,
    "redteam": SCAN_FAMILY_PROBE,
}


def scan_family(scan_type: str) -> str:
    key = (scan_type or "code").strip().lower()
    return _TYPE_TO_FAMILY.get(key, SCAN_FAMILY_CODE)


def project_has_active_scan_in_family(project: Project, family: str) -> bool:
    types = _FAMILY_SCAN_TYPES.get(family, _FAMILY_SCAN_TYPES[SCAN_FAMILY_CODE])
    return ScanRun.objects.filter(
        project=project,
        scan_type__in=types,
        status__in=_ACTIVE,
    ).exists()


def get_active_scan_run(
    project: Project,
    family: str,
) -> Optional[ScanRun]:
    types = _FAMILY_SCAN_TYPES.get(family, _FAMILY_SCAN_TYPES[SCAN_FAMILY_CODE])
    return (
        ScanRun.objects.filter(
            project=project,
            scan_type__in=types,
            status__in=_ACTIVE,
        )
        .order_by("-created_at")
        .first()
    )
