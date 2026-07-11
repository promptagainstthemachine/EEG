"""Deduplicate and lifecycle-manage security findings across scan runs."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional, Set, Tuple

from django.db.models import Q, QuerySet
from django.utils import timezone

from apps.projects.models import Project
from apps.security.finding_filters import VULN_INTEL_CATEGORIES, exclude_vuln_intel_findings
from apps.security.models import SecurityFinding

ACTIVE_STATUSES = frozenset({
    SecurityFinding.Status.OPEN,
    SecurityFinding.Status.ACKNOWLEDGED,
    SecurityFinding.Status.IN_PROGRESS,
})


def normalize_file_path(path: str) -> str:
    return (path or "").strip().replace("\\", "/").lstrip("/")


def build_finding_fingerprint(
    finding: Dict[str, Any],
    *,
    rule_id: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
) -> str:
    """Stable identity for the same vulnerability on the same project."""
    rid = (rule_id or finding.get("rule_id") or "unknown").strip()
    fpath = normalize_file_path(file_path if file_path is not None else finding.get("file_path", ""))
    line = line_number if line_number is not None else finding.get("line_number")
    line_key = 0 if line is None else int(line)
    raw = f"{rid}|{fpath}|{line_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def scope_queryset(qs: QuerySet, scope: str) -> QuerySet:
    """Narrow findings for reconcile: code, vuln, or all."""
    if scope == "all":
        return qs
    if scope == "vuln":
        return qs.filter(
            Q(category__in=VULN_INTEL_CATEGORIES)
            | Q(rule_id__icontains="CVE-")
            | Q(rule_id__icontains="GHSA-")
            | Q(rule_id__icontains="OSV-")
            | Q(source__startswith="vuln_intel")
        )
    return exclude_vuln_intel_findings(qs)


def reconcile_project_findings(
    project: Project,
    seen_fingerprints: Set[str],
    *,
    scope: str = "code",
) -> int:
    """
    Mark open findings not observed in the latest scan as resolved.

    Returns the number of findings auto-resolved.
    """
    qs = SecurityFinding.objects.filter(
        project=project,
        status__in=ACTIVE_STATUSES,
    )
    if seen_fingerprints:
        qs = qs.exclude(fingerprint__in=seen_fingerprints)

    qs = scope_queryset(qs, scope)
    now = timezone.now()
    return qs.update(status=SecurityFinding.Status.RESOLVED, resolved_at=now)


def count_active_findings(project: Project, *, scope: str = "code") -> int:
    qs = SecurityFinding.objects.filter(
        project=project,
        status__in=ACTIVE_STATUSES,
    )
    return scope_queryset(qs, scope).count()
