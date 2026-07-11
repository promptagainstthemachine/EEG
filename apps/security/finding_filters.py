"""Query helpers: separate code-security findings from threat-intel (CVE) rows."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from django.db.models import Q, QuerySet

VULN_INTEL_CATEGORIES = frozenset({
    "vulnerability_management",
    "sca",
    "dependency",
    "cve",
})


def is_vuln_intel_finding(*, category: str = "", rule_id: str = "", source: str = "") -> bool:
    cat = (category or "").lower()
    if cat in VULN_INTEL_CATEGORIES:
        rid = (rule_id or "").upper()
        if rid.startswith("OSV-") or "OSV-" in rid:
            return False
        return True
    rid = (rule_id or "").upper()
    if rid.startswith("CVE-") or rid.startswith("GHSA-"):
        return True
    if "CVE-" in rid or "GHSA-" in rid:
        return True
    src = (source or "").lower()
    if src.startswith("vuln_intel"):
        return True
    return False


def exclude_vuln_intel_findings(qs: QuerySet) -> QuerySet:
    """Code / policy findings only — CVE rows belong on Threat Intel."""
    return qs.exclude(category__in=VULN_INTEL_CATEGORIES).exclude(
        Q(rule_id__icontains="CVE-")
        | Q(rule_id__icontains="GHSA-")
        | Q(source__startswith="vuln_intel")
    ).exclude(rule_id__icontains="OSV-")


def vuln_intel_filter_q() -> Q:
    """Q object matching NVD / GHSA dependency rows for Threat Intel (excludes legacy OSV)."""
    return (
        Q(category__in=VULN_INTEL_CATEGORIES)
        | Q(rule_id__icontains="CVE-")
        | Q(rule_id__icontains="GHSA-")
        | Q(source__startswith="vuln_intel")
    ) & ~Q(rule_id__icontains="OSV-")


def vuln_intel_findings_qs(org, *, active_only: bool = True) -> QuerySet:
    """Project-scoped CVE / dependency findings for the Threat Intel feed."""
    from apps.security.models import SecurityFinding

    qs = SecurityFinding.objects.filter(
        organization=org,
        project__isnull=False,
    ).filter(vuln_intel_filter_q())
    if active_only:
        qs = qs.filter(
            status__in=(
                SecurityFinding.Status.OPEN,
                SecurityFinding.Status.ACKNOWLEDGED,
                SecurityFinding.Status.IN_PROGRESS,
            )
        )
    return qs


def partition_findings_by_intel_type(
    findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split scan payloads into code-security vs dependency/CVE rows."""
    code_rows: List[Dict[str, Any]] = []
    vuln_rows: List[Dict[str, Any]] = []
    for finding in findings:
        if is_vuln_intel_finding(
            category=str(finding.get("category") or ""),
            rule_id=str(finding.get("rule_id") or ""),
            source=str(finding.get("source") or ""),
        ):
            vuln_rows.append(finding)
        else:
            code_rows.append(finding)
    return code_rows, vuln_rows
