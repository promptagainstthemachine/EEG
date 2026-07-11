"""Helpers for AI-specific threat intelligence (NVD / GHSA / OSV)."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from eeg.vuln_manager.dependency_parser import AI_PACKAGE_REGISTRY

def normalize_package_name(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-")


def is_ai_package_name(name: str) -> bool:
    return normalize_package_name(name) in AI_PACKAGE_REGISTRY


def extract_dependency_package(file_path: str) -> Optional[str]:
    """Parse package name from dependency:pkg==ver (supports scoped npm names)."""
    fp = (file_path or "").strip()
    if not fp.lower().startswith("dependency:"):
        return None
    rest = fp.split(":", 1)[-1]
    if "==" in rest:
        name = rest.split("==", 1)[0]
    else:
        name = rest.split("@", 1)[0] if not rest.startswith("@") else rest
    name = name.strip()
    return normalize_package_name(name) if name else None


def is_ai_threat_intel_finding(
    *,
    category: str = "",
    rule_id: str = "",
    source: str = "",
    file_path: str = "",
    title: str = "",
) -> bool:
    """
    True when a vulnerability row belongs on the AI Threat Intel feed.

    NVD/CVE rows are included when tied to an AI-registry package path.
    GHSA/OSV rows require an AI package in file_path (or GHSA rule with AI title).
    """
    pkg = extract_dependency_package(file_path)
    if pkg and is_ai_package_name(pkg):
        return True

    rid = (rule_id or "").upper()
    if rid.startswith("CVE-") or "/CVE-" in rid:
        return pkg is not None and is_ai_package_name(pkg)

    if (file_path or "").startswith("advisory:"):
        t = (title or "").lower()
        return any(normalize_package_name(k) in t for k in AI_PACKAGE_REGISTRY)

    return False


def is_ai_threat_intel_dict(finding: Dict[str, Any]) -> bool:
    return is_ai_threat_intel_finding(
        category=str(finding.get("category") or ""),
        rule_id=str(finding.get("rule_id") or ""),
        source=str(finding.get("source") or ""),
        file_path=str(finding.get("file_path") or ""),
        title=str(finding.get("message") or finding.get("title") or ""),
    )
