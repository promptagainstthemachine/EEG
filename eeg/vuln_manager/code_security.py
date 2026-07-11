"""
EEG - Code Security Scanner Integration
Orchestrates in-tree static rule execution for code security scanning.
Provides unified interface for bundled AI practice patterns and EEG-native rules.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from eeg.collector import Collector, Finding
from eeg.detectors.boundary_policy_pack import BoundaryPolicyPackDetector
from eeg.utils.repocrawler import RepoCrawler


AI_CODE_SECURITY_CATEGORIES = frozenset({
    "prompt",
    "secrets",
    "policy",
    "boundary_pack",
})


def run_code_security_scan(
    repo_path: Path | str,
    cloud_env: str = "any",
    *,
    categories: Optional[Set[str]] = None,
    include_boundary_pack: bool = True,
) -> Dict[str, Any]:
    """Run focused code security scan using EEG bundled rules.

    This function provides a lightweight alternative to the full pipeline
    when you only need code security (no cloud posture, no CVE intel).

    Args:
        repo_path: Path to repository or directory to scan
        cloud_env: Cloud environment hint (aws, azure, gcp, any)
        categories: Specific categories to scan (defaults to AI code security set)
        include_boundary_pack: Whether to include bundled AI practice patterns

    Returns:
        Dict with findings, summary, and scan metadata
    """
    path = Path(repo_path).expanduser().resolve()
    if not path.is_dir():
        raise NotADirectoryError(f"Scan path is not a directory: {path}")

    collector = Collector()
    collector.set_metadata(
        target_path=str(path),
        cloud_env=cloud_env,
        scan_type="code_security",
    )

    crawler = RepoCrawler(str(path))
    files = crawler.crawl()
    collector.set_metadata(files_scanned=len(files))

    target_categories = categories or AI_CODE_SECURITY_CATEGORIES

    if include_boundary_pack and "boundary_pack" in target_categories:
        detector = BoundaryPolicyPackDetector(cloud_env)
        detector.scan(files, collector)

    result = collector.to_dict()
    result["scan_type"] = "code_security"
    result["categories_scanned"] = sorted(target_categories)

    return result


def get_code_security_rule_summary() -> Dict[str, Any]:
    """Get summary of available code security and bundle rules."""
    from eeg.detectors.boundary_policy_pack import _BUNDLES_ROOT, _parse_pack_rules
    from eeg.rules.bundle_loader import load_aegis_rules, load_eeg_import_bundle
    from eeg.rules.catalog_loader import get_bundle_manifest

    pack_dir = os.path.join(_BUNDLES_ROOT, "ai_practice_patterns")
    rows = _parse_pack_rules(pack_dir)

    by_category: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    for row in rows:
        cat = row.get("category", "unknown")
        sev = str(row.get("severity", "MEDIUM"))
        if hasattr(row.get("severity"), "value"):
            sev = row["severity"].value

        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    agent_forensics_counts = {
        "aegis_rules": len(load_aegis_rules()),
        "prompt_guard": len(load_eeg_import_bundle("prompt_guard")),
        "ssrf_patterns": len(load_eeg_import_bundle("ssrf_patterns")),
        "external_download": len(load_eeg_import_bundle("external_download")),
        "third_party_content": len(load_eeg_import_bundle("third_party_content")),
    }

    return {
        "total_rules": len(rows),
        "by_category": by_category,
        "by_severity": by_severity,
        "bundle_path": pack_dir,
        "boundary_pack_rules": len(rows),
        "agent_forensics_rules": agent_forensics_counts,
        "catalog_bundles": get_bundle_manifest(),
    }


def list_ai_practice_pattern_rules() -> List[Dict[str, Any]]:
    """List all bundled AI practice pattern rules with metadata."""
    from eeg.detectors.boundary_policy_pack import _BUNDLES_ROOT, _parse_pack_rules

    pack_dir = os.path.join(_BUNDLES_ROOT, "ai_practice_patterns")
    rows = _parse_pack_rules(pack_dir)

    rules = []
    for row in rows:
        severity = row.get("severity")
        sev_str = severity.value if hasattr(severity, "value") else str(severity)

        rules.append({
            "rule_id": row.get("eeg_rule_id"),
            "category": row.get("category"),
            "severity": sev_str,
            "message": row.get("message", "")[:200],
            "source_pack": row.get("source_pack"),
            "cwe": row.get("cwe"),
        })

    return rules
