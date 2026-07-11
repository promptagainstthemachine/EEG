"""Dependency Vulnerability Scan — NVD CVE and GitHub GHSA lookup."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.collector import Collector
from eeg.scans import BaseScan, ScanResult, ScanRegistry
from eeg.vuln_manager.dependency_scan import scan_project_dependencies


@ScanRegistry.register
class DependencyVulnScan(BaseScan):
    """Dependency vulnerability scan (Python, JS, Go, .NET, Ruby, Rust, Java)."""

    scan_id = "dependency_vuln"
    scan_type = "sca"
    description = (
        "Dependency CVE scan (NVD + GitHub GHSA) for all packages in Python, "
        "JavaScript/npm, Go, .NET, Ruby, Rust, and Java manifests"
    )
    categories = ["sca", "dependency", "vulnerability", "supply_chain"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        cloud_env = opts.get("cloud_env", "any")
        enable_nvd = opts.get("enable_nvd", True)
        enable_ghsa = opts.get("enable_ghsa", True)
        github_token = opts.get("github_token")

        collector = Collector()
        findings, summary = scan_project_dependencies(
            str(target_path),
            cloud_env,
            enable_nvd=enable_nvd,
            enable_ghsa=enable_ghsa,
            github_token=github_token,
        )
        collector.add_findings(findings)

        if summary.get("packages_found", 0):
            collector.add_completed_check("dependency_vuln_scan")

        errors = summary.get("errors") or []
        status = "completed" if not errors else "partial"

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status=status,
            findings=collector.to_dict().get("findings", []),
            summary=summary,
            errors=errors or None,
        )
