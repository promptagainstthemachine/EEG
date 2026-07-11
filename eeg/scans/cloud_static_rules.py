"""Cloud static rules scan — repo IaC patterns from rules/static/*.yaml.

Runs category detectors (IAM, storage, guardrail, etc.) for the project's cloud
environment. Skips boundary_pack (handled by code_security).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from eeg.collector import Collector
from eeg.detectors import load_detectors
from eeg.scans import BaseScan, ScanResult, ScanRegistry
from eeg.utils.repocrawler import RepoCrawler

_CLOUD_ENVS = frozenset({"aws", "azure", "gcp"})


def _finding_to_dict(finding: Any) -> Dict[str, Any]:
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    if isinstance(finding, dict):
        return finding
    return {}


@ScanRegistry.register
class CloudStaticRulesScan(BaseScan):
    """Static cloud posture rules on repository files (aws/azure/gcp YAML packs)."""

    scan_id = "cloud_static_rules"
    scan_type = "static"
    description = "Cloud IaC and configuration static rules (IAM, storage, guardrails)"
    categories = ["cloud", "iac", "iam", "storage", "guardrail"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        cloud_env = str(opts.get("cloud_env", "any")).lower()

        if cloud_env not in _CLOUD_ENVS:
            return ScanResult(
                scan_id=self.scan_id,
                scan_type=self.scan_type,
                status="completed",
                findings=[],
                summary={
                    "skipped": True,
                    "reason": f"cloud_env '{cloud_env}' is not aws/azure/gcp",
                },
            )

        collector = Collector()
        collector.set_metadata(
            target_path=str(target_path),
            cloud_env=cloud_env,
            scan_type=self.scan_id,
        )

        crawler = RepoCrawler(str(target_path))
        files = crawler.crawl()
        collector.set_metadata(files_scanned=len(files))

        avoid: Set[str] = {"boundary_pack"}
        detectors = load_detectors(cloud_env, avoid)

        for detector in detectors:
            detector.scan(files, collector)

        data = collector.to_dict()
        findings = [_finding_to_dict(f) for f in data.get("findings", [])]

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            sev = str(finding.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={
                "files_scanned": len(files),
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "cloud_env": cloud_env,
                "detectors_run": len(detectors),
            },
            metadata=data.get("metadata", {}),
        )
