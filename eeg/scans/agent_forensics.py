"""Agent Forensics Scan — deep code audit for AI agent vulnerabilities.

Scans for agent-specific patterns: tool boundary issues, MCP misconfigs,
OWASP Agentic coverage, SSRF, external download, third-party template loading,
and session/state handling vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.rules.bundle_loader import (
    load_aegis_rules,
    load_eeg_import_bundle,
    scan_aegis_rules,
    scan_eeg_import_rules,
)
from eeg.scans import BaseScan, ScanResult, ScanRegistry

# Bundles in catalog.yaml executed via EEG-import loader
EEG_IMPORT_BUNDLES = (
    "prompt_guard",
    "ssrf_patterns",
    "external_download",
    "third_party_content",
)


@ScanRegistry.register
class AgentForensicsScan(BaseScan):
    """Deep agent code forensics scan."""

    scan_id = "agent_forensics"
    scan_type = "static"
    description = (
        "Agent forensics (OWASP Agentic, MCP, prompt guard, SSRF, "
        "external download, third-party templates)"
    )
    categories = [
        "agent",
        "forensics",
        "mcp",
        "ssrf",
        "secrets",
        "owasp",
        "supply_chain",
        "external_download",
        "third_party_content",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._aegis_rules = load_aegis_rules()
        self._eeg_import_rules: Dict[str, List] = {
            name: load_eeg_import_bundle(name) for name in EEG_IMPORT_BUNDLES
        }

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        from eeg.utils.repocrawler import RepoCrawler

        crawler = RepoCrawler(str(target_path))
        files = crawler.crawl()

        for finfo in files:
            files_scanned += 1
            fpath = finfo.get("file_path")
            rel_path = finfo.get("relative_path", fpath)

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
            except OSError:
                continue

            findings.extend(scan_aegis_rules(self._aegis_rules, rel_path, content))
            for bundle_name, rules in self._eeg_import_rules.items():
                bundle_findings = scan_eeg_import_rules(rules, rel_path, content)
                for finding in bundle_findings:
                    finding.setdefault("category", bundle_name.replace("_", "-"))
                findings.extend(bundle_findings)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            sev = finding.get("severity", "MEDIUM").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        rule_counts = {
            "aegis": len(self._aegis_rules),
            **{name: len(rules) for name, rules in self._eeg_import_rules.items()},
        }

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={
                "files_scanned": files_scanned,
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "rule_counts": rule_counts,
            },
        )
