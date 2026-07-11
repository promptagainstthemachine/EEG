"""
EEG - OSV (Open Source Vulnerabilities) Database Fetcher
Queries the OSV.dev API for AI-specific package vulnerabilities.
OSV provides a unified schema across multiple vulnerability databases.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from eeg.collector import Finding, Severity
from eeg.vuln_manager.dependency_parser import ParsedDependency

OSV_API_BASE = "https://api.osv.dev/v1"
QUERY_ENDPOINT = f"{OSV_API_BASE}/query"
BATCH_ENDPOINT = f"{OSV_API_BASE}/querybatch"
REQUEST_DELAY = 0.5


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

ECOSYSTEM_MAP = {
    "pip": "PyPI",
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "rust": "crates.io",
    "cargo": "crates.io",
}


class OSVFetcher:
    """Fetch vulnerabilities from OSV.dev database."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "EEG-Security-Scanner/2.0",
        })

    def fetch_dependencies(
        self,
        deps: List[ParsedDependency],
        cloud_env: str,
    ) -> List[Finding]:
        """Batch-query OSV for multi-ecosystem dependency coordinates."""
        if not deps:
            return []

        packages = []
        for dep in deps:
            eco = ECOSYSTEM_MAP.get(dep.ecosystem.lower(), dep.ecosystem)
            packages.append(
                {
                    "name": dep.name,
                    "version": dep.normalized_version(),
                    "ecosystem": eco,
                }
            )
        return self.batch_query(packages, cloud_env)

    def fetch_all(
        self,
        ai_deps: Dict[str, str],
        cloud_env: str,
        ecosystem: str = "PyPI",
    ) -> List[Finding]:
        """Fetch OSV vulnerabilities for a name→version map (legacy PyPI-style)."""
        findings: List[Finding] = []

        for pkg_name, version in ai_deps.items():
            print(f"    [OSV] Querying OSV.dev for: {pkg_name}@{version}")
            try:
                vulns = self._query_package(pkg_name, version, ecosystem)
                for vuln in vulns:
                    finding = self._vuln_to_finding(vuln, pkg_name, version, cloud_env)
                    if finding:
                        findings.append(finding)
            except Exception as e:
                print(f"    [OSV] Error fetching vulns for {pkg_name}: {e}")
            time.sleep(REQUEST_DELAY)

        return findings

    def batch_query(
        self,
        packages: List[Dict[str, str]],
        cloud_env: str,
    ) -> List[Finding]:
        """Batch query multiple packages at once (more efficient for large scans)."""
        findings: List[Finding] = []

        queries = []
        pkg_map = {}
        for pkg in packages:
            name = pkg.get("name", "").strip()
            version = pkg.get("version", "").strip()
            ecosystem = pkg.get("ecosystem", "PyPI")

            if not name:
                continue

            query: Dict[str, Any] = {
                "package": {
                    "name": name,
                    "ecosystem": ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem),
                }
            }
            if version and version != "unknown":
                query["version"] = version

            queries.append(query)
            pkg_map[name] = {"version": version, "ecosystem": ecosystem}

        if not queries:
            return findings

        print(f"    [OSV] Batch querying {len(queries)} packages...")

        for i in range(0, len(queries), 100):
            batch = queries[i : i + 100]
            try:
                resp = self.session.post(
                    BATCH_ENDPOINT,
                    json={"queries": batch},
                    timeout=60,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])

                    for idx, result in enumerate(results):
                        vulns = result.get("vulns", [])
                        if vulns and idx < len(batch):
                            pkg_name = batch[idx]["package"]["name"]
                            pkg_info = pkg_map.get(pkg_name, {})
                            version = pkg_info.get("version", "unknown")

                            for vuln in vulns:
                                finding = self._vuln_to_finding(
                                    vuln, pkg_name, version, cloud_env
                                )
                                if finding:
                                    findings.append(finding)

                elif resp.status_code == 429:
                    print("    [OSV] Rate limited. Backing off...")
                    time.sleep(5)
                else:
                    print(f"    [OSV] HTTP {resp.status_code}: {resp.text[:200]}")

            except requests.exceptions.RequestException as e:
                print(f"    [OSV] Network error in batch query: {e}")

            time.sleep(REQUEST_DELAY)

        return findings

    def _query_package(
        self,
        package_name: str,
        version: str,
        ecosystem: str = "PyPI",
    ) -> List[Dict[str, Any]]:
        """Query OSV for a specific package."""
        payload: Dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem),
            }
        }
        if version and version != "unknown":
            payload["version"] = version.lstrip(">=<!")

        try:
            resp = self.session.post(QUERY_ENDPOINT, json=payload, timeout=30)

            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
            elif resp.status_code == 429:
                print("    [OSV] Rate limited.")
                return []
            else:
                return []

        except requests.exceptions.RequestException as e:
            print(f"    [OSV] Network error: {e}")
            return []

    def _vuln_to_finding(
        self,
        vuln: Dict[str, Any],
        pkg_name: str,
        version: str,
        cloud_env: str,
    ) -> Optional[Finding]:
        """Convert an OSV vulnerability entry to an EEG Finding."""
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No summary available")
        details = vuln.get("details", "")[:2000]

        severity = self._extract_severity(vuln)
        if severity.weight < Severity.MEDIUM.weight:
            return None

        remediation = self._build_remediation(vuln, pkg_name)

        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        rule_id = vuln_id
        if cve_id:
            rule_id = f"{vuln_id}/{cve_id}"

        cwes = vuln.get("database_specific", {}).get("cwes", [])
        cwe_str = None
        if cwes:
            cwe_str = cwes[0] if isinstance(cwes[0], str) else cwes[0].get("cweId")

        return Finding(
            rule_id=f"OSV-{rule_id}",
            severity=severity,
            category="vulnerability_management",
            cloud_env=cloud_env,
            file_path=f"dependency:{pkg_name}=={version}",
            line_number=0,
            code_snippet=summary[:200],
            message=f"{vuln_id} — {pkg_name} ({summary[:80]})",
            recommendation=remediation,
            cwe=cwe_str,
        )

    def _extract_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Extract severity from OSV vulnerability data."""
        severity_list = vuln.get("severity", [])
        for sev in severity_list:
            if isinstance(sev, dict):
                score_type = sev.get("type", "")
                score = sev.get("score", "")

                if score_type == "CVSS_V3" and isinstance(score, str):
                    try:
                        base_score = float(score.split("/")[0].split(":")[1])
                        if base_score >= 9.0:
                            return Severity.CRITICAL
                        elif base_score >= 7.0:
                            return Severity.HIGH
                        elif base_score >= 4.0:
                            return Severity.MEDIUM
                        else:
                            return Severity.LOW
                    except (ValueError, IndexError):
                        pass

        db_severity = vuln.get("database_specific", {}).get("severity")
        if db_severity:
            return SEVERITY_MAP.get(db_severity.upper(), Severity.MEDIUM)

        return Severity.MEDIUM

    def _build_remediation(self, vuln: Dict[str, Any], pkg_name: str) -> str:
        """Build remediation text from OSV affected ranges."""
        affected = vuln.get("affected", [])
        patched_versions = []
        affected_ranges = []

        for aff in affected:
            ranges = aff.get("ranges", [])
            for rng in ranges:
                events = rng.get("events", [])
                introduced = None
                fixed = None

                for evt in events:
                    if "introduced" in evt:
                        introduced = evt["introduced"]
                    if "fixed" in evt:
                        fixed = evt["fixed"]
                        patched_versions.append(fixed)

                if introduced and fixed:
                    affected_ranges.append(f">= {introduced}, < {fixed}")
                elif introduced:
                    affected_ranges.append(f">= {introduced}")

        parts = []
        if affected_ranges:
            parts.append(f"Affected versions: {'; '.join(affected_ranges[:3])}.")
        if patched_versions:
            latest_patch = sorted(patched_versions)[-1]
            parts.append(f"Upgrade {pkg_name} to >= {latest_patch}.")
        else:
            parts.append(f"Check for updates to {pkg_name}.")

        references = vuln.get("references", [])
        if references:
            ref = references[0]
            url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
            if url:
                parts.append(f"See: {url[:100]}")

        return " ".join(parts) if parts else f"Review and update {pkg_name}."
