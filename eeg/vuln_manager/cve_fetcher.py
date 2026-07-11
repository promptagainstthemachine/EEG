"""
EEG - CVE Fetcher
Queries the NVD (National Vulnerability Database) REST API for dependency CVEs.
"""

import time
import requests
from typing import Callable, List, Dict, Optional

from eeg.collector import Finding, Severity
from eeg.vuln_manager.dependency_parser import AI_PACKAGE_REGISTRY, ParsedDependency

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 6  # NVD rate limit: 5 requests per 30 seconds without API key

# Map NVD CVSS v3 severity to EEG severity
CVSS_TO_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

class CVEFetcher:
    """Fetch CVEs from NVD for project dependencies."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "EEG-Security-Scanner/1.0",
        })
        if api_key:
            self.session.headers["apiKey"] = api_key

    def fetch_all(self, deps: Dict[str, str], cloud_env: str) -> List[Finding]:
        """Fetch CVEs for a name→version map (legacy helper)."""
        parsed = [
            ParsedDependency(name=k, version=v, ecosystem="pip", source_file="")
            for k, v in deps.items()
        ]
        return self.fetch_for_dependencies(parsed, cloud_env)

    def fetch_for_dependencies(
        self,
        deps: List[ParsedDependency],
        cloud_env: str,
        *,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> List[Finding]:
        """Fetch NVD CVEs for every declared dependency."""
        findings: List[Finding] = []
        for dep in deps:
            if should_cancel and should_cancel():
                break
            normalized = dep.name.lower().replace("_", "-")
            keyword = AI_PACKAGE_REGISTRY.get(normalized, dep.name)
            print(f"    [NVD] Querying for: {keyword} ({dep.ecosystem}:{dep.name}@{dep.version})")
            try:
                cves = self._query_nvd(keyword)
                for cve in cves:
                    finding = self._cve_to_finding(
                        cve, dep.name, dep.version, cloud_env
                    )
                    if finding:
                        findings.append(finding)
            except Exception as e:
                print(f"    [NVD] Error fetching CVEs for {keyword}: {e}")
            time.sleep(REQUEST_DELAY)
        return findings

    def _query_nvd(self, keyword: str, max_results: int = 10) -> List[Dict]:
        """Query NVD API by keyword. Returns list of CVE items."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }
        try:
            resp = self.session.get(NVD_API_BASE, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulnerabilities", [])
            elif resp.status_code == 403:
                print(f"    [CVE] Rate limited by NVD. Consider using --vm false or setting NVD_API_KEY.")
                return []
            else:
                print(f"    [CVE] NVD returned status {resp.status_code}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"    [CVE] Network error: {e}")
            return []

    def _cve_to_finding(self, vuln: Dict, pkg_name: str, version: str, cloud_env: str) -> Optional[Finding]:
        """Convert an NVD vulnerability entry into an EEG Finding."""
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available")

        # Extract CVSS v3 score and severity
        metrics = cve_data.get("metrics", {})
        severity = Severity.MEDIUM
        cvss_score = 0.0

        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                base_severity = cvss_data.get("baseSeverity", "MEDIUM")
                severity = CVSS_TO_SEVERITY.get(base_severity.upper(), Severity.MEDIUM)
                break

        # Only report MEDIUM+ severity
        if severity.weight < Severity.MEDIUM.weight:
            return None

        # Extract affected version ranges for actionable remediation
        remediation = self._extract_remediation(cve_data, pkg_name)

        return Finding(
            rule_id=f"CVE-{cve_id}",
            severity=severity,
            category="vulnerability_management",
            cloud_env=cloud_env,
            file_path=f"dependency:{pkg_name}=={version}",
            line_number=0,
            code_snippet=desc,
            message=f"{cve_id} — {pkg_name} (CVSS: {cvss_score})",
            recommendation=remediation,
            cwe=self._extract_cwe(cve_data),
        )

    @staticmethod
    def _extract_cwe(cve_data: Dict) -> Optional[str]:
        weaknesses = cve_data.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    return desc["value"]
        return None

    @staticmethod
    def _extract_remediation(cve_data: Dict, pkg_name: str) -> str:
        """Build actionable remediation from NVD configurations (affected/patched versions)."""
        configs = cve_data.get("configurations", [])
        patched_versions = []
        affected_ranges = []

        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        end_excl = cpe_match.get("versionEndExcluding")
                        end_incl = cpe_match.get("versionEndIncluding")
                        start_incl = cpe_match.get("versionStartIncluding")
                        if end_excl:
                            patched_versions.append(end_excl)
                            range_str = f"< {end_excl}"
                            if start_incl:
                                range_str = f">= {start_incl}, {range_str}"
                            affected_ranges.append(range_str)
                        elif end_incl:
                            range_str = f"<= {end_incl}"
                            if start_incl:
                                range_str = f">= {start_incl}, {range_str}"
                            affected_ranges.append(range_str)

        parts = []
        if affected_ranges:
            parts.append(f"Affected versions: {'; '.join(affected_ranges)}.")
        if patched_versions:
            latest_patch = sorted(patched_versions)[-1]
            parts.append(f"Upgrade {pkg_name} to >= {latest_patch}.")
        else:
            parts.append(f"Upgrade {pkg_name} to the latest patched version.")

        return " ".join(parts)
