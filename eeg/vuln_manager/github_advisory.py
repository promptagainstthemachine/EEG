"""
EEG - GitHub Advisory Database Fetcher
Queries GitHub's Security Advisory Database (GHSA) for project dependencies.
Supports both authenticated and unauthenticated access with rate limit handling.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

import requests

from eeg.collector import Finding, Severity
from eeg.vuln_manager.ai_packages import normalize_package_name
from eeg.vuln_manager.dependency_parser import ParsedDependency

GITHUB_API_BASE = "https://api.github.com"
ADVISORIES_ENDPOINT = f"{GITHUB_API_BASE}/advisories"
REQUEST_DELAY = 1.0


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

AI_ECOSYSTEMS = {"pip", "npm", "go", "maven", "nuget", "rubygems", "rust"}


class GitHubAdvisoryFetcher:
    """Fetch security advisories from GitHub's GHSA database."""

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "EEG-Security-Scanner/2.0",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def fetch_ai_advisories(
        self,
        cloud_env: str,
        *,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        per_page: int = 50,
        max_pages: int = 3,
    ) -> List[Finding]:
        """Fetch advisories filtered by ecosystem and optionally severity."""
        findings: List[Finding] = []

        ecosystems = [ecosystem] if ecosystem else list(AI_ECOSYSTEMS)

        for eco in ecosystems:
            print(f"    [GHSA] Querying GitHub advisories for ecosystem: {eco}")
            try:
                advisories = self._query_advisories(
                    ecosystem=eco,
                    severity=severity,
                    per_page=per_page,
                    max_pages=max_pages,
                )
                for adv in advisories:
                    finding = self._advisory_to_finding(adv, cloud_env)
                    if finding:
                        findings.append(finding)
            except Exception as e:
                print(f"    [GHSA] Error fetching advisories for {eco}: {e}")
            time.sleep(REQUEST_DELAY)

        return findings

    def fetch_for_dependencies(
        self,
        deps: List[ParsedDependency],
        cloud_env: str,
        *,
        per_page: int = 50,
        max_pages: int = 2,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> List[Finding]:
        """Fetch GHSA advisories matching packages declared in the project."""
        if not deps:
            return []

        project_packages: Set[str] = {
            normalize_package_name(d.name) for d in deps
        }
        ecosystems = sorted({d.ecosystem.lower() for d in deps})
        findings: List[Finding] = []

        for eco in ecosystems:
            if should_cancel and should_cancel():
                break
            api_eco = "pip" if eco in ("pip", "pypi") else eco
            print(f"    [GHSA] Querying advisories for {api_eco} dependencies")
            try:
                advisories = self._query_advisories(
                    ecosystem=api_eco,
                    per_page=per_page,
                    max_pages=max_pages,
                )
                for adv in advisories:
                    finding = self._advisory_to_finding(
                        adv, cloud_env, project_packages=project_packages
                    )
                    if finding:
                        findings.append(finding)
            except Exception as e:
                print(f"    [GHSA] Error fetching advisories for {api_eco}: {e}")
            time.sleep(REQUEST_DELAY)

        return findings

    fetch_for_ai_dependencies = fetch_for_dependencies

    def _query_advisories(
        self,
        ecosystem: str,
        severity: Optional[str] = None,
        per_page: int = 50,
        max_pages: int = 3,
    ) -> List[Dict[str, Any]]:
        """Query the GitHub Advisories API with pagination."""
        all_advisories: List[Dict[str, Any]] = []
        page = 1

        while page <= max_pages:
            params: Dict[str, Any] = {
                "per_page": min(per_page, 100),
                "ecosystem": ecosystem,
                "type": "reviewed",
            }
            if severity:
                params["severity"] = severity

            try:
                resp = self.session.get(ADVISORIES_ENDPOINT, params=params, timeout=30)

                if resp.status_code == 200:
                    items = resp.json()
                    if not isinstance(items, list) or not items:
                        break
                    all_advisories.extend(items)

                    link_header = resp.headers.get("Link", "")
                    if 'rel="next"' not in link_header:
                        break
                    page += 1

                elif resp.status_code == 403:
                    print("    [GHSA] Rate limited. Consider using GITHUB_TOKEN.")
                    break
                elif resp.status_code == 401:
                    print("    [GHSA] Authentication failed. Check GITHUB_TOKEN.")
                    break
                else:
                    print(f"    [GHSA] HTTP {resp.status_code}: {resp.text[:200]}")
                    break

            except requests.exceptions.RequestException as e:
                print(f"    [GHSA] Network error: {e}")
                break

            time.sleep(REQUEST_DELAY)

        return all_advisories

    def _advisory_to_finding(
        self,
        advisory: Dict[str, Any],
        cloud_env: str,
        *,
        project_packages: Optional[Set[str]] = None,
    ) -> Optional[Finding]:
        """Convert a GitHub Advisory to an EEG Finding for a project dependency."""
        ghsa_id = advisory.get("ghsa_id", "UNKNOWN")
        cve_id = advisory.get("cve_id")
        summary = advisory.get("summary", "No summary")
        description = advisory.get("description", "")[:2000]
        severity_str = (advisory.get("severity") or "medium").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        if severity.weight < Severity.MEDIUM.weight:
            return None

        vulnerabilities = advisory.get("vulnerabilities", [])
        affected_packages = []
        for vuln in vulnerabilities:
            pkg = vuln.get("package", {})
            name = pkg.get("name", "unknown")
            eco = pkg.get("ecosystem", "unknown")
            affected = vuln.get("vulnerable_version_range", "*")
            patched = vuln.get("patched_versions")
            affected_packages.append({
                "name": name,
                "ecosystem": eco,
                "affected": affected,
                "patched": patched,
            })

        matched = affected_packages
        if project_packages is not None:
            matched = [
                p
                for p in affected_packages
                if normalize_package_name(p.get("name", "")) in project_packages
            ]
            if not matched:
                return None

        remediation = self._build_remediation(matched)
        primary = matched[0]
        pkg_name = primary.get("name", "unknown")
        rule_id = f"GHSA-{ghsa_id}"
        if cve_id:
            rule_id = f"{rule_id}/{cve_id}"

        cwes = advisory.get("cwes", [])
        cwe_str = None
        if cwes and isinstance(cwes, list):
            first_cwe = cwes[0]
            if isinstance(first_cwe, dict):
                cwe_str = first_cwe.get("cwe_id")
            elif isinstance(first_cwe, str):
                cwe_str = first_cwe

        return Finding(
            rule_id=rule_id,
            severity=severity,
            category="vulnerability_management",
            cloud_env=cloud_env,
            file_path=f"dependency:{pkg_name}==*",
            line_number=0,
            code_snippet=summary[:200],
            message=f"{ghsa_id} — {summary[:100]}",
            recommendation=remediation,
            cwe=cwe_str,
        )

    @staticmethod
    def _build_remediation(packages: List[Dict[str, Any]]) -> str:
        """Build remediation text from affected package info."""
        if not packages:
            return "Review the advisory and update affected packages."

        parts = []
        for pkg in packages[:5]:
            name = pkg.get("name", "unknown")
            patched = pkg.get("patched", "latest")
            affected = pkg.get("affected", "*")
            if patched:
                parts.append(f"Upgrade {name} to {patched} (affected: {affected}).")
            else:
                parts.append(f"Review {name} ({affected}) for available patches.")

        return " ".join(parts)


def fetch_github_advisories_for_deps(
    ai_deps: Dict[str, str],
    cloud_env: str,
    token: Optional[str] = None,
) -> List[Finding]:
    """Fetch GitHub advisories relevant to detected AI dependencies."""
    from eeg.vuln_manager.dependency_parser import ParsedDependency

    deps = [
        ParsedDependency(name=k, version=v, ecosystem="pip", source_file="")
        for k, v in ai_deps.items()
    ]
    fetcher = GitHubAdvisoryFetcher(token=token)
    return fetcher.fetch_for_dependencies(deps, cloud_env, per_page=30, max_pages=2)
