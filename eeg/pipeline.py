"""Control-plane entry for EEG static analysis (used by EEG-SAAS, not a shell CLI).

Runs the same detector matrix and optional dependency/CVE intel as the historical
`eeg` console flow, without argparse or live-cloud coupling.

Supports multiple vulnerability intelligence sources:
- NVD/CVE: National Vulnerability Database
- GHSA: GitHub Security Advisory Database
- OSV: Open Source Vulnerabilities database
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Set

from eeg.collector import Collector
from eeg.detectors import load_detectors
from eeg.utils.repocrawler import RepoCrawler
from eeg.utils.threadpoolexecutor import ThreadManager
from eeg.vuln_manager.cve_fetcher import CVEFetcher
from eeg.vuln_manager.dependency_parser import DependencyParser


def run_core_static_pipeline(
    cloud_env: str,
    repo_path: Path | str,
    *,
    thread_level: str = "med",
    vm_enabled: bool = True,
    avoid_categories: Optional[Set[str]] = None,
    enable_ghsa: bool = False,
    github_token: Optional[str] = None,
) -> Collector:
    """Crawl *repo_path*, run all EEG static detectors, optionally attach dependency CVE intel.

    Args:
        cloud_env: Cloud environment (aws, azure, gcp)
        repo_path: Path to repository to scan
        thread_level: Threading intensity (low, med, high)
        vm_enabled: Enable vulnerability management (NVD CVE lookup)
        avoid_categories: Set of detector categories to skip
        enable_ghsa: Enable GitHub Security Advisory lookups
        github_token: GitHub token for authenticated GHSA queries

    Returns:
        Populated :class:`Collector` (call ``.to_dict()`` for API payloads).
    """
    path = Path(repo_path).expanduser().resolve()
    if not path.is_dir():
        raise NotADirectoryError(str(path))

    avoid = {c.strip().lower() for c in (avoid_categories or set()) if c and str(c).strip()}

    collector = Collector()
    collector.set_metadata(
        target_path=str(path),
        cloud_env=cloud_env,
        auth_enabled=False,
        vm_enabled=vm_enabled,
        avoided_categories=sorted(avoid),
        thread_level=thread_level,
        vuln_sources=_build_vuln_sources_list(vm_enabled, enable_ghsa),
    )

    crawler = RepoCrawler(str(path))
    files = crawler.crawl()
    collector.set_metadata(files_scanned=len(files))

    detectors = load_detectors(cloud_env, avoid)
    tm = ThreadManager(thread_level)

    def _run(detector):
        return detector.scan(files, collector)

    tm.execute(_run, detectors)

    if vm_enabled or enable_ghsa:
        from eeg.vuln_manager.dependency_scan import scan_project_dependencies

        findings, _summary = scan_project_dependencies(
            str(path),
            cloud_env,
            enable_nvd=vm_enabled,
            enable_ghsa=enable_ghsa,
            github_token=github_token,
        )
        if findings:
            collector.add_findings(findings)

    return collector


def _build_vuln_sources_list(vm_enabled: bool, enable_ghsa: bool) -> list[str]:
    """Build list of enabled vulnerability sources for metadata."""
    sources = []
    if vm_enabled:
        sources.append("nvd")
    if enable_ghsa:
        sources.append("ghsa")
    return sources


def _run_osv_scan(ai_deps: dict, cloud_env: str, collector: Collector) -> None:
    """Run OSV.dev vulnerability scan."""
    try:
        from eeg.vuln_manager.osv_fetcher import OSVFetcher

        print("  [OSV] Running OSV.dev vulnerability scan...")
        osv = OSVFetcher()
        findings = osv.fetch_all(ai_deps, cloud_env)
        collector.add_findings(findings)
        collector.add_completed_check("osv_vulnerability_scan")
    except Exception as e:
        print(f"  [OSV] Error: {e}")
        collector.add_permission_issue("osv_vulnerability_scan", "osv.dev", str(e))


def _run_ghsa_scan(
    ai_deps: dict, cloud_env: str, collector: Collector, token: Optional[str]
) -> None:
    """Run GitHub Security Advisory scan."""
    try:
        from eeg.vuln_manager.github_advisory import GitHubAdvisoryFetcher

        gh_token = token or os.environ.get("GITHUB_TOKEN")
        print("  [GHSA] Running GitHub Security Advisory scan...")
        ghsa = GitHubAdvisoryFetcher(token=gh_token)
        findings = ghsa.fetch_ai_advisories(cloud_env, per_page=30, max_pages=2)
        collector.add_findings(findings)
        collector.add_completed_check("ghsa_advisory_scan")
    except Exception as e:
        print(f"  [GHSA] Error: {e}")
        collector.add_permission_issue("ghsa_advisory_scan", "api.github.com", str(e))


def run_code_security_only(
    repo_path: Path | str,
    cloud_env: str = "any",
    *,
    thread_level: str = "med",
) -> Collector:
    """Run only code security scans (no cloud posture, no CVE intel).

    Lightweight alternative for CI/CD pipelines focused on code patterns.
    """
    path = Path(repo_path).expanduser().resolve()
    if not path.is_dir():
        raise NotADirectoryError(str(path))

    collector = Collector()
    collector.set_metadata(
        target_path=str(path),
        cloud_env=cloud_env,
        scan_type="code_security_only",
        thread_level=thread_level,
    )

    crawler = RepoCrawler(str(path))
    files = crawler.crawl()
    collector.set_metadata(files_scanned=len(files))

    from eeg.detectors.boundary_policy_pack import BoundaryPolicyPackDetector
    from eeg.detectors.secrets import SecretsDetector
    from eeg.detectors.prompt import PromptDetector
    from eeg.detectors.policy import PolicyDetector

    code_detectors = [
        BoundaryPolicyPackDetector(cloud_env),
        SecretsDetector(cloud_env),
        PromptDetector(cloud_env),
        PolicyDetector(cloud_env),
    ]

    tm = ThreadManager(thread_level)

    def _run(detector):
        return detector.scan(files, collector)

    tm.execute(_run, code_detectors)

    return collector
