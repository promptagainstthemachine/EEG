"""EEG Vulnerability Management Package.

Provides multi-source vulnerability intelligence:
- CVE/NVD: National Vulnerability Database queries
- GHSA: GitHub Security Advisory Database
- OSV: Open Source Vulnerabilities database
- Code Security: In-tree static rule execution for AI code patterns
"""

from eeg.vuln_manager.cve_fetcher import CVEFetcher
from eeg.vuln_manager.dependency_parser import (
    AI_PACKAGE_REGISTRY,
    DependencyParser,
    ParsedDependency,
)
from eeg.vuln_manager.dependency_scan import scan_project_dependencies
from eeg.vuln_manager.github_advisory import GitHubAdvisoryFetcher, fetch_github_advisories_for_deps
from eeg.vuln_manager.osv_fetcher import OSVFetcher
from eeg.vuln_manager.code_security import (
    run_code_security_scan,
    get_code_security_rule_summary,
    list_ai_practice_pattern_rules,
)

__all__ = [
    "CVEFetcher",
    "DependencyParser",
    "ParsedDependency",
    "AI_PACKAGE_REGISTRY",
    "scan_project_dependencies",
    "GitHubAdvisoryFetcher",
    "fetch_github_advisories_for_deps",
    "OSVFetcher",
    "run_code_security_scan",
    "get_code_security_rule_summary",
    "list_ai_practice_pattern_rules",
]
