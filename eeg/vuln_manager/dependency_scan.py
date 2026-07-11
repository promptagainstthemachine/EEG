"""Orchestrate multi-ecosystem dependency vulnerability scanning (NVD + GitHub GHSA)."""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from eeg.collector import Finding
from eeg.vuln_manager.dependency_parser import DependencyParser, ParsedDependency


def scan_project_dependencies(
    repo_path: str,
    cloud_env: str,
    *,
    enable_nvd: bool = True,
    enable_ghsa: bool = True,
    github_token: Optional[str] = None,
    max_packages: int = 400,
    max_nvd_packages: int = 80,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> tuple[List[Finding], Dict[str, Any]]:
    """
    Scan all dependencies from supported manifests using NVD and GitHub advisories only.

    Covers Python, JavaScript/npm, Go, .NET, Ruby, Rust, and Java — every declared package,
    not limited to an AI allowlist.
    """
    parser = DependencyParser(repo_path)
    deps = parser.parse_all(max_packages=max_packages)

    if not deps:
        return [], {
            "packages_found": 0,
            "ecosystems": [],
            "note": (
                "No dependency manifests found. Add package.json, requirements.txt, "
                "go.mod, *.csproj, Gemfile, Cargo.toml, or pom.xml."
            ),
        }

    ecosystems = sorted({d.ecosystem for d in deps})
    findings: List[Finding] = []
    errors: List[str] = []

    if should_cancel and should_cancel():
        summary = {
            "packages_found": len(deps),
            "ecosystems": ecosystems,
            "cancelled": True,
        }
        return findings, summary

    if enable_nvd:
        nvd_deps = deps[:max_nvd_packages]
        if len(deps) > max_nvd_packages:
            errors.append(
                f"NVD lookup capped at {max_nvd_packages} of {len(deps)} packages "
                "(set NVD_API_KEY for higher throughput)."
            )
        try:
            from eeg.vuln_manager.cve_fetcher import CVEFetcher

            nvd_key = os.environ.get("NVD_API_KEY")
            fetcher = CVEFetcher(api_key=nvd_key)
            findings.extend(
                fetcher.fetch_for_dependencies(
                    nvd_deps, cloud_env, should_cancel=should_cancel
                )
            )
        except Exception as exc:
            errors.append(f"NVD scan error: {exc}")

        if should_cancel and should_cancel():
            summary = {
                "packages_found": len(deps),
                "ecosystems": ecosystems,
                "cancelled": True,
            }
            if errors:
                summary["errors"] = errors
            return findings, summary

    if enable_ghsa:
        try:
            from eeg.vuln_manager.github_advisory import GitHubAdvisoryFetcher

            token = github_token or os.environ.get("GITHUB_TOKEN")
            ghsa = GitHubAdvisoryFetcher(token=token)
            findings.extend(
                ghsa.fetch_for_dependencies(deps, cloud_env, should_cancel=should_cancel)
            )
        except Exception as exc:
            errors.append(f"GHSA scan error: {exc}")

    summary: Dict[str, Any] = {
        "packages_found": len(deps),
        "ecosystems": ecosystems,
        "packages": [f"{d.ecosystem}:{d.name}@{d.version}" for d in deps[:50]],
        "sources": {"nvd": enable_nvd, "ghsa": enable_ghsa},
    }
    if errors:
        summary["errors"] = errors
    return findings, summary


# Backward-compatible alias
scan_ai_threat_intel = scan_project_dependencies
