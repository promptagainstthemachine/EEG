"""EEG Security Scanning Service.

Connects Django views to the EEG scanning engine.
Includes vulnerability intelligence from NVD, OSV, and GitHub Advisory databases.
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from datetime import datetime

from django.conf import settings
from django.utils import timezone as django_tz

from apps.projects.models import Project, ScanRun
from apps.projects.repo_storage import persist_project_repository, project_repo_path

from apps.security.finding_dedup import (
    build_finding_fingerprint,
    count_active_findings,
    reconcile_project_findings,
)
from apps.security.models import SecurityFinding
from eeg.scans import run_scan, run_all_scans, get_all_scans, ScanResult
from eeg.probes import run_probe, get_all_probes, ProbeResult
from eeg.rules.catalog_loader import (
    get_full_scan_ids,
    get_probe_ids_for_api_endpoint,
    get_scan_ids_for_profile,
)

logger = logging.getLogger(__name__)

CLOUD_PROJECT_TYPES = {Project.ProjectType.AWS, Project.ProjectType.GCP, Project.ProjectType.AZURE}


def _cloud_project_type(project: Project) -> Optional[str]:
    pt = project.project_type
    if pt in CLOUD_PROJECT_TYPES:
        return str(pt).lower()
    return None


def _scan_options_for_project(
    project: Project,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Merge scan options with cloud_env from project type."""
    merged = dict(options or {})
    cloud = _cloud_project_type(project)
    if cloud and merged.get("cloud_env", "any") == "any":
        merged["cloud_env"] = cloud
    elif "cloud_env" not in merged:
        merged["cloud_env"] = "any"
    github_token = merged.get("github_token") or os.environ.get("GITHUB_TOKEN")
    if github_token:
        merged["github_token"] = github_token
    merged.setdefault("enable_nvd", True)
    merged.setdefault("enable_ghsa", True)
    return merged


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev = str(finding.get("severity", "MEDIUM")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _merge_summaries(*summaries: Dict[str, Any]) -> Dict[str, Any]:
    total = 0
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    scans_executed: List[str] = []
    probes_executed: List[str] = []

    for summary in summaries:
        if not summary:
            continue
        total += summary.get("total_findings", 0)
        for sev, count in (summary.get("by_severity") or {}).items():
            key = str(sev).upper()
            if key in by_severity:
                by_severity[key] += count
        scans_executed.extend(summary.get("scans_executed") or [])
        probes_executed.extend(summary.get("probes_executed") or [])

    return {
        "total_findings": total,
        "by_severity": by_severity,
        "scans_executed": scans_executed,
        "probes_executed": probes_executed,
    }


class ScanningService:
    """Service for running EEG security scans with vulnerability intelligence."""

    @classmethod
    def get_scan_ids_for_type(
        cls,
        scan_type: str,
        *,
        include_model: bool = False,
        project: Optional[Project] = None,
    ) -> Optional[List[str]]:
        """Resolve scan IDs from catalog scan_profiles. None = run all registered scans."""
        if scan_type in ("full", "comprehensive"):
            return get_full_scan_ids(
                include_model=include_model,
                cloud_project_type=_cloud_project_type(project) if project else None,
            )

        profile = scan_type
        if scan_type == "vuln_intel":
            profile = "dependency"

        if profile in ("code", "model", "dependency", "agent"):
            return get_scan_ids_for_profile(
                profile,
                include_model=include_model,
                cloud_project_type=_cloud_project_type(project) if project else None,
            )

        return None

    @classmethod
    def get_available_scans(cls) -> List[Dict[str, Any]]:
        """Return list of available scan types."""
        scans = get_all_scans()
        return [
            {
                "scan_id": scan_id,
                "scan_type": scan_cls.scan_type,
                "description": scan_cls.description,
                "categories": scan_cls.categories,
            }
            for scan_id, scan_cls in scans.items()
        ]
    
    @classmethod
    def run_project_scan(
        cls,
        project: Project,
        scan_type: str = "code",
        options: Optional[Dict[str, Any]] = None,
        scan_run: Optional[ScanRun] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Run security scan on a project.
        
        Args:
            project: Project model instance
            scan_type: Type of scan (code, model, dependency, full)
            options: Additional scan options
            
        Returns:
            Dict with scan results and any created ScanRun
        """
        from apps.security.scan_workers import resolve_scan_type

        if scan_run is None:
            scan_run = ScanRun.objects.create(
                project=project,
                scan_type=resolve_scan_type(scan_type),
                status=ScanRun.Status.RUNNING,
                started_at=django_tz.now(),
            )

        def _cancelled_response() -> Dict[str, Any]:
            return {
                "success": False,
                "cancelled": True,
                "error": "Cancelled: project was deleted",
                "scan_run": scan_run,
                "findings": [],
            }

        try:
            if should_cancel and should_cancel():
                return _cancelled_response()

            org = project.organization
            if scan_type == "model" and not getattr(org, "model_scanning_enabled", False):
                scan_run.status = ScanRun.Status.FAILED
                scan_run.completed_at = django_tz.now()
                scan_run.error_message = (
                    "Model scanning is disabled for this organization. "
                    "Enable it under Profile → Security."
                )
                scan_run.save()
                return {
                    "success": False,
                    "error": scan_run.error_message,
                    "scan_run": scan_run,
                    "findings": [],
                }

            target_path = cls._resolve_project_path(project)
            
            if not target_path or not target_path.exists():
                scan_run.status = ScanRun.Status.FAILED
                scan_run.completed_at = django_tz.now()
                scan_run.error_message = "Project path not found or inaccessible"
                scan_run.save()
                return {
                    "success": False,
                    "error": "Project path not found or inaccessible",
                    "scan_run": scan_run,
                    "findings": [],
                }
            
            include_model = getattr(org, "model_scanning_enabled", False)
            scan_opts = _scan_options_for_project(project, options)
            scan_ids = cls.get_scan_ids_for_type(
                scan_type,
                include_model=include_model,
                project=project,
            )

            if scan_ids is None:
                if should_cancel and should_cancel():
                    return _cancelled_response()
                results = run_all_scans(target_path, config=scan_opts)
            else:
                results = {}
                for sid in scan_ids:
                    if should_cancel and should_cancel():
                        return _cancelled_response()
                    results[sid] = run_scan(sid, target_path, options=scan_opts)

            if should_cancel and should_cancel():
                return _cancelled_response()

            all_findings: List[Dict[str, Any]] = []
            for scan_id, result in results.items():
                all_findings.extend(result.findings)

            persist_stats = cls._persist_findings_batch(
                project,
                scan_run,
                all_findings,
                scan_root=str(target_path),
                reconcile_scope="code",
            )
            total_by_severity = _severity_counts(all_findings)
            active_count = count_active_findings(project, scope="code")

            scan_run.status = ScanRun.Status.COMPLETED
            scan_run.completed_at = django_tz.now()
            scan_run.findings_count = active_count
            scan_run.critical_count = total_by_severity["CRITICAL"]
            scan_run.high_count = total_by_severity["HIGH"]
            scan_run.medium_count = total_by_severity["MEDIUM"]
            scan_run.low_count = total_by_severity["LOW"]
            scan_run.result_summary = {
                "detected_in_scan": len(all_findings),
                "new_findings": persist_stats["new"],
                "updated_findings": persist_stats["updated"],
                "resolved_findings": persist_stats["resolved"],
                "active_findings": active_count,
                "by_severity": total_by_severity,
            }
            scan_run.save()
            
            project.last_scan_at = django_tz.now()
            project.save(update_fields=["last_scan_at"])
            
            return {
                "success": True,
                "scan_run": scan_run,
                "findings": all_findings,
                "summary": {
                    "total_findings": len(all_findings),
                    "by_severity": total_by_severity,
                    "scans_executed": list(results.keys()),
                },
            }
            
        except Exception as e:
            logger.exception("Scan failed for project %s", project.pk)
            scan_run.status = ScanRun.Status.FAILED
            scan_run.completed_at = django_tz.now()
            scan_run.error_message = str(e)
            scan_run.save()
            return {
                "success": False,
                "error": str(e),
                "scan_run": scan_run,
                "findings": [],
            }
    
    @classmethod
    def resolve_project_target(cls, project: Project) -> Optional[str]:
        """Resolve network probe target URL for a project."""
        if project.api_endpoint:
            return project.api_endpoint.strip()
        if project.repository_url:
            return project.repository_url.strip()
        return None

    @classmethod
    def _resolve_project_path(cls, project: Project) -> Optional[Path]:
        """Resolve filesystem path (managed org/project storage preferred)."""
        managed = project_repo_path(project)
        if managed.is_dir():
            if project.repository_url:
                persisted = persist_project_repository(project)
                if persisted:
                    return persisted
            return managed

        if project.local_path:
            from apps.projects.path_utils import is_under_allowed_roots

            path = Path(project.local_path).expanduser()
            if path.is_dir() and is_under_allowed_roots(path):
                return path

        if project.repository_url or project.project_type == Project.ProjectType.LOCAL:
            persisted = persist_project_repository(project)
            if persisted:
                return persisted

        return None
    
    @classmethod
    def _persist_findings_batch(
        cls,
        project: Project,
        scan_run: Optional[ScanRun],
        findings: List[Dict[str, Any]],
        *,
        source_prefix: str = "scan",
        scan_root: Optional[str] = None,
        reconcile_scope: Optional[str] = "code",
        seen_fingerprints: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Upsert findings and optionally reconcile stale open rows for this project."""
        seen = set(seen_fingerprints or ())
        new_count = 0
        updated_count = 0

        for finding in findings:
            obj, created = cls._upsert_finding(
                project,
                scan_run,
                finding,
                source_prefix=source_prefix,
                scan_root=scan_root,
            )
            if obj.fingerprint:
                seen.add(obj.fingerprint)
            if created:
                new_count += 1
            else:
                updated_count += 1

        resolved_count = 0
        if reconcile_scope:
            resolved_count = reconcile_project_findings(
                project,
                seen,
                scope=reconcile_scope,
            )

        return {
            "new": new_count,
            "updated": updated_count,
            "resolved": resolved_count,
            "seen_fingerprints": seen,
        }

    @classmethod
    def _upsert_finding(
        cls,
        project: Project,
        scan_run: Optional[ScanRun],
        finding: Dict[str, Any],
        *,
        source_prefix: str = "scan",
        scan_root: Optional[str] = None,
    ) -> Tuple[SecurityFinding, bool]:
        """Create or update a finding keyed by rule + file + line."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }

        raw_severity = finding.get("severity", "MEDIUM")
        if hasattr(raw_severity, "value"):
            raw_severity = raw_severity.value
        raw_severity = str(raw_severity).upper()
        severity = severity_map.get(raw_severity, "medium")

        source = f"{source_prefix}_{scan_run.pk}" if scan_run else source_prefix

        file_path = finding.get("file_path", "") or ""
        line_number = finding.get("line_number")
        metadata: Dict[str, Any] = {}
        code_snippet = (finding.get("matched") or finding.get("code_snippet", "")) or ""

        if scan_root and file_path:
            from apps.security.finding_context import (
                build_workflow_metadata,
                build_workflow_snippet,
            )

            metadata = build_workflow_metadata(scan_root, file_path, line_number)
            workflow_snippet = build_workflow_snippet(scan_root, file_path, line_number)
            if workflow_snippet:
                code_snippet = workflow_snippet

        fingerprint = build_finding_fingerprint(
            finding,
            rule_id=finding.get("rule_id", "unknown"),
            file_path=file_path,
            line_number=line_number,
        )
        title = finding.get("message", finding.get("title", "Security Finding"))[:500]
        description = finding.get("description", finding.get("recommendation", ""))
        recommendation = finding.get("remediation", finding.get("recommendation", ""))
        category = finding.get("category", "security")
        cwe = finding.get("cwe_id", "") or finding.get("cwe", "") or ""
        owasp_llm = finding.get("owasp_agentic_id", "") or finding.get("owasp_llm", "") or ""

        existing = SecurityFinding.objects.filter(
            organization=project.organization,
            project=project,
            fingerprint=fingerprint,
        ).first()
        if not existing:
            existing = SecurityFinding.objects.filter(
                organization=project.organization,
                project=project,
                rule_id=finding.get("rule_id", "unknown"),
                file_path=file_path,
                line_number=line_number,
            ).first()

        now = django_tz.now()
        if existing:
            existing.last_seen_at = now
            existing.title = title
            existing.severity = severity
            existing.category = category
            existing.description = description or existing.description
            existing.recommendation = recommendation or existing.recommendation
            existing.cwe = cwe or existing.cwe
            existing.owasp_llm = owasp_llm or existing.owasp_llm
            existing.source = source
            existing.fingerprint = fingerprint
            if code_snippet:
                existing.code_snippet = code_snippet[:1000]
            if metadata:
                merged = dict(existing.metadata) if isinstance(existing.metadata, dict) else {}
                merged.update(metadata)
                existing.metadata = merged
            if existing.status == SecurityFinding.Status.RESOLVED:
                existing.status = SecurityFinding.Status.OPEN
                existing.resolved_at = None
            existing.save()
            return existing, False

        obj = SecurityFinding.objects.create(
            organization=project.organization,
            project=project,
            rule_id=finding.get("rule_id", "unknown"),
            title=title,
            severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_number,
            description=description,
            code_snippet=code_snippet[:1000],
            cwe=cwe,
            owasp_llm=owasp_llm,
            recommendation=recommendation,
            source=source,
            status=SecurityFinding.Status.OPEN,
            metadata=metadata,
            fingerprint=fingerprint,
        )
        return obj, True

    @classmethod
    def run_comprehensive_scan(
        cls,
        project: Project,
        *,
        scan_run: Optional[ScanRun] = None,
        include_vuln_intel: bool = True,
        include_probes: bool = True,
        include_cloud_auth: bool = True,
        github_token: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Run all applicable EEG scans, probes, and cloud auth checks for a project."""
        if scan_run is None:
            scan_run = ScanRun.objects.create(
                project=project,
                scan_type=ScanRun.ScanType.FULL,
                status=ScanRun.Status.RUNNING,
                started_at=django_tz.now(),
            )

        all_findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        partial_summaries: List[Dict[str, Any]] = []
        org = project.organization

        def _cancelled_response() -> Dict[str, Any]:
            return {
                "success": False,
                "cancelled": True,
                "error": "Cancelled: project was deleted",
                "scan_run": scan_run,
                "findings": all_findings,
            }

        try:
            if should_cancel and should_cancel():
                return _cancelled_response()

            target_path = cls._resolve_project_path(project)
            has_filesystem = target_path is not None and target_path.exists()

            if has_filesystem:
                scan_opts = _scan_options_for_project(project, options)
                scan_ids = cls.get_scan_ids_for_type(
                    "full",
                    include_model=getattr(org, "model_scanning_enabled", False),
                    project=project,
                )
                results: Dict[str, ScanResult] = {}
                for sid in scan_ids or []:
                    if should_cancel and should_cancel():
                        return _cancelled_response()
                    results[sid] = run_scan(sid, target_path, options=scan_opts)

                if should_cancel and should_cancel():
                    return _cancelled_response()

                for scan_id, result in results.items():
                    if result.status == "failed" and result.errors:
                        errors.append(f"{scan_id}: {'; '.join(result.errors)}")
                    all_findings.extend(result.findings)

                partial_summaries.append({
                    "total_findings": sum(len(r.findings) for r in results.values()),
                    "by_severity": _severity_counts(all_findings),
                    "scans_executed": list(results.keys()),
                })
            elif project.project_type not in CLOUD_PROJECT_TYPES:
                errors.append(
                    "No scannable path: set local_path or repository_url on the project"
                )

            if should_cancel and should_cancel():
                return _cancelled_response()

            if include_probes:
                probe_result = ProbeService.run_project_probes(
                    project,
                    scan_run=scan_run,
                    persist=False,
                )
                if probe_result.get("findings"):
                    all_findings.extend(probe_result["findings"])
                if probe_result.get("errors"):
                    errors.extend(probe_result["errors"])
                partial_summaries.append(probe_result.get("summary", {}))

            if should_cancel and should_cancel():
                return _cancelled_response()

            if include_cloud_auth and project.project_type in CLOUD_PROJECT_TYPES:
                cloud_result = CloudAuthService.run_cloud_scan(
                    project,
                    scan_run=scan_run,
                    persist=False,
                )
                if cloud_result.get("findings"):
                    all_findings.extend(cloud_result["findings"])
                if cloud_result.get("errors"):
                    errors.extend(cloud_result["errors"])
                partial_summaries.append(cloud_result.get("summary", {}))

            if should_cancel and should_cancel():
                return _cancelled_response()

            from apps.security.finding_filters import partition_findings_by_intel_type

            code_rows, vuln_rows = partition_findings_by_intel_type(all_findings)
            seen: Set[str] = set()
            persist_stats = {"new": 0, "updated": 0, "resolved": 0}
            scan_root = str(target_path) if has_filesystem else None

            if code_rows:
                code_stats = cls._persist_findings_batch(
                    project,
                    scan_run,
                    code_rows,
                    scan_root=scan_root,
                    reconcile_scope="code",
                    seen_fingerprints=seen,
                )
                seen = code_stats["seen_fingerprints"]
                for key in persist_stats:
                    persist_stats[key] += code_stats[key]

            if include_vuln_intel and vuln_rows:
                vuln_stats = cls._persist_findings_batch(
                    project,
                    scan_run,
                    vuln_rows,
                    source_prefix="vuln_intel",
                    scan_root=scan_root,
                    reconcile_scope="vuln",
                    seen_fingerprints=seen,
                )
                for key in persist_stats:
                    persist_stats[key] += vuln_stats[key]

            by_severity = _severity_counts(all_findings)
            merged = _merge_summaries(*partial_summaries)
            merged["by_severity"] = by_severity
            merged["total_findings"] = len(all_findings)
            active_code = count_active_findings(project, scope="code")
            merged["active_vuln_findings"] = count_active_findings(
                project, scope="vuln"
            )
            merged.update({
                "detected_in_scan": len(all_findings),
                "new_findings": persist_stats["new"],
                "updated_findings": persist_stats["updated"],
                "resolved_findings": persist_stats["resolved"],
                "active_findings": active_code,
            })

            scan_run.status = ScanRun.Status.COMPLETED
            scan_run.completed_at = django_tz.now()
            scan_run.findings_count = active_code
            scan_run.critical_count = by_severity["CRITICAL"]
            scan_run.high_count = by_severity["HIGH"]
            scan_run.medium_count = by_severity["MEDIUM"]
            scan_run.low_count = by_severity["LOW"]
            scan_run.result_summary = merged
            scan_run.save()

            project.last_scan_at = django_tz.now()
            project.save(update_fields=["last_scan_at"])

            return {
                "success": len(errors) == 0 or len(all_findings) > 0,
                "scan_run": scan_run,
                "findings": all_findings,
                "summary": merged,
                "errors": errors if errors else None,
            }

        except Exception as e:
            logger.exception("Comprehensive scan failed for project %s", project.pk)
            scan_run.status = ScanRun.Status.FAILED
            scan_run.completed_at = django_tz.now()
            scan_run.error_message = str(e)
            scan_run.save()
            return {
                "success": False,
                "error": str(e),
                "scan_run": scan_run,
                "findings": all_findings,
            }


class VulnIntelService:
    """Dedicated vulnerability intelligence service using multi-source databases.
    
    Sources:
    - NVD (National Vulnerability Database) - CVE data
    - OSV (Open Source Vulnerabilities) - Unified vulnerability data
    - GHSA (GitHub Security Advisories) - GitHub-curated advisories
    """
    
    @classmethod
    def scan_dependencies(
        cls,
        project: Project,
        *,
        enable_nvd: bool = True,
        enable_ghsa: bool = True,
        github_token: Optional[str] = None,
        persist: bool = False,
        scan_run: Optional[ScanRun] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Run vulnerability intelligence scan on project dependencies.
        
        Args:
            project: Project to scan
            enable_nvd: Query NVD for CVEs
            enable_ghsa: Query GitHub Advisory Database (requires token for best results)
            github_token: GitHub token for GHSA API
            
        Returns:
            Dict with findings, summary, and package info
        """
        from eeg.vuln_manager.dependency_scan import scan_project_dependencies

        if should_cancel and should_cancel():
            return {
                "success": False,
                "cancelled": True,
                "error": "Cancelled: project was deleted",
                "findings": [],
                "ai_packages": {},
            }

        target_path = ScanningService._resolve_project_path(project)

        if not target_path or not target_path.exists():
            return {
                "success": False,
                "error": "Project path not accessible",
                "findings": [],
                "ai_packages": {},
            }

        cloud_env = _cloud_project_type(project) or "any"
        raw_findings, scan_summary = scan_project_dependencies(
            str(target_path),
            cloud_env,
            enable_nvd=enable_nvd,
            enable_ghsa=enable_ghsa,
            github_token=github_token,
            should_cancel=should_cancel,
        )
        if scan_summary.get("cancelled"):
            return {
                "success": False,
                "cancelled": True,
                "error": "Cancelled: project was deleted",
                "findings": [],
                "ai_packages": {},
                "summary": scan_summary,
            }

        errors = list(scan_summary.get("errors") or [])
        findings = [
            f.to_dict() if hasattr(f, "to_dict") else f for f in raw_findings
        ]

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = str(f.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        if persist:
            ScanningService._persist_findings_batch(
                project,
                scan_run,
                findings,
                source_prefix="vuln_intel",
                reconcile_scope="vuln",
            )

        return {
            "success": True,
            "findings": findings,
            "ai_packages": {},
            "summary": {
                "total_findings": len(findings),
                "packages_found": scan_summary.get("packages_found", 0),
                "ecosystems": scan_summary.get("ecosystems", []),
                "packages": scan_summary.get("packages", []),
                "by_severity": severity_counts,
                "sources_queried": {
                    "nvd": enable_nvd,
                    "ghsa": enable_ghsa,
                },
                "note": scan_summary.get("note"),
            },
            "errors": errors if errors else None,
        }
    
    @classmethod
    def get_ai_package_registry(cls) -> Dict[str, str]:
        """Return the AI package registry for reference."""
        from eeg.vuln_manager import AI_PACKAGE_REGISTRY
        return dict(AI_PACKAGE_REGISTRY)
    
    @classmethod
    def run_code_security_rules(
        cls,
        project: Project,
    ) -> Dict[str, Any]:
        """Run EEG code security rules (AI practice patterns).
        
        This runs the bundled YAML rule packs for detecting:
        - Hardcoded API keys
        - Prompt injection vulnerabilities  
        - MCP security issues
        - Unsafe LLM configurations
        """
        from eeg.vuln_manager import run_code_security_scan, get_code_security_rule_summary
        
        target_path = ScanningService._resolve_project_path(project)
        
        if not target_path or not target_path.exists():
            return {
                "success": False,
                "error": "Project path not accessible",
            }
        
        try:
            scan_result = run_code_security_scan(str(target_path))
            findings = scan_result.get("findings", [])
            summary = get_code_security_rule_summary()

            return {
                "success": True,
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "rule_packs": summary,
                    "by_severity": _severity_counts(findings),
                },
            }
        except Exception as e:
            logger.exception("Code security scan failed")
            return {
                "success": False,
                "error": str(e),
            }
    
    @classmethod
    def full_security_scan(
        cls,
        project: Project,
        *,
        include_vuln_intel: bool = True,
        include_code_security: bool = True,
        include_probes: bool = True,
        include_cloud_auth: bool = True,
        github_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run comprehensive security scan using all applicable EEG engine modules."""
        return ScanningService.run_comprehensive_scan(
            project,
            include_vuln_intel=include_vuln_intel,
            include_probes=include_probes,
            include_cloud_auth=include_cloud_auth,
            github_token=github_token,
        )


class ProbeService:
    """Runs EEG dynamic probes against project endpoints."""

    API_ENDPOINT_PROBES = get_probe_ids_for_api_endpoint()

    @classmethod
    def get_probes_for_project(cls, project: Project) -> List[str]:
        """Select probe IDs based on project type and org settings."""
        probes: List[str] = []

        if project.project_type == Project.ProjectType.API_ENDPOINT:
            probes.extend(get_probe_ids_for_api_endpoint())

        if project.api_endpoint and project.project_type != Project.ProjectType.API_ENDPOINT:
            probes.extend(get_probe_ids_for_api_endpoint())

        org = project.organization
        if getattr(org, "auto_redteam_enabled", False):
            if "auto_redteam" not in probes:
                probes.append("auto_redteam")

        seen: set[str] = set()
        unique: List[str] = []
        for probe_id in probes:
            if probe_id not in seen and probe_id in get_all_probes():
                seen.add(probe_id)
                unique.append(probe_id)
        return unique

    @classmethod
    def _probe_findings_from_result(
        cls,
        probe_id: str,
        result: ProbeResult,
        target: str,
    ) -> List[Dict[str, Any]]:
        """Convert probe signals into SecurityFinding-compatible dicts."""
        findings: List[Dict[str, Any]] = []

        if result.posture_state in ("critical", "at_risk"):
            findings.append({
                "rule_id": f"PROBE-{probe_id.upper()}-POSTURE",
                "severity": "HIGH" if result.posture_state == "at_risk" else "CRITICAL",
                "category": "probe",
                "file_path": target,
                "message": f"Probe {probe_id} reports posture: {result.posture_state}",
                "description": ", ".join(result.errors) if result.errors else "",
            })

        for signal in result.signals:
            sev_band = str(signal.get("severity_band", "medium")).upper()
            severity = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "INFO": "LOW",
            }.get(sev_band, "MEDIUM")

            context = signal.get("context") or {}
            blocked = context.get("blocked")
            if blocked is False or context.get("jailbroken"):
                severity = "CRITICAL"
            elif blocked is True:
                severity = "LOW"

            findings.append({
                "rule_id": f"PROBE-{probe_id.upper()}-{signal.get('signal_category', 'signal')}",
                "severity": severity,
                "category": signal.get("signal_category", "probe"),
                "file_path": target,
                "message": signal.get("pulse_summary", f"Probe signal from {probe_id}"),
                "description": str(context)[:500] if context else "",
            })

        return findings

    @classmethod
    def run_project_probes(
        cls,
        project: Project,
        *,
        probe_ids: Optional[List[str]] = None,
        scan_run: Optional[ScanRun] = None,
        persist: bool = False,
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Execute all applicable probes for a project."""
        target = ScanningService.resolve_project_target(project)
        if not target:
            return {
                "success": False,
                "error": "No api_endpoint configured for probing",
                "findings": [],
                "probe_results": {},
            }

        probe_ids = probe_ids or cls.get_probes_for_project(project)
        org = project.organization
        if not getattr(org, "auto_redteam_enabled", False):
            probe_ids = [p for p in probe_ids if p != "auto_redteam"]
        if not probe_ids:
            return {
                "success": True,
                "findings": [],
                "probe_results": {},
                "summary": {"total_findings": 0, "probes_executed": []},
            }

        all_findings: List[Dict[str, Any]] = []
        probe_results: Dict[str, Dict[str, Any]] = {}
        errors: List[str] = []

        for probe_id in probe_ids:
            opts: Dict[str, Any] = {"timeout": 30}
            if probe_id == "auto_redteam":
                use_dry = dry_run if dry_run is not None else not bool(project.api_endpoint)
                opts.update({
                    "enabled": True,
                    "dry_run": use_dry,
                    "max_probes_per_category": 5,
                })

            result = run_probe(probe_id, target, options=opts)
            probe_results[probe_id] = result.to_dict()

            if result.errors:
                errors.extend([f"{probe_id}: {e}" for e in result.errors])

            probe_findings = cls._probe_findings_from_result(probe_id, result, target)
            all_findings.extend(probe_findings)

            if persist and probe_findings:
                ScanningService._persist_findings_batch(
                    project,
                    scan_run,
                    probe_findings,
                    source_prefix=f"probe_{probe_id}",
                )

        return {
            "success": len(errors) == 0 or len(all_findings) > 0,
            "findings": all_findings,
            "probe_results": probe_results,
            "errors": errors if errors else None,
            "summary": {
                "total_findings": len(all_findings),
                "by_severity": _severity_counts(all_findings),
                "probes_executed": probe_ids,
            },
        }

    @classmethod
    def get_available_probes(cls) -> List[Dict[str, Any]]:
        """Return metadata for all registered probes."""
        return [probe_cls.get_metadata() for probe_cls in get_all_probes().values()]


class CloudAuthService:
    """Runs authenticated live cloud audits via EEG auth scanners."""

    @classmethod
    def _build_auth_context(cls, project: Project) -> Dict[str, Any]:
        cloud = project.project_type
        return {
            "profile": os.environ.get(f"{cloud.upper()}_PROFILE") or os.environ.get("AWS_PROFILE"),
            "region": os.environ.get(
                f"{cloud.upper()}_REGION",
                os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            ),
            "subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID"),
            "project_id": os.environ.get("GCP_PROJECT") or project.cloud_resource_id,
            "source": "sdk",
        }

    @classmethod
    def run_cloud_scan(
        cls,
        project: Project,
        *,
        scan_run: Optional[ScanRun] = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Run live cloud auth scanner for AWS/GCP/Azure projects."""
        from eeg.auth_scanner import get_auth_scanner
        from eeg.collector import Collector

        cloud = project.project_type
        if cloud not in ("aws", "gcp", "azure"):
            return {
                "success": False,
                "error": f"Not a cloud project type: {cloud}",
                "findings": [],
            }

        scanner = get_auth_scanner(cloud, cls._build_auth_context(project))
        if scanner is None:
            return {
                "success": False,
                "error": f"No auth scanner for cloud: {cloud}",
                "findings": [],
            }

        collector = Collector()
        errors: List[str] = []

        try:
            scanner.scan(collector)
        except Exception as e:
            logger.exception("Cloud auth scan failed for %s", project.pk)
            errors.append(str(e))

        data = collector.to_dict()
        findings = data.get("findings", [])

        if persist and findings:
            ScanningService._persist_findings_batch(
                project,
                scan_run,
                findings,
                source_prefix=f"cloud_{cloud}",
                reconcile_scope="all",
            )

        return {
            "success": len(errors) == 0,
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "by_severity": _severity_counts(findings),
                "scans_executed": [f"cloud_auth_{cloud}"],
            },
            "errors": errors if errors else None,
        }


def organization_scan_in_progress(organization) -> bool:
    """True while any project in the org has a scan RUNNING or QUEUED."""
    if not organization:
        return False
    return ScanRun.objects.filter(
        project__organization=organization,
        status__in=(ScanRun.Status.RUNNING, ScanRun.Status.QUEUED),
    ).exists()
