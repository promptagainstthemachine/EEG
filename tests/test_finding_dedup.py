"""Tests for cross-scan finding deduplication."""

from __future__ import annotations

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project, ScanRun
from apps.security.finding_dedup import build_finding_fingerprint, count_active_findings
from apps.security.models import SecurityFinding
from apps.security.services import ScanningService


class FindingDedupTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Dedup Org", slug="dedup-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="bedrock",
            slug="bedrock",
        )
        self.scan_run = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.FULL,
            status=ScanRun.Status.RUNNING,
        )
        self.finding_dict = {
            "rule_id": "AGENT-001",
            "severity": "CRITICAL",
            "category": "command_injection",
            "file_path": "code/lambdas/handler.py",
            "line_number": 57,
            "message": "Command Injection",
            "matched": "exec",
        }

    def test_same_finding_not_duplicated_on_rescan(self):
        stats1 = ScanningService._persist_findings_batch(
            self.project,
            self.scan_run,
            [self.finding_dict],
            reconcile_scope="code",
        )
        self.assertEqual(stats1["new"], 1)
        self.assertEqual(SecurityFinding.objects.filter(project=self.project).count(), 1)

        stats2 = ScanningService._persist_findings_batch(
            self.project,
            self.scan_run,
            [self.finding_dict],
            reconcile_scope="code",
        )
        self.assertEqual(stats2["new"], 0)
        self.assertEqual(stats2["updated"], 1)
        self.assertEqual(SecurityFinding.objects.filter(project=self.project).count(), 1)
        self.assertEqual(count_active_findings(self.project, scope="code"), 1)

    def test_resolved_when_missing_from_scan(self):
        ScanningService._persist_findings_batch(
            self.project,
            self.scan_run,
            [self.finding_dict],
            reconcile_scope="code",
        )
        stats = ScanningService._persist_findings_batch(
            self.project,
            self.scan_run,
            [],
            reconcile_scope="code",
        )
        self.assertEqual(stats["resolved"], 1)
        self.assertEqual(count_active_findings(self.project, scope="code"), 0)
        finding = SecurityFinding.objects.get(project=self.project)
        self.assertEqual(finding.status, SecurityFinding.Status.RESOLVED)

    def test_fingerprint_stable(self):
        fp1 = build_finding_fingerprint(self.finding_dict)
        fp2 = build_finding_fingerprint(self.finding_dict)
        self.assertEqual(fp1, fp2)
