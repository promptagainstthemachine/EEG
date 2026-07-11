"""Threat intel feed: NVD/GHSA rows; no placeholder CVEs; excludes legacy OSV."""

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.models import SecurityFinding
from apps.ui.views import build_vulnerability_intel_entries


class ThreatIntelFeedTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", slug="test-org")

    def test_empty_when_no_projects_even_if_orphan_categories_exist(self):
        SecurityFinding.objects.create(
            organization=self.org,
            project=None,
            rule_id="CVE-2024-3094",
            title="Should not appear without projects",
            category="cve",
            severity="critical",
            status=SecurityFinding.Status.OPEN,
            fingerprint="orphan-cve",
        )
        self.assertEqual(build_vulnerability_intel_entries(self.org), [])

    def test_returns_rows_only_for_project_scoped_findings(self):
        project = Project.objects.create(organization=self.org, name="app", slug="app")
        SecurityFinding.objects.create(
            organization=self.org,
            project=project,
            rule_id="CVE-2024-9999",
            title="scoped",
            category="cve",
            severity="high",
            status=SecurityFinding.Status.OPEN,
            fingerprint="p1",
        )
        entries = build_vulnerability_intel_entries(self.org)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], "CVE-2024-9999")

    def test_includes_vulnerability_management_category(self):
        project = Project.objects.create(
            organization=self.org, name="ml-app", slug="ml-app"
        )
        SecurityFinding.objects.create(
            organization=self.org,
            project=project,
            rule_id="CVE-2024-1234",
            title="OpenSSL in torch",
            category="vulnerability_management",
            severity="high",
            file_path="dependency:torch==2.0.0",
            status=SecurityFinding.Status.OPEN,
            fingerprint="vm1",
            source="vuln_intel_99",
        )
        entries = build_vulnerability_intel_entries(self.org)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["package"], "torch==2.0.0")

    def test_excludes_resolved_vuln_rows(self):
        project = Project.objects.create(
            organization=self.org, name="old", slug="old"
        )
        SecurityFinding.objects.create(
            organization=self.org,
            project=project,
            rule_id="CVE-2020-0001",
            title="resolved",
            category="vulnerability_management",
            severity="medium",
            status=SecurityFinding.Status.RESOLVED,
            fingerprint="resolved1",
        )
        self.assertEqual(build_vulnerability_intel_entries(self.org), [])

    def test_excludes_legacy_osv_rows(self):
        project = Project.objects.create(
            organization=self.org, name="web", slug="web"
        )
        SecurityFinding.objects.create(
            organization=self.org,
            project=project,
            rule_id="OSV-GHSA-rv95-896h-c2vc",
            title="express advisory",
            category="vulnerability_management",
            severity="medium",
            file_path="dependency:express==4.18.2",
            status=SecurityFinding.Status.OPEN,
            fingerprint="express1",
        )
        SecurityFinding.objects.create(
            organization=self.org,
            project=project,
            rule_id="GHSA-xxxx-yyyy-zzzz",
            title="ai sdk advisory",
            category="vulnerability_management",
            severity="high",
            file_path="dependency:@ai-sdk/openai==*",
            status=SecurityFinding.Status.OPEN,
            fingerprint="ghsa1",
        )
        entries = build_vulnerability_intel_entries(self.org)
        self.assertEqual(len(entries), 1)
        self.assertIn("GHSA", entries[0]["id"])

    def test_includes_non_ai_packages(self):
        project = Project.objects.create(
            organization=self.org, name="node", slug="node"
        )
        SecurityFinding.objects.create(
            organization=self.org,
            project=project,
            rule_id="CVE-2024-5555",
            title="commander CVE",
            category="vulnerability_management",
            severity="high",
            file_path="dependency:commander==14.0.0",
            status=SecurityFinding.Status.OPEN,
            fingerprint="cmd1",
        )
        entries = build_vulnerability_intel_entries(self.org)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["source"], "NVD")

    def test_no_placeholder_demo_entries(self):
        project = Project.objects.create(organization=self.org, name="app2", slug="app2")
        entries = build_vulnerability_intel_entries(self.org)
        self.assertEqual(entries, [])
        ids = {e["id"] for e in entries}
        self.assertNotIn("CVE-2024-3094", ids)
