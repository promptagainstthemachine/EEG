"""Tests for vulnerability graph builder."""

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.models import SecurityFinding
from apps.security.threat_graph import build_vulnerability_graph


class ThreatGraphTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
        )

    def test_build_vulnerability_graph_links_findings(self):
        finding = SecurityFinding.objects.create(
            organization=self.org,
            project=self.project,
            rule_id="SECRET-001",
            title="Hardcoded API key",
            severity="high",
            category="secrets",
            file_path="src/config.py",
            status=SecurityFinding.Status.OPEN,
            fingerprint="fp1",
        )

        data = build_vulnerability_graph(self.org, limit=10)
        node_ids = {n["id"] for n in data["nodes"]}

        self.assertIn(f"finding:{finding.pk}", node_ids)
        self.assertIn("bucket:secrets", node_ids)
        self.assertIn("file:src/config.py", node_ids)
        self.assertIn(f"project:{self.project.pk}", node_ids)
        self.assertTrue(any(n["group"] == "hub" for n in data["nodes"]))
        self.assertTrue(any(n["group"] == "severity" for n in data["nodes"]))
        self.assertEqual(data["meta"]["finding_count"], 1)
        self.assertGreaterEqual(len(data["links"]), 5)
        link_types = {lnk["type"] for lnk in data["links"]}
        self.assertIn("file", link_types)
        self.assertIn("rule", link_types)

        finding_node = next(n for n in data["nodes"] if n["id"] == f"finding:{finding.pk}")
        self.assertIn("fp_score", finding_node)
        self.assertIn("fp_signals", finding_node)

    def test_only_eeg_bucket_nodes_no_auxiliary_taxonomy(self):
        """Graph uses THREAT_BUCKETS only, not raw category / CWE / OWASP nodes."""
        finding = SecurityFinding.objects.create(
            organization=self.org,
            project=self.project,
            rule_id="SECRET-001",
            title="Hardcoded API key",
            severity="high",
            category="secrets",
            file_path="src/config.py",
            status=SecurityFinding.Status.OPEN,
            fingerprint="fp-tax",
            cwe="79",
            owasp_llm="LLM01",
        )
        data = build_vulnerability_graph(self.org, limit=10)
        groups = {n["group"] for n in data["nodes"]}
        self.assertNotIn("category", groups)
        self.assertNotIn("cwe", groups)
        self.assertNotIn("owasp", groups)
        self.assertIn("bucket", groups)

    def test_no_bucket_nodes_without_findings(self):
        data = build_vulnerability_graph(self.org, limit=10)
        self.assertEqual(data["meta"]["finding_count"], 0)
        self.assertFalse(any(n["group"] == "bucket" for n in data["nodes"]))

    def test_same_line_links_for_collocated_findings(self):
        f1 = SecurityFinding.objects.create(
            organization=self.org,
            project=self.project,
            rule_id="R-A",
            file_path="src/x.py",
            line_number=5,
            code_snippet="eval(x)",
            status=SecurityFinding.Status.OPEN,
            fingerprint="fp-a",
        )
        f2 = SecurityFinding.objects.create(
            organization=self.org,
            project=self.project,
            rule_id="R-B",
            file_path="src/x.py",
            line_number=5,
            code_snippet="eval(x)",
            status=SecurityFinding.Status.OPEN,
            fingerprint="fp-b",
        )
        data = build_vulnerability_graph(self.org, limit=10)
        link_types = {lnk["type"] for lnk in data["links"]}
        self.assertIn("same_line", link_types)
        self.assertIn("snippet_match", link_types)
