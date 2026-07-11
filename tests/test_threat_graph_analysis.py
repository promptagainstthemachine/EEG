"""Tests for vulnerability graph analysis heuristics."""

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.models import SecurityFinding
from apps.security.threat_graph_analysis import (
    FindingGraphIndexes,
    assess_fp_risk,
    is_test_surface_path,
    snippet_signature,
)


class ThreatGraphAnalysisTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
        )

    def test_test_surface_detection(self):
        self.assertTrue(is_test_surface_path("tests/unit/test_auth.py"))
        self.assertFalse(is_test_surface_path("src/auth.py"))

    def test_fp_risk_higher_in_tests(self):
        finding = SecurityFinding(
            organization=self.org,
            project=self.project,
            rule_id="EEG-SEM-001",
            file_path="tests/test_api.py",
            severity="low",
            code_snippet="",
        )
        score, signals = assess_fp_risk(finding)
        self.assertGreaterEqual(score, 50)
        self.assertIn("test_surface", signals)

    def test_same_line_index(self):
        f1 = SecurityFinding.objects.create(
            organization=self.org,
            project=self.project,
            rule_id="R1",
            file_path="src/a.py",
            line_number=10,
            status=SecurityFinding.Status.OPEN,
            fingerprint="a",
        )
        f2 = SecurityFinding.objects.create(
            organization=self.org,
            project=self.project,
            rule_id="R2",
            file_path="src/a.py",
            line_number=10,
            status=SecurityFinding.Status.OPEN,
            fingerprint="b",
        )
        indexes = FindingGraphIndexes([f1, f2])
        self.assertEqual(indexes.rules_at_line(f1), 2)
        sig = snippet_signature("eval(user_input)")
        self.assertEqual(sig, snippet_signature("  eval(user_input)  "))
