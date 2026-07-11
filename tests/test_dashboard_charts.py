"""Dashboard chart data builders."""

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.finding_dedup import build_finding_fingerprint
from apps.security.models import SecurityFinding
from apps.projects.models import ScanRun
from apps.ui.dashboard_charts import (
    build_category_distribution,
    build_scan_distribution,
    build_severity_distribution,
    build_threat_radar,
)
from apps.ui.views import open_code_findings_qs


class DashboardChartTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Chart Org", slug="chart-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Demo",
            slug="demo",
        )

    def _finding(self, **kwargs):
        data = {
            "organization": self.org,
            "project": self.project,
            "rule_id": "TEST.RULE",
            "title": "Test finding",
            "severity": "high",
            "status": SecurityFinding.Status.OPEN,
            "category": "command_injection",
        }
        data.update(kwargs)
        data.setdefault("fingerprint", build_finding_fingerprint(data))
        return SecurityFinding.objects.create(**data)

    def test_severity_distribution_includes_info(self):
        self._finding(severity="critical")
        self._finding(severity="info", rule_id="TEST.INFO", file_path="b.py", line_number=2)

        qs = open_code_findings_qs(self.org)
        data = build_severity_distribution(qs)

        self.assertTrue(data["has_data"])
        self.assertEqual(data["total"], 2)
        self.assertIn("Info", data["labels"])
        self.assertIn("Critical", data["labels"])

    def test_category_distribution_uses_threat_buckets(self):
        self._finding(category="command_injection", severity="critical")
        self._finding(
            category="prompt_injection",
            severity="high",
            rule_id="TEST.PROMPT",
            file_path="c.py",
            line_number=3,
        )

        data = build_category_distribution(open_code_findings_qs(self.org))
        self.assertTrue(data["has_data"])
        self.assertEqual(data["total"], 2)
        self.assertIn("Command Injection", data["labels"])
        self.assertIn("Prompt Injection", data["labels"])

    def test_scan_distribution_groups_by_type(self):
        ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.FULL,
            status=ScanRun.Status.COMPLETED,
        )
        ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.FULL,
            status=ScanRun.Status.COMPLETED,
        )
        ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.CODE_SECURITY,
            status=ScanRun.Status.FAILED,
        )
        qs = ScanRun.objects.filter(project=self.project)
        data = build_scan_distribution(qs)
        self.assertTrue(data["has_data"])
        self.assertEqual(data["total"], 3)
        self.assertIn("Full Scan", data["labels"])

    def test_threat_radar_includes_all_buckets(self):
        self._finding(category="prompt_injection", severity="high")
        self._finding(
            category="secrets",
            severity="medium",
            rule_id="TEST.SECRET",
            file_path="d.py",
            line_number=4,
        )

        data = build_threat_radar(open_code_findings_qs(self.org))
        self.assertTrue(data["has_data"])
        self.assertEqual(len(data["labels"]), 6)
        self.assertEqual(len(data["values"]), 6)
        self.assertIn("Agent Control", data["labels"])
        self.assertGreaterEqual(data["scale_max"], data["values"][0])

    def test_runtime_agent_control_maps_to_bucket(self):
        from apps.ui.dashboard_charts import (
            build_category_distribution_from_counts,
            build_threat_radar_from_counts,
            count_runtime_buckets,
            runtime_threat_bucket,
        )

        row = {
            "title": "Runtime Agent control: start",
            "category": "runtime_agent_control",
            "rule_id": "runtime.agent_control",
            "trace_type": "agent_control",
            "source": "runtime",
            "severity": "low",
            "metadata": {},
        }
        self.assertEqual(runtime_threat_bucket(row), "agent_control")
        buckets = count_runtime_buckets([row])
        self.assertEqual(buckets["agent_control"], 1)
        category = build_category_distribution_from_counts(buckets)
        self.assertTrue(category["has_data"])
        self.assertIn("Agent Control", category["labels"])
        radar = build_threat_radar_from_counts(buckets)
        self.assertTrue(radar["has_data"])
        self.assertIn("Agent Control", radar["labels"])
        self.assertGreater(radar["values"][radar["keys"].index("agent_control")], 0)
