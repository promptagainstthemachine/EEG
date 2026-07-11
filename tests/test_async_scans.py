"""Background scan queue returns immediately."""

from unittest.mock import patch

from django.test import TestCase

from apps.accounts.models import Organization
from apps.api.operations import refresh_threat_intel, run_project_scan
from apps.projects.models import Project, ScanRun
from apps.security.scan_cancellation import clear_all_cancellations


class AsyncScanOperationsTests(TestCase):
    def setUp(self):
        clear_all_cancellations()
        self.org = Organization.objects.create(name="Async Org", slug="async-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
            local_path="/tmp/app",
        )

    @patch("apps.security.scan_workers.run_in_background")
    def test_run_project_scan_returns_scan_run_id(self, mock_bg):
        result = run_project_scan(self.org, self.project.pk, "code")
        self.assertTrue(result["success"])
        self.assertTrue(result["async"])
        self.assertIsNotNone(result["scan_run_id"])
        mock_bg.assert_called_once()
        self.assertEqual(
            ScanRun.objects.filter(project=self.project).count(),
            1,
        )

    @patch("apps.security.scan_workers.run_in_background")
    def test_refresh_threat_intel_queues_dependency_scan(self, mock_bg):
        result = refresh_threat_intel(self.org, self.project.pk)
        self.assertTrue(result["success"])
        self.assertTrue(result["async"])
        scan_run = ScanRun.objects.get(pk=result["scan_run_id"])
        self.assertEqual(scan_run.scan_type, ScanRun.ScanType.DEPENDENCY)
        self.assertEqual(scan_run.status, ScanRun.Status.QUEUED)
        mock_bg.assert_called_once()
