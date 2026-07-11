"""Cancelling scans when a project is deleted."""

from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import Organization, User
from apps.projects.models import Project, ScanRun
from apps.security.scan_cancellation import (
    clear_all_cancellations,
    is_scan_cancelled,
)
from apps.security.scan_workers import cancel_scans_for_project, execute_scan_run


class ScanCancellationTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Del Org", slug="del-org")
        self.user = User.objects.create_user(
            username="deluser",
            email="del@example.com",
            password="pass",
            organization=self.org,
        )
        self.project = Project.objects.create(
            organization=self.org,
            name="to-delete",
            slug="to-delete",
            local_path="/tmp/to-delete",
        )

    def tearDown(self):
        clear_all_cancellations()

    def test_cancel_marks_active_scan_runs(self):
        scan = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.DEPENDENCY,
            status=ScanRun.Status.RUNNING,
            started_at=timezone.now(),
        )
        count = cancel_scans_for_project(self.project.pk)
        self.assertEqual(count, 1)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanRun.Status.FAILED)
        self.assertIn("deleted", scan.error_message.lower())
        self.assertTrue(is_scan_cancelled(project_id=self.project.pk))

    @patch("apps.security.scan_workers.run_in_background")
    def test_delete_project_cancels_via_signal(self, mock_bg):
        scan = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.DEPENDENCY,
            status=ScanRun.Status.QUEUED,
        )
        self.project.delete()
        scan_run_still_exists = ScanRun.objects.filter(pk=scan.pk).exists()
        self.assertFalse(scan_run_still_exists)
        mock_bg.assert_not_called()

    @patch("apps.security.services.VulnIntelService.scan_dependencies")
    def test_execute_scan_run_stops_when_cancelled(self, mock_scan):
        scan = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.DEPENDENCY,
            status=ScanRun.Status.QUEUED,
        )
        cancel_scans_for_project(self.project.pk)
        execute_scan_run(scan.pk, "vuln_intel", {})
        mock_scan.assert_not_called()
        if ScanRun.objects.filter(pk=scan.pk).exists():
            scan.refresh_from_db()
            self.assertEqual(scan.status, ScanRun.Status.FAILED)
            self.assertIn("deleted", scan.error_message.lower())
