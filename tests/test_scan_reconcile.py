"""Orphaned scan reconciliation on startup."""

from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import Organization
from apps.projects.models import Project, ScanRun
from apps.security.scan_reconcile import reconcile_orphaned_scan_runs


class ScanReconcileTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="R Org", slug="r-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
        )

    def test_reconcile_marks_queued_and_running_failed(self):
        queued = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.DEPENDENCY,
            status=ScanRun.Status.QUEUED,
        )
        running = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.FULL,
            status=ScanRun.Status.RUNNING,
            started_at=timezone.now(),
        )
        completed = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.CODE_SECURITY,
            status=ScanRun.Status.COMPLETED,
            completed_at=timezone.now(),
        )

        count = reconcile_orphaned_scan_runs()
        self.assertEqual(count, 2)

        queued.refresh_from_db()
        running.refresh_from_db()
        completed.refresh_from_db()
        self.assertEqual(queued.status, ScanRun.Status.FAILED)
        self.assertEqual(running.status, ScanRun.Status.FAILED)
        self.assertEqual(completed.status, ScanRun.Status.COMPLETED)
        self.assertIn("restarted", queued.error_message.lower())
