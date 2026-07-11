"""Scan-in-progress detection for dashboard banner."""

from django.utils import timezone

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project, ScanRun
from apps.security.services import organization_scan_in_progress


class OrganizationScanProgressTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
        )

    def test_running_scan_run_implies_in_progress(self):
        self.assertFalse(organization_scan_in_progress(self.org))
        ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.CODE_SECURITY,
            status=ScanRun.Status.RUNNING,
            started_at=timezone.now(),
        )
        self.assertTrue(organization_scan_in_progress(self.org))
