"""Threat Intel refresh queues background CVE fetch."""

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import Organization, User
from apps.projects.models import Project, ScanRun


class ThreatIntelRefreshTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="TI Org", slug="ti-org")
        self.user = User.objects.create_user(
            username="tiuser",
            email="ti@example.com",
            password="pass",
            organization=self.org,
        )
        self.project = Project.objects.create(
            organization=self.org,
            name="vuln-agent",
            slug="vuln-agent",
            local_path="/tmp/vuln-agent",
        )
        self.user.dashboard_project = self.project
        self.user.save(update_fields=["dashboard_project_id"])
        self.client.force_login(self.user)

    @patch("apps.security.scan_workers.enqueue_project_scan")
    def test_refresh_post_queues_scan_and_returns_poll(self, mock_enqueue):
        def _enqueue(project, scan_type, **kwargs):
            return ScanRun.objects.create(
                project=project,
                scan_type=ScanRun.ScanType.DEPENDENCY,
                status=ScanRun.Status.QUEUED,
            )

        mock_enqueue.side_effect = _enqueue

        response = self.client.post(
            reverse("ui:refresh_threat_intel") + f"?project={self.project.pk}"
        )
        self.assertEqual(response.status_code, 200)
        mock_enqueue.assert_called_once_with(self.project, "vuln_intel")
        self.assertContains(response, "threat-intel-refresh-poll")
        self.assertContains(response, "Fetching CVE")

    @patch("apps.security.scan_workers.enqueue_project_scan")
    def test_refresh_requires_active_project(self, mock_enqueue):
        self.user.dashboard_project = None
        self.user.save(update_fields=["dashboard_project_id"])

        response = self.client.post(reverse("ui:refresh_threat_intel"))
        self.assertEqual(response.status_code, 200)
        mock_enqueue.assert_not_called()
        self.assertContains(response, "Select a project")

    @patch("apps.security.scan_workers.execute_scan_run")
    def test_status_poll_returns_feed_when_complete(self, mock_execute):
        scan_run = ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.DEPENDENCY,
            status=ScanRun.Status.COMPLETED,
            findings_count=2,
            result_summary={
                "total_findings": 2,
                "packages_found": 3,
                "note": "",
            },
        )

        response = self.client.get(
            reverse("ui:threat_intel_scan_status")
            + f"?scan_run={scan_run.pk}&project={self.project.pk}"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Refreshed")
        mock_execute.assert_not_called()
