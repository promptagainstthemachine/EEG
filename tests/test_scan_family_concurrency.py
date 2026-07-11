"""Full scan and CVE refresh can run concurrently on the same project."""

import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from apps.accounts.models import ApiKey, Organization
from apps.api.operations import refresh_threat_intel, run_project_scan
from apps.projects.models import Project, ScanRun

User = get_user_model()


class ScanFamilyConcurrencyTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
            local_path="/tmp/app",
        )
        ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.DEPENDENCY,
            status=ScanRun.Status.RUNNING,
            started_at=timezone.now(),
        )

    @patch("apps.security.scan_workers.run_in_background")
    def test_full_scan_allowed_during_cve_refresh(self, mock_bg):
        result = run_project_scan(self.org, self.project.pk, "full")
        self.assertTrue(result["success"])
        self.assertTrue(result["async"])
        mock_bg.assert_called_once()

    @patch("apps.security.scan_workers.run_in_background")
    def test_cve_refresh_blocked_when_cve_already_running(self, mock_bg):
        result = refresh_threat_intel(self.org, self.project.pk)
        self.assertFalse(result["success"])
        self.assertEqual(result.get("code"), "scan_in_progress")
        mock_bg.assert_not_called()

    @patch("apps.security.scan_workers.run_in_background")
    def test_api_full_scan_202_during_dependency_scan(self, mock_bg):
        api_key, raw_key = ApiKey.create_key(self.org, "test")
        client = Client()
        res = client.post(
            "/api/v1/scan/",
            data=json.dumps({"project_id": self.project.pk, "scan_type": "full"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {raw_key}",
        )
        self.assertEqual(res.status_code, 202)
        self.assertTrue(res.json().get("async"))
        mock_bg.assert_called_once()
