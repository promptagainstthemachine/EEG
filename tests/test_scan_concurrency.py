"""Per-project scan concurrency (API + operations)."""

import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from apps.accounts.models import ApiKey, Organization
from apps.projects.models import Project, ScanRun

User = get_user_model()


class ScanConcurrencyTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.user = User.objects.create_user(username="apiu", password="secret")
        self.user.organization = self.org
        self.user.save()
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
        )
        self.api_key, self.raw_key = ApiKey.create_key(self.org, "test")

    def test_post_scan_returns_409_when_project_already_scanning(self):
        ScanRun.objects.create(
            project=self.project,
            scan_type=ScanRun.ScanType.CODE_SECURITY,
            status=ScanRun.Status.RUNNING,
            started_at=timezone.now(),
        )
        client = Client()
        res = client.post(
            "/api/v1/scan/",
            data=json.dumps({"project_id": self.project.pk, "scan_type": "code"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_key}",
        )
        self.assertEqual(res.status_code, 409)
        body = res.json()
        self.assertEqual(body.get("code"), "scan_in_progress")
