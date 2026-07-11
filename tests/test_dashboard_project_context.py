"""Dashboard active project selection and scoping."""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.finding_dedup import build_finding_fingerprint
from apps.security.models import SecurityFinding

User = get_user_model()


class DashboardProjectContextTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Ctx Org", slug="ctx-org")
        self.user = User.objects.create_user(
            username="dashuser",
            email="dash@example.com",
            password="testpass123",
            organization=self.org,
        )
        self.project_a = Project.objects.create(
            organization=self.org,
            name="Alpha",
            slug="alpha",
        )
        self.project_b = Project.objects.create(
            organization=self.org,
            name="Beta",
            slug="beta",
        )
        self.client.login(username="dashuser", password="testpass123")

    def _finding(self, project, severity="critical"):
        data = {
            "organization": self.org,
            "project": project,
            "rule_id": f"RULE.{project.slug}",
            "title": "Finding",
            "severity": severity,
            "status": SecurityFinding.Status.OPEN,
            "category": "test",
        }
        data["fingerprint"] = build_finding_fingerprint(data)
        return SecurityFinding.objects.create(**data)

    def test_select_project_persists_on_user(self):
        url = reverse("ui:dashboard") + f"?project={self.project_a.pk}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.dashboard_project_id, self.project_a.pk)

    def test_dashboard_scopes_metrics_to_active_project(self):
        self._finding(self.project_a, severity="critical")
        self._finding(self.project_b, severity="high")

        self.user.dashboard_project = self.project_a
        self.user.save(update_fields=["dashboard_project_id"])

        response = self.client.get(reverse("ui:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["active_project"].name, "Alpha")
        self.assertContains(response, "severityPie")
        self.assertContains(response, "scanBar")
        self.assertEqual(response.context["critical_count"], 1)
        self.assertEqual(response.context["high_count"], 0)

    def test_switching_project_resets_dashboard_context(self):
        self._finding(self.project_a, severity="critical")
        self._finding(self.project_b, severity="high")

        self.client.get(reverse("ui:dashboard") + f"?project={self.project_a.pk}")
        response = self.client.get(
            reverse("ui:dashboard") + f"?project={self.project_b.pk}"
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.dashboard_project_id, self.project_b.pk)
        self.assertEqual(response.context["critical_count"], 0)
        self.assertEqual(response.context["high_count"], 1)

    def test_persisted_project_survives_fresh_request(self):
        self.user.dashboard_project = self.project_b
        self.user.save(update_fields=["dashboard_project_id"])

        response = self.client.get(reverse("ui:dashboard"))
        self.assertEqual(response.context["active_project"].pk, self.project_b.pk)

    def test_set_dashboard_project_post(self):
        response = self.client.post(
            reverse("ui:set_dashboard_project"),
            {"project_id": self.project_a.pk},
        )
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.dashboard_project_id, self.project_a.pk)
        self.assertIn("projects", response.url)
        self.assertIn(f"project={self.project_a.pk}", response.url)
