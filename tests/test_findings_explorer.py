"""Findings explorer filter validation."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import Organization
from apps.projects.models import Project

User = get_user_model()


class FindingsExplorerFilterTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme-fe")
        self.user = User.objects.create_user(username="fe-user", password="x")
        self.user.organization = self.org
        self.user.save()
        self.project = Project.objects.create(
            organization=self.org,
            name="Demo",
            slug="demo-fe",
        )
        self.client.force_login(self.user)
        self.url = reverse("ui:findings_explorer")

    def test_empty_filter_submit_redirects_to_clean_url(self):
        r = self.client.get(self.url, {"severity": "", "status": "", "project": ""})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r["Location"], self.url)

    def test_invalid_project_param_does_not_500(self):
        r = self.client.get(self.url, {"project": "'"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r["Location"], self.url)

    def test_valid_project_filter_applies(self):
        r = self.client.get(self.url, {"project": str(self.project.pk)})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Demo")
