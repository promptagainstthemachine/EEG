"""User activity log model and endpoints."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import ApiKey, Organization, UserActivityLog

User = get_user_model()


class UserActivityLogTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.user = User.objects.create_user(username="owner", password="x")
        self.user.organization = self.org
        self.user.save()

    def test_log_created_and_listed(self):
        UserActivityLog.objects.create(
            user=self.user,
            organization=self.org,
            event_type=UserActivityLog.EventType.PROJECT_CREATED,
            actor_username="owner",
            metadata={"project_name": "p1", "project_id": 1},
        )
        self.assertEqual(UserActivityLog.objects.filter(user=self.user).count(), 1)

    def test_download_requires_login(self):
        r = self.client.get(reverse("accounts:activity_logs_download"))
        self.assertEqual(r.status_code, 302)

    def test_download_and_clear(self):
        UserActivityLog.objects.create(
            user=self.user,
            organization=self.org,
            event_type=UserActivityLog.EventType.USER_LOGIN,
            actor_username="owner",
            metadata={},
        )
        self.client.force_login(self.user)
        r = self.client.get(reverse("accounts:activity_logs_download"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("user_login", r.content.decode())
        r = self.client.post(reverse("accounts:activity_logs_clear"))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(UserActivityLog.objects.filter(user=self.user).count(), 0)

    def test_api_key_create_and_revoke_write_activity_log(self):
        self.client.force_login(self.user)
        r = self.client.post(
            reverse("accounts:create_api_key"),
            {"label": "CI token"},
        )
        self.assertEqual(r.status_code, 302)
        log_create = UserActivityLog.objects.filter(
            user=self.user,
            event_type=UserActivityLog.EventType.API_KEY_CREATED,
        ).first()
        self.assertIsNotNone(log_create)
        self.assertEqual(log_create.metadata.get("label"), "CI token")
        key_id = log_create.metadata.get("api_key_id")
        self.assertIsNotNone(key_id)
        key = ApiKey.objects.get(pk=key_id)
        self.assertTrue(key.is_active)

        r2 = self.client.post(reverse("accounts:revoke_api_key", args=[key.pk]))
        self.assertEqual(r2.status_code, 302)
        log_revoke = UserActivityLog.objects.filter(
            user=self.user,
            event_type=UserActivityLog.EventType.API_KEY_REVOKED,
        ).first()
        self.assertIsNotNone(log_revoke)
        self.assertEqual(log_revoke.metadata.get("api_key_id"), key.pk)
        self.assertEqual(log_revoke.metadata.get("label"), "CI token")
        key.refresh_from_db()
        self.assertFalse(key.is_active)
