"""Dashboard findings timeline aggregation."""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.finding_dedup import build_finding_fingerprint
from apps.security.models import SecurityFinding
from apps.ui.timeline import build_findings_timeline


class DashboardTimelineTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Timeline Org", slug="timeline-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Demo",
            slug="demo",
        )

    def _finding(self, **kwargs):
        data = {
            "organization": self.org,
            "project": self.project,
            "rule_id": "TEST.RULE",
            "title": "Test finding",
            "severity": "high",
            "status": SecurityFinding.Status.OPEN,
            "category": "test",
        }
        data.update(kwargs)
        data.setdefault("fingerprint", build_finding_fingerprint(data))
        return SecurityFinding.objects.create(**data)

    def test_timeline_counts_today_activity(self):
        now = timezone.now()
        finding = self._finding()
        SecurityFinding.objects.filter(pk=finding.pk).update(
            first_seen_at=now,
            last_seen_at=now,
        )

        data = build_findings_timeline(self.org, days=7)
        self.assertTrue(data["has_data"])
        self.assertEqual(len(data["labels"]), 7)
        self.assertEqual(data["critical_high"][-1], 1)
        self.assertGreaterEqual(sum(data["critical_high"]), 1)

    def test_timeline_shows_open_backlog_without_recent_touch(self):
        old = timezone.now() - timedelta(days=20)
        finding = self._finding()
        SecurityFinding.objects.filter(pk=finding.pk).update(
            first_seen_at=old,
            last_seen_at=old,
        )

        data = build_findings_timeline(self.org, days=7)
        self.assertTrue(data["has_data"])
        self.assertEqual(data["open_total"], 1)
        self.assertTrue(all(v >= 1 for v in data["critical_high"]))

    def test_timeline_excludes_resolved_from_current_backlog(self):
        now = timezone.now()
        finding = self._finding(status=SecurityFinding.Status.RESOLVED, resolved_at=now)
        SecurityFinding.objects.filter(pk=finding.pk).update(
            first_seen_at=now,
            resolved_at=now,
        )

        data = build_findings_timeline(self.org, days=7)
        self.assertFalse(data["has_data"])
        self.assertEqual(data["open_total"], 0)
