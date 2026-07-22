"""Project-scoped dashboard, cascade delete, and runtime ingest attach."""

from datetime import datetime, timezone

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.accounts.models import Organization
from apps.projects.models import Project, ScanRun
from apps.security.finding_dedup import build_finding_fingerprint
from apps.security.models import AITrace, ManagedAgent, SecurityFinding
from apps.security.runtime_findings import list_runtime_finding_dicts
from apps.security.trace_ingest import ingest_traces

User = get_user_model()


class ProjectScopedFindingsTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Scope Org", slug="scope-org")
        self.user = User.objects.create_user(
            username="scopeuser",
            email="scope@example.com",
            password="testpass123",
            organization=self.org,
        )
        self.static = Project.objects.create(
            organization=self.org,
            name="Static App",
            slug="static-app",
            project_type=Project.ProjectType.LOCAL,
        )
        self.gateway = Project.objects.create(
            organization=self.org,
            name="Gateway App",
            slug="gateway-app",
            project_type=Project.ProjectType.GATEWAY,
            gateway_agent_key="agent-goat",
        )
        self.client.login(username="scopeuser", password="testpass123")

    def _finding(self, project, severity="critical", title="Finding"):
        data = {
            "organization": self.org,
            "project": project,
            "rule_id": f"RULE.{project.slug}.{severity}",
            "title": title,
            "severity": severity,
            "status": SecurityFinding.Status.OPEN,
            "category": "secrets" if severity == "critical" else "test",
        }
        data["fingerprint"] = build_finding_fingerprint(data)
        return SecurityFinding.objects.create(**data)

    def _trace(self, *, project=None, agent_key="", risk=0.9, status="blocked"):
        started = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
        return AITrace.objects.create(
            organization=self.org,
            project=project,
            trace_id=f"t-{AITrace.objects.count()}",
            span_id=f"s-{AITrace.objects.count()}",
            trace_type=AITrace.TraceType.LLM_CALL,
            status=status,
            risk_score=risk,
            started_at=started,
            metadata={"agent_key": agent_key} if agent_key else {},
            session_id=f"agent-{agent_key}" if agent_key else "",
        )

    def test_ingest_attaches_trace_to_gateway_project_via_agent_key(self):
        started = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        created, errors = ingest_traces(
            self.org,
            [
                {
                    "trace_id": "attach-1",
                    "span_id": "span-1",
                    "trace_type": "llm_call",
                    "status": "blocked",
                    "risk_score": 0.95,
                    "started_at": started,
                    "metadata": {"agent_key": "agent-goat"},
                }
            ],
        )
        self.assertEqual(errors, {})
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].project_id, self.gateway.pk)

    def test_ingest_creates_gateway_project_for_new_agent(self):
        started = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        created, errors = ingest_traces(
            self.org,
            [
                {
                    "trace_id": "new-agent-1",
                    "span_id": "span-1",
                    "trace_type": "llm_call",
                    "started_at": started,
                    "metadata": {"agent_key": "brand-new-agent", "name": "New Bot"},
                }
            ],
        )
        self.assertEqual(errors, {})
        self.assertEqual(created[0].project.gateway_agent_key, "brand-new-agent")
        self.assertTrue(created[0].project.is_gateway_app)

    def test_runtime_findings_require_project(self):
        self._trace(project=self.gateway, agent_key="agent-goat")
        self.assertEqual(list_runtime_finding_dicts(self.org, project=None), [])
        rows = list_runtime_finding_dicts(self.org, project=self.gateway)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            list_runtime_finding_dicts(self.org, project=self.static),
            [],
        )

    def test_runtime_findings_include_orphan_traces_for_gateway_project(self):
        self._trace(project=None, agent_key=self.gateway.gateway_agent_key)
        rows = list_runtime_finding_dicts(self.org, project=self.gateway)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")

    def test_dashboard_requires_project_selection(self):
        self._finding(self.static)
        response = self.client.get(reverse("ui:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["requires_project"])
        self.assertEqual(response.context["critical_count"], 0)
        self.assertContains(response, "Select a project")

    def test_dashboard_scopes_to_active_project_only(self):
        self._finding(self.static, severity="critical")
        self._finding(self.static, severity="high")
        other = Project.objects.create(
            organization=self.org, name="Other", slug="other"
        )
        self._finding(other, severity="critical")
        self._trace(project=self.gateway, agent_key="agent-goat")

        response = self.client.get(
            reverse("ui:dashboard") + f"?project={self.static.pk}"
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["requires_project"])
        self.assertEqual(response.context["active_project"].pk, self.static.pk)
        self.assertEqual(response.context["critical_count"], 1)
        self.assertEqual(response.context["high_count"], 1)
        self.assertEqual(response.context["runtime_detection_count"], 0)

    def test_dashboard_runtime_project_shows_gateway_findings(self):
        self._trace(project=self.gateway, agent_key="agent-goat")
        response = self.client.get(
            reverse("ui:dashboard") + f"?project={self.gateway.pk}"
        )
        self.assertTrue(response.context["is_runtime_project"])
        self.assertGreaterEqual(response.context["runtime_detection_count"], 1)
        self.assertContains(response, "Full Scan is disabled")

    def test_delete_project_removes_findings_and_traces(self):
        finding = self._finding(self.static)
        trace = self._trace(project=self.static)
        ScanRun.objects.create(
            project=self.static,
            scan_type=ScanRun.ScanType.FULL,
            status=ScanRun.Status.COMPLETED,
        )
        orphan = self._trace(project=None, agent_key="agent-goat")

        response = self.client.post(
            reverse("ui:projects:delete", args=[self.static.pk])
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Project.objects.filter(pk=self.static.pk).exists())
        self.assertFalse(SecurityFinding.objects.filter(pk=finding.pk).exists())
        self.assertFalse(AITrace.objects.filter(pk=trace.pk).exists())
        # Orphan for another agent key remains until that gateway project is deleted
        self.assertTrue(AITrace.objects.filter(pk=orphan.pk).exists())

    def test_delete_gateway_project_cleans_orphan_agent_traces(self):
        ManagedAgent.objects.create(
            organization=self.org,
            agent_key="agent-goat",
            name="Goat",
        )
        linked = self._trace(project=self.gateway, agent_key="agent-goat")
        orphan = self._trace(project=None, agent_key="agent-goat")

        response = self.client.post(
            reverse("ui:projects:delete", args=[self.gateway.pk])
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(AITrace.objects.filter(pk=linked.pk).exists())
        self.assertFalse(AITrace.objects.filter(pk=orphan.pk).exists())
        self.assertFalse(
            ManagedAgent.objects.filter(
                organization=self.org, agent_key="agent-goat"
            ).exists()
        )

    def test_full_scan_blocked_for_gateway_project(self):
        response = self.client.post(
            reverse("ui:projects:scan", args=[self.gateway.pk]),
            {"scan_type": "full"},
        )
        self.assertIn(response.status_code, (200, 302))
        self.assertEqual(
            ScanRun.objects.filter(project=self.gateway).count(),
            0,
        )
