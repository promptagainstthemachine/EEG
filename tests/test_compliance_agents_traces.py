"""Tests for OSS compliance, agent controls, and multi-surface traces."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from apps.accounts.models import Organization
from apps.security.agent_control import control_agent, ensure_agent, is_agent_blocked
from apps.security.models import AITrace, ManagedAgent
from apps.security.runtime_findings import list_runtime_finding_dicts
from apps.security.threat_graph import build_runtime_interaction_graph
from eeg.compliance import evaluate, build_posture_dashboard, run_realtime_compliance_audit


User = get_user_model()


class ComplianceEngineTests(TestCase):
    def test_evaluate_scores_from_findings_and_traces(self):
        findings = [
            {
                "title": "Prompt injection in chat handler",
                "severity": "high",
                "category": "injection",
                "rule_id": "PI-1",
            }
        ]
        traces = [
            {
                "trace_type": "llm_call",
                "status": "blocked",
                "blocked_by_policy": True,
                "threat_level": "high",
                "detection_tags": ["prompt_injection", "jailbreak"],
                "model_name": "test",
            }
        ]
        result = evaluate(findings=findings, traces=traces)
        self.assertIn("compliance_score", result)
        self.assertGreaterEqual(len(result["gaps"]), 1)
        posture = build_posture_dashboard(findings=findings, traces=traces)
        self.assertIn("cards", posture)
        audit = run_realtime_compliance_audit(findings=findings, traces=traces)
        self.assertEqual(audit["audit_type"], "realtime")


class AgentControlTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme-agents")
        self.agent = ensure_agent(self.org, "goat-1", name="Goat")

    def test_pause_updates_blocklist(self):
        result = control_agent(self.org, str(self.agent.id), "pause")
        self.assertEqual(result["control_status"], "paused")
        self.org.refresh_from_db()
        keys = self.org.runtime_policy_config.get("blocked_agent_keys") or []
        self.assertIn("goat-1", keys)
        blocked, status = is_agent_blocked(self.org, "goat-1")
        self.assertTrue(blocked)
        self.assertEqual(status, "paused")

    def test_start_clears_block(self):
        control_agent(self.org, str(self.agent.id), "quarantine")
        control_agent(self.org, str(self.agent.id), "start")
        blocked, _ = is_agent_blocked(self.org, "goat-1")
        self.assertFalse(blocked)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.control_status, ManagedAgent.ControlStatus.ACTIVE)


class TraceSurfaceTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="TraceOrg", slug="trace-org")
        now = datetime.now(timezone.utc)
        for ttype, risk in (
            ("llm_call", 0.2),
            ("tool_call", 0.5),
            ("retrieval", 0.3),
            ("mcp_tool", 0.8),
        ):
            AITrace.objects.create(
                organization=self.org,
                trace_id=f"t-{uuid4().hex[:8]}",
                span_id=f"s-{uuid4().hex[:8]}",
                trace_type=ttype,
                status="blocked" if risk >= 0.8 else "success",
                risk_score=risk,
                started_at=now,
                metadata={
                    "blocked_by_policy": risk >= 0.8,
                    "detection_tags": [ttype],
                    "tool_name": "search" if ttype == "tool_call" else "",
                },
            )

    def test_runtime_findings_and_graph(self):
        rows = list_runtime_finding_dicts(self.org, limit=50)
        self.assertGreaterEqual(len(rows), 1)
        graph = build_runtime_interaction_graph(self.org, limit=50)
        self.assertGreaterEqual(graph["meta"]["interaction_count"], 4)
        self.assertGreater(graph["meta"]["node_count"], 0)


class UINavSmokeTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="UIOrg", slug="ui-org")
        self.user = User.objects.create_user(username="u1", password="pass12345")
        self.user.organization = self.org
        self.user.save()
        self.client = Client()
        self.client.force_login(self.user)

    def test_compliance_agents_traces_pages(self):
        for path in ("/compliance/", "/agents/", "/traces/", "/findings/runtime/", "/threat-graph/runtime/"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, path)

    def test_runtime_redirects_to_compliance(self):
        resp = self.client.get("/runtime/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Compliance")
