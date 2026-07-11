"""Tests for gateway agent identity resolution + auto-register."""

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from apps.accounts.models import Organization
from apps.security.agent_control import (
    resolve_agent_ref,
    touch_agent_from_request,
)
from apps.security.models import ManagedAgent


class AgentRefResolveTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        user = get_user_model().objects.create_user(
            username="agentref", password="x", email="a@example.com"
        )
        self.org = Organization.objects.create(name="Agent Org", slug="agent-org")
        user.organization = self.org
        user.save(update_fields=["organization"])

    def test_resolves_metadata_agent_id(self):
        req = self.factory.post("/api/v1/gateway/chat/completions/")
        body = {"metadata": {"agent_id": "ai-goat-challenge", "framework": "ai-goat"}}
        self.assertEqual(resolve_agent_ref(req, body), "ai-goat-challenge")

    def test_header_wins_over_metadata(self):
        req = self.factory.post(
            "/api/v1/gateway/chat/completions/",
            HTTP_X_EEG_AGENT="from-header",
        )
        body = {"metadata": {"agent_id": "from-meta"}, "agent_id": "from-body"}
        self.assertEqual(resolve_agent_ref(req, body), "from-header")

    def test_touch_auto_registers(self):
        req = self.factory.post("/api/v1/gateway/chat/completions/")
        body = {
            "metadata": {
                "agent_id": "auto-goat",
                "framework": "ai-goat",
                "name": "AI Goat",
            }
        }
        agent = touch_agent_from_request(self.org, req, body)
        self.assertIsNotNone(agent)
        self.assertEqual(agent.agent_key, "auto-goat")
        self.assertEqual(agent.name, "AI Goat")
        self.assertEqual(agent.framework, "ai-goat")
        self.assertTrue(
            ManagedAgent.objects.filter(
                organization=self.org, agent_key="auto-goat"
            ).exists()
        )
