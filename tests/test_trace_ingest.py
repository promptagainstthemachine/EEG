"""Trace ingestion API and SDK tests."""

import json
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import urlparse

from django.test import Client, TestCase

from apps.accounts.models import ApiKey, Organization
from apps.projects.models import Project
from apps.security.models import AITrace
from eeg.sdk.client import EEGClient, EEGClientError


class TraceIngestApiTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        _, self.raw_key = ApiKey.create_key(self.org, "test")
        self.project = Project.objects.create(
            organization=self.org,
            name="app",
            slug="app",
        )
        self.client = Client()

    def _auth_headers(self):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.raw_key}",
            "content_type": "application/json",
        }

    def test_post_trace_requires_auth(self):
        response = self.client.post(
            "/api/v1/traces/",
            data=json.dumps({"trace_id": "t1", "span_id": "s1", "trace_type": "llm_call"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_post_trace_creates_record(self):
        started = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "trace_id": "trace-demo-001",
            "span_id": "span-001",
            "trace_type": "llm_call",
            "status": "success",
            "provider": "openai",
            "model": "gpt-4o",
            "input_tokens": 50,
            "output_tokens": 20,
            "latency_ms": 400,
            "started_at": started.isoformat(),
            "project_id": self.project.id,
        }
        response = self.client.post(
            "/api/v1/traces/",
            data=json.dumps(payload),
            **self._auth_headers(),
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("trace", data)
        self.assertEqual(data["trace"]["trace_id"], "trace-demo-001")
        self.assertEqual(AITrace.objects.filter(organization=self.org).count(), 1)

    def test_post_trace_batch(self):
        started = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        payload = {
            "traces": [
                {
                    "trace_id": "batch-1",
                    "span_id": "span-1",
                    "trace_type": "llm_call",
                    "started_at": started,
                },
                {
                    "trace_id": "batch-1",
                    "span_id": "span-2",
                    "trace_type": "tool_call",
                    "started_at": started,
                },
            ]
        }
        response = self.client.post(
            "/api/v1/traces/",
            data=json.dumps(payload),
            **self._auth_headers(),
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["created"], 2)

    def test_post_trace_validation_error(self):
        response = self.client.post(
            "/api/v1/traces/",
            data=json.dumps({"trace_type": "llm_call"}),
            **self._auth_headers(),
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("fields", response.json())

    def test_post_trace_telemetry_disabled(self):
        self.org.realtime_telemetry_enabled = False
        self.org.save(update_fields=["realtime_telemetry_enabled"])
        response = self.client.post(
            "/api/v1/traces/",
            data=json.dumps(
                {
                    "trace_id": "t1",
                    "span_id": "s1",
                    "trace_type": "llm_call",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
            ),
            **self._auth_headers(),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "telemetry_disabled")

    def test_post_trace_policy_enforcement_blocks_high_risk(self):
        self.org.policy_enforcement_enabled = True
        self.org.save(update_fields=["policy_enforcement_enabled"])
        started = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        payload = {
            "trace_id": "policy-1",
            "span_id": "span-1",
            "trace_type": "llm_call",
            "status": "success",
            "risk_score": 0.95,
            "started_at": started,
            "project_id": self.project.id,
        }
        response = self.client.post(
            "/api/v1/traces/",
            data=json.dumps(payload),
            **self._auth_headers(),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "policy_enforcement_blocked")
        self.assertEqual(AITrace.objects.filter(organization=self.org).count(), 0)

    def test_get_traces_after_ingest(self):
        started = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        self.client.post(
            "/api/v1/traces/",
            data=json.dumps(
                {
                    "trace_id": "listed-1",
                    "span_id": "span-1",
                    "trace_type": "llm_call",
                    "started_at": started,
                }
            ),
            **self._auth_headers(),
        )
        response = self.client.get("/api/v1/traces/", **self._auth_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)


class EEGClientTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Sdk Org", slug="sdk-org")
        _, self.raw_key = ApiKey.create_key(self.org, "sdk")
        self.django_client = Client()

    def _bridge_requests(self, method, url, **kwargs):
        """Route SDK HTTP calls through Django test client (no real network)."""
        path = urlparse(url).path
        extra = {}
        session_headers = getattr(self._sdk, "_session", None)
        session_headers = getattr(session_headers, "headers", {}) if session_headers else {}
        merged = {**session_headers, **(kwargs.get("headers") or {})}
        auth = merged.get("Authorization")
        if auth:
            extra["HTTP_AUTHORIZATION"] = auth
        if method.upper() == "GET":
            response = self.django_client.get(path, **extra)
        else:
            response = self.django_client.post(
                path,
                data=json.dumps(kwargs.get("json") or {}),
                content_type="application/json",
                **extra,
            )

        class _Resp:
            status_code = response.status_code
            content = response.content

            def json(self):
                return json.loads(self.content or b"{}")

        return _Resp()

    def test_sdk_ingest_trace(self):
        self._sdk = EEGClient("http://testserver", api_key=self.raw_key)
        with patch.object(self._sdk._session, "request", side_effect=self._bridge_requests):
            result = self._sdk.ingest_trace(
                trace_id="sdk-trace-1",
                span_id="sdk-span-1",
                trace_type="llm_call",
                provider="openai",
                model="gpt-4o",
                latency_ms=100,
            )
        self.assertEqual(result["trace"]["trace_id"], "sdk-trace-1")
        self.assertEqual(AITrace.objects.filter(organization=self.org).count(), 1)

    def test_sdk_auth_error(self):
        self._sdk = EEGClient("http://testserver", api_key="eeg_oss_invalid_key_xxx")
        with patch.object(self._sdk._session, "request", side_effect=self._bridge_requests):
            with self.assertRaises(EEGClientError) as ctx:
                self._sdk.ingest_trace(
                    trace_id="t1",
                    span_id="s1",
                    trace_type="llm_call",
                )
        self.assertEqual(ctx.exception.status_code, 401)
