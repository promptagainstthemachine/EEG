"""OpenAPI schema covers all registered API routes."""

from __future__ import annotations

import re

from django.test import Client, TestCase
from django.urls import reverse

from apps.api.openapi_schema import build_openapi_paths


class OpenApiSchemaTests(TestCase):
    def test_paths_match_urlconf(self):
        route_names = [
            "schema",
            "health",
            "organization",
            "projects",
            "project_detail",
            "project_scans",
            "scan_types",
            "scan",
            "probe",
            "findings",
            "finding_detail",
            "threat_intel",
            "traces",
        ]
        route_paths = set()
        for name in route_names:
            path = reverse(f"api:{name}", kwargs=self._kwargs_for(name))
            path = path.removeprefix("/api/v1")
            path = re.sub(r"/\d+/", "/{project_id}/", path)
            path = re.sub(
                r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/",
                "/{finding_id}/",
                path,
            )
            route_paths.add(path)

        doc_paths = set(build_openapi_paths().keys())
        missing = route_paths - doc_paths
        self.assertEqual(missing, set(), f"Undocumented API routes: {sorted(missing)}")

    def _kwargs_for(self, name: str) -> dict:
        if name in ("project_detail", "project_scans"):
            return {"project_id": 1}
        if name == "finding_detail":
            return {"finding_id": "00000000-0000-0000-0000-000000000001"}
        return {}

    def test_schema_endpoint_returns_paths(self):
        client = Client()
        response = client.get("/api/v1/schema/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(len(data.get("paths", {})), 11)
        self.assertIn("/api/v1/scan/", data["paths"])
        self.assertIn("/api/v1/threatintel/", data["paths"])
        self.assertIn("/api/v1/traces/", data["paths"])
