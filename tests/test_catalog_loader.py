"""Tests for eeg.rules.catalog_loader."""

from __future__ import annotations

import unittest

from eeg.rules.catalog_loader import (
    get_full_scan_ids,
    get_probe_ids_for_api_endpoint,
    get_scan_ids_for_profile,
    load_catalog,
    validate_catalog,
)


class TestCatalogLoader(unittest.TestCase):
    def test_load_catalog_has_scan_profiles(self):
        catalog = load_catalog()
        self.assertIn("scan_profiles", catalog)
        self.assertIn("full", catalog["scan_profiles"])

    def test_full_scan_includes_core_scans(self):
        ids = get_full_scan_ids()
        self.assertIn("code_security", ids)
        self.assertIn("dependency_vuln", ids)
        self.assertIn("agent_forensics", ids)
        self.assertIn("redteam_marker_surface", ids)

    def test_full_scan_includes_cloud_static_for_aws(self):
        ids = get_full_scan_ids(cloud_project_type="aws")
        self.assertIn("cloud_static_rules", ids)

    def test_full_scan_excludes_cloud_static_for_generic(self):
        ids = get_full_scan_ids(cloud_project_type=None)
        self.assertNotIn("cloud_static_rules", ids)

    def test_code_profile_subset(self):
        code_ids = set(get_scan_ids_for_profile("code"))
        full_ids = set(get_full_scan_ids())
        self.assertTrue(code_ids.issubset(full_ids))

    def test_api_endpoint_probes(self):
        probes = get_probe_ids_for_api_endpoint()
        self.assertIn("gateway_surface", probes)
        self.assertIn("mcp_jsonrpc_handshake", probes)

    def test_validate_catalog_registered_scans(self):
        report = validate_catalog()
        self.assertEqual(report["unregistered_scans"], [])


if __name__ == "__main__":
    unittest.main()
