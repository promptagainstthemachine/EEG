"""Golden fixture tests for scan signal quality."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from eeg.cli import run_profile_scan

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIR = ROOT / "fixtures" / "expected"


def _load_expected(name: str) -> dict:
    path = EXPECTED_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


class TestScanFixtures(unittest.TestCase):
    def test_vulnerable_agent_meets_expectations(self):
        spec = _load_expected("vulnerable-agent-code.json")
        fixture = ROOT / "fixtures" / "vulnerable-agent"
        report = run_profile_scan(fixture, profile=spec["profile"])
        findings = report["findings"]
        self.assertGreaterEqual(len(findings), spec["min_findings"])
        rule_ids = {str(f.get("rule_id", "")) for f in findings}
        for rid in spec.get("required_rule_ids", []):
            self.assertIn(rid, rule_ids, msg=f"missing required rule_id: {rid}")
        for prefix in spec.get("required_rule_id_prefixes", []):
            self.assertTrue(
                any(r.startswith(prefix) for r in rule_ids),
                msg=f"no rule_id with prefix {prefix!r} in {rule_ids}",
            )
        rule_blob = " ".join(
            f"{f.get('rule_id', '')} {f.get('message', '')}" for f in findings
        ).lower()
        for needle in spec.get("must_include_rule_substrings", []):
            self.assertIn(needle.lower(), rule_blob, msg=f"missing rule substring: {needle}")

    def test_clean_agent_within_bounds(self):
        spec = _load_expected("clean-agent-code.json")
        fixture = ROOT / "fixtures" / "clean-agent"
        report = run_profile_scan(fixture, profile=spec["profile"])
        findings = report["findings"]
        self.assertLessEqual(len(findings), spec["max_findings"])
        for f in findings:
            rid = str(f.get("rule_id", "")).lower()
            for forbidden in spec.get("forbidden_rule_substrings", []):
                self.assertNotIn(
                    forbidden.lower(),
                    rid,
                    msg=f"clean fixture triggered {rid}",
                )


if __name__ == "__main__":
    unittest.main()
