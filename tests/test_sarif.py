"""Tests for eeg.sarif."""

from __future__ import annotations

import json
import unittest

from eeg.sarif import dumps_sarif, findings_to_sarif


class TestSarif(unittest.TestCase):
    def test_findings_to_sarif_structure(self):
        findings = [
            {
                "rule_id": "test-hardcoded-key",
                "severity": "HIGH",
                "message": "Hardcoded API key detected",
                "file_path": "agent.py",
                "line_number": 7,
                "code_snippet": 'api_key="sk-..."',
                "recommendation": "Use environment variables",
                "cwe": "798",
            }
        ]
        doc = findings_to_sarif(findings, target_uri="/repo")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "EEG")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["ruleId"], "test-hardcoded-key")

    def test_dumps_sarif_valid_json(self):
        payload = dumps_sarif([])
        parsed = json.loads(payload)
        self.assertEqual(parsed["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
