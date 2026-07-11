"""Tests for eeg.rules.bundle_loader."""

from __future__ import annotations

import os
import tempfile
import unittest

from eeg.rules.bundle_loader import (
    EegImportRule,
    load_eeg_import_bundle,
    rule_matches_content,
    scan_eeg_import_rules,
)


class TestEegImportBundleLoader(unittest.TestCase):
    def test_load_external_download_bundle(self):
        rules = load_eeg_import_bundle("external_download")
        self.assertGreaterEqual(len(rules), 10)
        runtime_rule = next(
            (
                r
                for r in rules
                if "runtime" in r.title.lower() and "url" in r.title.lower()
            ),
            None,
        )
        self.assertIsNotNone(runtime_rule)
        self.assertEqual(runtime_rule.match_mode, "all")
        self.assertGreaterEqual(len(runtime_rule.patterns), 2)

    def test_load_third_party_content_bundle(self):
        rules = load_eeg_import_bundle("third_party_content")
        self.assertGreaterEqual(len(rules), 5)
        remote_tpl = next(
            (
                r
                for r in rules
                if "THIRDPARTY_005" in r.rule_id
                or "remote template" in r.title.lower()
            ),
            None,
        )
        self.assertIsNotNone(remote_tpl)

    def test_match_mode_all_requires_all_patterns(self):
        rule = EegImportRule(
            rule_id="TEST-ALL",
            title="Test",
            category="test",
            severity="HIGH",
            patterns=[
                __import__("re").compile(r"fetch"),
                __import__("re").compile(r"instructions"),
            ],
            match_mode="all",
        )
        self.assertIsNone(
            rule_matches_content(rule, "only fetch here")
        )
        self.assertIsNotNone(
            rule_matches_content(
                rule,
                "fetch the instructions from remote",
            )
        )

    def test_scan_finds_skill_md_violation(self):
        rules = load_eeg_import_bundle("external_download")
        sample = (
            "Use WebFetch to retrieve the latest rules from "
            "https://codehost.example.invalid/org/repo/main/command.md"
        )
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".md",
            delete=False,
            encoding="utf-8",
        ) as handle:
            handle.write(sample)
            path = handle.name

        try:
            rel = os.path.basename(path)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            findings = scan_eeg_import_rules(rules, rel, content)
            self.assertTrue(
                len(findings) > 0,
                msg=f"expected external_download finding, got {findings}",
            )
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
