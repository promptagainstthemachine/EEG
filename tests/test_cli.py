"""Tests for eeg.cli."""

from __future__ import annotations

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from eeg.cli import build_parser, main, run_profile_scan

ROOT = Path(__file__).resolve().parents[1]
VULN_FIXTURE = ROOT / "fixtures" / "vulnerable-agent"
CLEAN_FIXTURE = ROOT / "fixtures" / "clean-agent"


class TestCli(unittest.TestCase):
    def test_parser_scan_defaults(self):
        args = build_parser().parse_args(["scan", str(VULN_FIXTURE)])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.profile, "code")
        self.assertEqual(args.format, "json")
        self.assertEqual(args.fail_on, "high")

    def test_run_profile_scan_vulnerable_fixture(self):
        report = run_profile_scan(VULN_FIXTURE, profile="code")
        self.assertGreaterEqual(report["summary"]["total_findings"], 1)
        blob = " ".join(
            f"{f.get('rule_id', '')} {f.get('message', '')}" for f in report["findings"]
        ).lower()
        self.assertTrue(
            any(k in blob for k in ("hardcoded", "api", "credential", "exec")),
            msg=f"expected security finding, got: {blob[:200]}",
        )

    def test_main_sarif_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.sarif"
            code = main(
                [
                    "scan",
                    str(VULN_FIXTURE),
                    "--profile",
                    "code",
                    "--format",
                    "sarif",
                    "--output",
                    str(out),
                    "--fail-on",
                    "none",
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(out.is_file())
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["version"], "2.1.0")
            self.assertIn("runs", doc)

    def test_main_missing_directory(self):
        code = main(["scan", "/nonexistent-eeg-path-xyz"])
        self.assertEqual(code, 2)

    def test_clean_fixture_fewer_than_vulnerable(self):
        vuln = run_profile_scan(VULN_FIXTURE, profile="code")
        clean = run_profile_scan(CLEAN_FIXTURE, profile="code")
        self.assertGreater(
            vuln["summary"]["total_findings"],
            clean["summary"]["total_findings"],
        )

    def test_profiles_command(self):
        buf = StringIO()
        with mock.patch("sys.stdout", buf):
            code = main(["profiles"])
        self.assertEqual(code, 0)
        self.assertIn("code:", buf.getvalue())


class TestCliModes(unittest.TestCase):
    def test_headless_parser(self):
        from eeg.cli import _build_headless_parser

        args = _build_headless_parser().parse_args(
            [str(VULN_FIXTURE), "--profile", "code"]
        )
        self.assertEqual(args.profile, "code")
        self.assertEqual(Path(args.target).name, VULN_FIXTURE.name)

    def test_serve_parser(self):
        from eeg.cli import _build_serve_parser

        args = _build_serve_parser().parse_args(["--port", "9001"])
        self.assertEqual(args.port, 9001)

    def test_gateway_wrap_parser(self):
        from eeg.cli import _build_gateway_wrap_parser

        args = _build_gateway_wrap_parser().parse_args(
            ["--gateway-wrap", "https://myaiapp.com", "--port", "8787"]
        )
        self.assertEqual(args.gateway_wrap, "https://myaiapp.com")
        self.assertEqual(args.port, 8787)

    def test_main_headless_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            (target / "app.py").write_text("print('hello')\n", encoding="utf-8")
            out = Path(tmp) / "out.json"
            code = main(
                [
                    "--headless",
                    str(target),
                    "--profile",
                    "code",
                    "--output",
                    str(out),
                    "--fail-on",
                    "none",
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(out.is_file())
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("findings", doc)

    def test_normalize_gateway_wrap_url(self):
        from eeg.cli_serve import normalize_wrap_upstream

        self.assertTrue(
            normalize_wrap_upstream("https://myaiapp.com").endswith("/v1/chat/completions")
        )
        self.assertEqual(
            normalize_wrap_upstream("https://myaiapp.com/v1/chat/completions"),
            "https://myaiapp.com/v1/chat/completions",
        )


if __name__ == "__main__":
    unittest.main()
