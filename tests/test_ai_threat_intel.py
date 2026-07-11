"""Dependency scan helpers: all packages, NVD + GHSA only."""

from unittest.mock import MagicMock, patch

from django.test import TestCase

from eeg.vuln_manager.ai_packages import extract_dependency_package, is_ai_package_name
from eeg.vuln_manager.dependency_parser import DependencyParser


class DependencyPackageHelperTests(TestCase):
    def test_scoped_npm_package_name(self):
        self.assertEqual(
            extract_dependency_package("dependency:@ai-sdk/openai==1.3.23"),
            "@ai-sdk/openai",
        )

    def test_express_is_not_ai_registry_only(self):
        self.assertFalse(is_ai_package_name("express"))
        self.assertFalse(is_ai_package_name("commander"))


class ParseAllPackageJsonTests(TestCase):
    def test_parses_dependencies_and_dev_dependencies(self):
        import json
        import tempfile
        from pathlib import Path

        pkg = {
            "dependencies": {
                "@ai-sdk/openai": "1.3.23",
                "commander": "14.0.0",
            },
            "devDependencies": {
                "vitest": "3.2.4",
                "hono": "4.8.9",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
            parser = DependencyParser(str(root))
            deps = parser.parse_all()
            names = {d.name for d in deps}
            self.assertIn("@ai-sdk/openai", names)
            self.assertIn("commander", names)
            self.assertIn("vitest", names)
            self.assertIn("hono", names)


class ScanProjectDependenciesTests(TestCase):
    @patch("eeg.vuln_manager.dependency_scan.DependencyParser")
    def test_scan_uses_nvd_and_ghsa_only(self, mock_parser_cls):
        from eeg.vuln_manager.dependency_parser import ParsedDependency
        from eeg.vuln_manager.dependency_scan import scan_project_dependencies

        dep = ParsedDependency(
            name="commander", version="14.0.0", ecosystem="npm", source_file="package.json"
        )
        mock_parser = MagicMock()
        mock_parser.parse_all.return_value = [dep]
        mock_parser_cls.return_value = mock_parser

        with patch("eeg.vuln_manager.cve_fetcher.CVEFetcher") as mock_nvd, patch(
            "eeg.vuln_manager.github_advisory.GitHubAdvisoryFetcher"
        ) as mock_ghsa:
            mock_nvd.return_value.fetch_for_dependencies.return_value = []
            mock_ghsa.return_value.fetch_for_dependencies.return_value = []
            findings, summary = scan_project_dependencies("/tmp/repo", "any")

        self.assertEqual(findings, [])
        self.assertEqual(summary["packages_found"], 1)
        mock_nvd.return_value.fetch_for_dependencies.assert_called_once()
        mock_ghsa.return_value.fetch_for_dependencies.assert_called_once()
