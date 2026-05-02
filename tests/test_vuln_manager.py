"""
Tests for vulnerability management modules.
"""

import pytest

from eeg.vuln_manager.dependency_parser import DependencyParser, AI_PACKAGE_REGISTRY
from eeg.vuln_manager.cve_fetcher import CVEFetcher, CVSS_TO_SEVERITY
from eeg.collector import Severity


class TestDependencyParser:
    """Tests for AI dependency parsing."""

    def test_parse_requirements_txt(self, temp_repo):
        import os
        req_file = os.path.join(temp_repo, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("""
boto3>=1.34.0
langchain==0.1.0
openai>=1.0.0
requests>=2.31.0
""")
        
        parser = DependencyParser(temp_repo)
        ai_deps = parser.parse()
        
        # Should identify AI packages
        assert "langchain" in ai_deps or "openai" in ai_deps

    def test_ai_package_registry_coverage(self):
        """Registry should include major AI packages."""
        expected_packages = ["langchain", "openai", "anthropic", "boto3", "transformers"]
        for pkg in expected_packages:
            assert pkg in AI_PACKAGE_REGISTRY, f"Missing {pkg} in AI_PACKAGE_REGISTRY"


class TestCVEFetcher:
    """Tests for CVE fetching (mocked to avoid network calls)."""

    def test_cvss_severity_mapping(self):
        assert CVSS_TO_SEVERITY["CRITICAL"] == Severity.CRITICAL
        assert CVSS_TO_SEVERITY["HIGH"] == Severity.HIGH
        assert CVSS_TO_SEVERITY["MEDIUM"] == Severity.MEDIUM
        assert CVSS_TO_SEVERITY["LOW"] == Severity.LOW

    def test_fetcher_initialization(self):
        fetcher = CVEFetcher()
        assert fetcher.api_key is None
        assert fetcher.session is not None

    def test_fetcher_with_api_key(self):
        fetcher = CVEFetcher(api_key="test-key")
        assert fetcher.api_key == "test-key"
        assert fetcher.session.headers.get("apiKey") == "test-key"
