"""
Tests for the Collector module.
"""

import pytest
from eeg.collector import Collector, Finding, Severity


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_weight_order(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_severity_comparison(self):
        assert Severity.LOW < Severity.CRITICAL
        assert Severity.MEDIUM < Severity.HIGH


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        finding = Finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            category="test",
            cloud_env="aws",
            file_path="test.py",
            line_number=10,
            code_snippet="test code",
            message="Test finding",
            recommendation="Fix the issue",
        )
        assert finding.rule_id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.timestamp is not None

    def test_finding_to_dict(self):
        finding = Finding(
            rule_id="TEST-001",
            severity=Severity.CRITICAL,
            category="iam",
            cloud_env="aws",
            file_path="policy.json",
            line_number=5,
            code_snippet="bedrock:*",
            message="Wildcard permissions",
            recommendation="Scope permissions",
            cwe="CWE-250",
            owasp_llm="LLM06",
        )
        d = finding.to_dict()
        assert d["rule_id"] == "TEST-001"
        assert d["severity"] == "CRITICAL"
        assert d["cwe"] == "CWE-250"
        assert d["owasp_llm"] == "LLM06"


class TestCollector:
    """Tests for Collector class."""

    def test_add_finding(self, collector):
        finding = Finding(
            rule_id="TEST-001",
            severity=Severity.MEDIUM,
            category="test",
            cloud_env="aws",
            file_path="test.py",
            line_number=1,
            code_snippet="code",
            message="Test",
            recommendation="Fix",
        )
        collector.add_finding(finding)
        assert len(collector.findings) == 1

    def test_deduplication(self, collector):
        """Same rule+file+line should only appear once."""
        for _ in range(3):
            finding = Finding(
                rule_id="TEST-001",
                severity=Severity.MEDIUM,
                category="test",
                cloud_env="aws",
                file_path="test.py",
                line_number=10,
                code_snippet="code",
                message="Test",
                recommendation="Fix",
            )
            collector.add_finding(finding)
        assert len(collector.findings) == 1

    def test_different_lines_not_deduplicated(self, collector):
        """Same rule, different lines should both appear."""
        for line in [10, 20, 30]:
            finding = Finding(
                rule_id="TEST-001",
                severity=Severity.MEDIUM,
                category="test",
                cloud_env="aws",
                file_path="test.py",
                line_number=line,
                code_snippet="code",
                message="Test",
                recommendation="Fix",
            )
            collector.add_finding(finding)
        assert len(collector.findings) == 3

    def test_set_metadata(self, collector):
        collector.set_metadata(cloud_env="aws", auth_enabled=True)
        assert collector.scan_metadata["cloud_env"] == "aws"
        assert collector.scan_metadata["auth_enabled"] is True

    def test_permission_issue_tracking(self, collector):
        collector.add_permission_issue("check_guardrails", "bedrock:ListGuardrails", "Access Denied")
        assert len(collector.permission_issues) == 1
        assert "check_guardrails" in collector.skipped_checks

    def test_completed_check_tracking(self, collector):
        collector.add_completed_check("check_iam")
        collector.add_completed_check("check_iam")  # Duplicate
        assert collector.completed_checks.count("check_iam") == 1
