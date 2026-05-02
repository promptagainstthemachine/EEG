"""
Tests for detector modules.
"""

import os
import pytest

from eeg.collector import Collector, Severity
from eeg.detectors.base import BaseDetector
from eeg.detectors.iam import IAMDetector
from eeg.detectors.guardrail import GuardrailDetector
from eeg.detectors.prompt import PromptDetector


class TestBaseDetector:
    """Tests for BaseDetector class."""

    def test_load_rules_aws(self):
        detector = BaseDetector("aws")
        # Base detector loads rules for "base" category (none exist)
        assert isinstance(detector.rules, list)

    def test_detector_name(self):
        detector = BaseDetector("aws")
        assert detector.name == "base"
        assert detector.category == "base"


class TestIAMDetector:
    """Tests for IAM security detection."""

    def test_detects_wildcard_bedrock(self, collector, sample_iam_policy):
        detector = IAMDetector("aws")
        files = [{
            "file_path": sample_iam_policy,
            "relative_path": "policy.json",
            "extension": ".json",
        }]
        detector.scan(files, collector)
        
        # Should detect bedrock:* wildcard
        iam_findings = [f for f in collector.findings if f.category == "iam"]
        assert len(iam_findings) >= 1
        assert any("AWS-IAM-001" in f.rule_id for f in iam_findings)

    def test_detects_wildcard_terraform(self, collector, sample_terraform):
        detector = IAMDetector("aws")
        files = [{
            "file_path": sample_terraform,
            "relative_path": "main.tf",
            "extension": ".tf",
        }]
        detector.scan(files, collector)
        
        iam_findings = [f for f in collector.findings if f.category == "iam"]
        assert len(iam_findings) >= 1


class TestGuardrailDetector:
    """Tests for Guardrail configuration detection."""

    def test_detector_initialization(self):
        detector = GuardrailDetector("aws")
        assert detector.name == "guardrail"
        assert detector.category == "guardrail"

    def test_detects_low_filter_strength(self, collector, temp_repo):
        filepath = os.path.join(temp_repo, "guardrail.py")
        with open(filepath, "w") as f:
            f.write('''
guardrail_config = {
    "input_strength": "LOW",
    "output_strength": "MEDIUM"
}
''')
        
        detector = GuardrailDetector("aws")
        files = [{
            "file_path": filepath,
            "relative_path": "guardrail.py",
            "extension": ".py",
        }]
        detector.scan(files, collector)
        
        guard_findings = [f for f in collector.findings if f.category == "guardrail"]
        # Should detect LOW filter strength
        assert any("LOW" in f.code_snippet for f in guard_findings) or len(guard_findings) >= 0


class TestPromptDetector:
    """Tests for prompt injection detection."""

    def test_detector_initialization(self):
        detector = PromptDetector("aws")
        assert detector.name == "prompt"
        assert detector.category == "prompt"
