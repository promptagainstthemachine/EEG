"""Threat radar bucket filters."""

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.finding_dedup import build_finding_fingerprint
from apps.security.models import SecurityFinding
from apps.security.threat_categories import (
    filter_findings_by_bucket,
    finding_matches_bucket,
    is_command_injection_finding,
    is_prompt_injection_finding,
)


class ThreatCategoryFilterTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", slug="test-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Demo",
            slug="demo",
        )

    def _finding(self, **kwargs):
        data = {
            "organization": self.org,
            "project": self.project,
            "severity": "high",
            "status": SecurityFinding.Status.OPEN,
        }
        data.update(kwargs)
        data.setdefault(
            "fingerprint",
            build_finding_fingerprint(data),
        )
        return SecurityFinding.objects.create(**data)

    def test_secrets_bucket_matches_rule_id_and_category(self):
        by_rule = self._finding(
            rule_id="EEG.SECRET.HARDCODED",
            title="Hardcoded API key",
            category="code",
            file_path="app/config.py",
            line_number=12,
            code_snippet='API_KEY = "sk-live-abc"',
        )
        by_category = self._finding(
            rule_id="custom.rule",
            title="Leak",
            category="secrets",
            severity="medium",
            file_path="src/leak.py",
            line_number=3,
        )
        other = self._finding(
            rule_id="prompt.jailbreak",
            title="Injection",
            category="prompt",
            file_path="src/agent.py",
            line_number=9,
        )

        qs = SecurityFinding.objects.filter(organization=self.org)
        matched = set(filter_findings_by_bucket(qs, "secrets").values_list("pk", flat=True))

        self.assertIn(by_rule.pk, matched)
        self.assertIn(by_category.pk, matched)
        self.assertNotIn(other.pk, matched)

    def test_prompt_injection_bucket(self):
        finding = self._finding(
            rule_id="prompt.injection",
            title="Jailbreak attempt in system prompt",
            category="prompt_injection",
            severity="critical",
            file_path="src/prompt.py",
            line_number=1,
        )
        qs = SecurityFinding.objects.filter(organization=self.org)
        self.assertTrue(
            filter_findings_by_bucket(qs, "prompt_injection").filter(pk=finding.pk).exists()
        )

    def test_command_injection_not_in_prompt_bucket(self):
        cmd = self._finding(
            rule_id="EEG-AEGIS-CMD001",
            title="OS command injection via subprocess",
            category="command_injection",
            severity="critical",
            file_path="src/run.py",
            line_number=10,
        )
        prompt = self._finding(
            rule_id="prompt.jailbreak",
            title="Jailbreak in system prompt",
            category="prompt_injection",
            severity="high",
            file_path="src/agent.py",
            line_number=2,
        )
        qs = SecurityFinding.objects.filter(organization=self.org)

        prompt_ids = set(
            filter_findings_by_bucket(qs, "prompt_injection").values_list("pk", flat=True)
        )
        cmd_ids = set(
            filter_findings_by_bucket(qs, "command_injection").values_list("pk", flat=True)
        )

        self.assertIn(prompt.pk, prompt_ids)
        self.assertNotIn(cmd.pk, prompt_ids)
        self.assertIn(cmd.pk, cmd_ids)
        self.assertNotIn(prompt.pk, cmd_ids)

    def test_misclassified_prompt_category_command_execution(self):
        """Static rules tagged category=prompt for OS command injection."""
        cmd = self._finding(
            rule_id="EEG-BND-ABC123",
            title=(
                "Untrusted input flows into command execution sink; "
                "enables OS command injection."
            ),
            category="prompt",
            severity="critical",
            file_path="hooks/run.sh",
            line_number=4,
            cwe="CWE-78",
        )
        prompt = self._finding(
            rule_id="openai-user-input-in-system-prompt-python",
            title="User input flows into the OpenAI system prompt (prompt injection)",
            category="prompt",
            severity="high",
            file_path="src/chat.py",
            line_number=8,
        )
        qs = SecurityFinding.objects.filter(organization=self.org)

        self.assertTrue(
            filter_findings_by_bucket(qs, "command_injection").filter(pk=cmd.pk).exists()
        )
        self.assertFalse(
            filter_findings_by_bucket(qs, "prompt_injection").filter(pk=cmd.pk).exists()
        )
        self.assertTrue(
            filter_findings_by_bucket(qs, "prompt_injection").filter(pk=prompt.pk).exists()
        )

    def test_classifier_helpers(self):
        cmd = self._finding(
            category="command_injection",
            title="subprocess call",
            rule_id="AGENT-001",
            file_path="a.py",
            line_number=1,
        )
        prompt = self._finding(
            category="prompt_injection",
            title="jailbreak",
            rule_id="prompt.jailbreak",
            file_path="b.py",
            line_number=2,
        )

        self.assertTrue(is_command_injection_finding(cmd))
        self.assertFalse(is_prompt_injection_finding(cmd))
        self.assertTrue(is_prompt_injection_finding(prompt))
        self.assertFalse(is_command_injection_finding(prompt))
        self.assertEqual(finding_matches_bucket(cmd, "command_injection"), True)
        self.assertEqual(finding_matches_bucket(cmd, "prompt_injection"), False)
