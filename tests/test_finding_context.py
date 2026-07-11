"""Tests for finding code workflow context."""

from __future__ import annotations

import tempfile
from pathlib import Path

from django.test import TestCase

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.security.finding_context import (
    _safe_file_under_root,
    build_finding_code_context,
    build_workflow_metadata,
    build_workflow_snippet,
)
from apps.security.models import SecurityFinding


class FindingContextTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / "code" / "lambdas" / "handler.py"
        self.target.parent.mkdir(parents=True)
        lines = []
        for i in range(1, 41):
            if i == 20:
                lines.append("    result = eval(user_input)")
            else:
                lines.append(f"    line_{i} = {i}")
        self.target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.rel = "code/lambdas/handler.py"
        self.lineno = 20

    def tearDown(self):
        self.tmp.cleanup()

    def test_safe_file_under_root_finds_nested_path(self):
        root = str(self.root)
        self.assertIsNotNone(_safe_file_under_root(root, self.rel))
        code_root = str(self.root / "code")
        self.assertIsNotNone(_safe_file_under_root(code_root, self.rel))

    def test_build_workflow_metadata_includes_scan_root(self):
        meta = build_workflow_metadata(str(self.root), self.rel, self.lineno)
        self.assertIn("workflow_lines", meta)
        self.assertIn("scan_root", meta)
        self.assertGreater(len(meta["workflow_lines"]), 5)
        hits = [r for r in meta["workflow_lines"] if r.get("highlight")]
        self.assertEqual(len(hits), 1)
        self.assertIn("eval", hits[0]["text"])

    def test_build_workflow_snippet_multiline(self):
        snippet = build_workflow_snippet(str(self.root), self.rel, self.lineno)
        self.assertIn("\n", snippet)
        self.assertIn("eval", snippet)

    def test_legacy_exec_snippet_not_shown_as_workflow(self):
        org = Organization.objects.create(name="Ctx Org", slug="ctx-org")
        project = Project.objects.create(
            organization=org,
            name="P",
            slug="p",
            local_path="/nonexistent",
        )
        finding = SecurityFinding.objects.create(
            organization=org,
            project=project,
            rule_id="TEST",
            title="Test",
            severity="high",
            file_path="missing.py",
            line_number=10,
            code_snippet="exec",
        )
        ctx = build_finding_code_context(finding, persist_backfill=False)
        self.assertEqual(ctx["workflow_lines"], [])
        self.assertTrue(ctx["has_matched_snippet"])
        self.assertEqual(len(ctx["matched_lines"]), 1)

    def test_absolute_file_path_resolves_under_root(self):
        org = Organization.objects.create(name="Abs Org", slug="abs-org")
        project = Project.objects.create(
            organization=org,
            name="P",
            slug="p",
            local_path=str(self.root),
        )
        abs_path = str(self.target)
        finding = SecurityFinding.objects.create(
            organization=org,
            project=project,
            rule_id="ABS-PATH",
            title="Test",
            severity="high",
            file_path=abs_path,
            line_number=self.lineno,
            code_snippet="exec",
        )
        ctx = build_finding_code_context(finding, persist_backfill=False)
        self.assertTrue(ctx["has_full_workflow"])
        self.assertGreater(len(ctx["workflow_lines"]), 5)

    def test_backfill_from_local_path_on_read(self):
        org = Organization.objects.create(name="Ctx Org 2", slug="ctx-org-2")
        project = Project.objects.create(
            organization=org,
            name="P2",
            slug="p2",
            local_path=str(self.root),
        )
        finding = SecurityFinding.objects.create(
            organization=org,
            project=project,
            rule_id="AGENT-001",
            title="Command Injection",
            severity="critical",
            file_path=self.rel,
            line_number=self.lineno,
            code_snippet="exec",
        )
        ctx = build_finding_code_context(finding, persist_backfill=True)
        self.assertGreater(len(ctx["workflow_lines"]), 5)
        finding.refresh_from_db()
        self.assertGreater(len(finding.metadata.get("workflow_lines", [])), 5)
        self.assertIn("\n", finding.code_snippet)
