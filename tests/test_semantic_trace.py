"""Tests for semantic AI practice pattern analysis."""

from __future__ import annotations

import os
import tempfile
import unittest

from eeg.analysis.code_context import match_span_is_non_executable
from eeg.analysis.semantic_trace import AiPracticeSemanticEngine


_FIXTURES = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "eeg",
    "rules",
    "bundles",
    "ai_practice_patterns",
    "_test_fixtures",
)


class TestCodeContext(unittest.TestCase):
    def test_eval_in_docstring_not_executable(self) -> None:
        source = '''"""Never use eval() in production."""
x = 1
'''
        # eval() inside docstring
        idx = source.index("eval")
        self.assertTrue(match_span_is_non_executable(source, idx, idx + 3))

    def test_eval_call_is_executable(self) -> None:
        source = "code = 'print(1)'\neval(code)\n"
        idx = source.index("eval(code)")
        self.assertFalse(match_span_is_non_executable(source, idx, idx + len("eval(code)")))


class TestSemanticTrace(unittest.TestCase):
    def test_llm_output_fixture_detects_tainted_exec(self) -> None:
        path = os.path.join(_FIXTURES, "llm-output-to-exec", "llm-output-to-exec-python.py")
        if not os.path.isfile(path):
            self.skipTest("fixture missing")
        engine = AiPracticeSemanticEngine()
        findings = engine.scan_file(path, "llm-output-to-exec-python.py", ".py")
        rule_ids = {f["rule_id"] for f in findings}
        self.assertTrue(
            any("llm-output-to-exec" in rid.lower() or "SEM" in rid for rid in rule_ids),
            msg=f"findings: {findings}",
        )
        lines = {f["line_number"] for f in findings}
        self.assertIn(10, lines)  # eval(code)
        self.assertIn(16, lines)  # exec(code)

    def test_docstring_mentioning_eval_no_finding(self) -> None:
        source = '''def safe_docs():
    """Documentation: do not call eval() or exec() on user input."""
    return 42
'''
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as handle:
            handle.write(source)
            path = handle.name
        try:
            engine = AiPracticeSemanticEngine()
            findings = engine.scan_file(path, "safe_docs.py", ".py")
            exec_eval_lines = [
                f["line_number"]
                for f in findings
                if "eval" in f.get("code_snippet", "").lower()
                and "exec" in f.get("code_snippet", "").lower()
            ]
            self.assertEqual(exec_eval_lines, [], msg=f"unexpected: {findings}")
        finally:
            os.unlink(path)

    def test_comment_mentioning_exec_no_finding(self) -> None:
        source = "# See also: exec() and eval() in the Python docs\nprint('ok')\n"
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as handle:
            handle.write(source)
            path = handle.name
        try:
            engine = AiPracticeSemanticEngine()
            findings = engine.scan_file(path, "comment.py", ".py")
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
