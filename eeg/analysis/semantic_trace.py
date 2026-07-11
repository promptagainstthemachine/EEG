"""Semantic trace engine for ai_practice_patterns (AST + light taint)."""

from __future__ import annotations

import ast
import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

from eeg.analysis.code_context import (
    bash_eval_is_real_command,
    bash_line_is_comment,
    line_is_comment_only,
    match_span_is_non_executable,
    python_docstring_lines,
)
from eeg.collector import Collector, Finding, Severity

_BUNDLE_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "rules",
    "bundles",
    "ai_practice_patterns",
)

# LLM response / untrusted content name hints
_TAINT_NAME_HINTS = frozenset({
    "response",
    "content",
    "text",
    "message",
    "output",
    "completion",
    "choice",
    "code",
    "cmd",
    "command",
    "result",
    "data",
    "body",
})

# Dangerous builtins / sinks
_PYTHON_SINK_NAMES = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
})
_PYTHON_OS_SINKS = frozenset({"system", "popen"})
_SUBPROCESS_SHELL_ATTRS = frozenset({"run", "call", "Popen", "check_output"})

# Attribute tails that indicate LLM API calls (source)
_LLM_CALL_TAILS: Tuple[Tuple[str, ...], ...] = (
    ("chat", "completions", "create"),
    ("messages", "create"),
    ("generate_content",),
    ("chat",),
    ("completions", "create"),
)

_LANGCHAIN_SOURCE_NAMES = frozenset({
    "PythonREPL",
    "BashProcess",
    "PythonAstREPLTool",
})


@dataclass
class SemanticRule:
    rule_id: str
    message: str
    severity: Severity
    languages: List[str]
    mode: str  # taint | pattern | pattern-either | audit
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    source_file: str = ""


def _severity_map(raw: Optional[str]) -> Severity:
    if not raw:
        return Severity.MEDIUM
    key = str(raw).upper()
    if key in ("ERROR", "CRITICAL"):
        return Severity.CRITICAL
    if key in ("WARNING", "WARN"):
        return Severity.HIGH
    if key == "INFO":
        return Severity.INFO
    if key == "LOW":
        return Severity.LOW
    return Severity.MEDIUM


def _rule_uid(path: str, idx: int) -> str:
    digest = hashlib.sha256(f"{path}\0{idx}".encode()).hexdigest()[:10].upper()
    return f"EEG-SEM-{digest}"


def _collect_pattern_strings(obj: Any, out: List[str]) -> None:
    if isinstance(obj, dict):
        for key in ("pattern", "pattern-regex"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                out.append(val.strip())
        if "patterns" in obj and isinstance(obj["patterns"], list):
            for item in obj["patterns"]:
                _collect_pattern_strings(item, out)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _collect_pattern_strings(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_pattern_strings(item, out)


def load_semantic_rules(bundle_root: str = _BUNDLE_ROOT) -> List[SemanticRule]:
    """Load ai_practice rules that need AST/taint (skip pure pattern-regex rows)."""
    rules: List[SemanticRule] = []
    if not os.path.isdir(bundle_root):
        return rules

    for dirpath, _, filenames in os.walk(bundle_root):
        if "_test_fixtures" in dirpath:
            continue
        for fname in filenames:
            if not fname.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, bundle_root)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    doc = yaml.safe_load(handle) or {}
            except (OSError, yaml.YAMLError):
                continue
            for idx, raw in enumerate(doc.get("rules") or []):
                if not isinstance(raw, dict):
                    continue
                mode = str(raw.get("mode", "audit"))
                sources: List[str] = []
                for ps in raw.get("pattern-sources") or []:
                    if isinstance(ps, str):
                        sources.append(ps)
                    elif isinstance(ps, dict) and ps.get("pattern"):
                        sources.append(str(ps["pattern"]))

                sinks: List[str] = []
                for block in raw.get("pattern-sinks") or []:
                    _collect_pattern_strings(block, sinks)

                patterns: List[str] = []
                if raw.get("pattern"):
                    patterns.append(str(raw["pattern"]))
                pe = raw.get("pattern-either")
                if isinstance(pe, list):
                    for item in pe:
                        if isinstance(item, dict) and item.get("pattern"):
                            patterns.append(str(item["pattern"]))
                        elif isinstance(item, str):
                            patterns.append(item)

                # Skip rules that are only pattern-regex (handled by boundary pack with filtering)
                regex_only = _walk_has_only_regex(raw)
                if regex_only and mode != "taint" and not patterns and not sinks:
                    continue

                if mode != "taint" and not patterns and not sinks:
                    continue

                msg = raw.get("message") or raw.get("id") or "Semantic rule matched"
                rules.append(
                    SemanticRule(
                        rule_id=str(raw.get("id") or _rule_uid(rel, idx)),
                        message=str(msg).strip().split("\n", 1)[0][:500],
                        severity=_severity_map(raw.get("severity")),
                        languages=list(raw.get("languages") or ["python"]),
                        mode=mode,
                        sources=sources,
                        sinks=sinks,
                        patterns=patterns,
                        cwe=(raw.get("metadata") or {}).get("cwe") if isinstance(raw.get("metadata"), dict) else None,
                        source_file=rel,
                    )
                )
    return rules


def _walk_has_only_regex(obj: Any) -> bool:
    if isinstance(obj, dict):
        if obj.get("pattern-regex"):
            return True
        if obj.get("pattern") or obj.get("pattern-sources") or obj.get("pattern-sinks"):
            return False
        return all(_walk_has_only_regex(v) for v in obj.values() if v is not None)
    if isinstance(obj, list):
        return bool(obj) and all(_walk_has_only_regex(i) for i in obj)
    return False


def _attr_chain(node: ast.AST) -> List[str]:
    parts: List[str] = []
    cur: Optional[ast.AST] = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return list(reversed(parts))


def _chain_matches_tails(chain: List[str], tails: Tuple[Tuple[str, ...], ...]) -> bool:
    if not chain:
        return False
    for tail in tails:
        if len(chain) >= len(tail) and chain[-len(tail) :] == list(tail):
            return True
    return False


def _is_llm_api_call(node: ast.Call) -> bool:
    chain = _attr_chain(node.func)
    return _chain_matches_tails(chain, _LLM_CALL_TAILS)


def _is_langchain_source_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id in _LANGCHAIN_SOURCE_NAMES:
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr in _LANGCHAIN_SOURCE_NAMES:
        return True
    return False


def _name_hints_taint(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _TAINT_NAME_HINTS)


class _TaintState:
    def __init__(self) -> None:
        self.tainted: Set[str] = set()

    def mark(self, name: str) -> None:
        if name:
            self.tainted.add(name)

    def is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted or _name_hints_taint(node.id)
        if isinstance(node, ast.Attribute):
            if _name_hints_taint(node.attr):
                return True
            return self.is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self.is_tainted(node.value)
        if isinstance(node, ast.Call):
            return self.is_tainted(node.func)
        return False


class _PythonSemanticVisitor(ast.NodeVisitor):
    def __init__(
        self,
        source: str,
        rel_path: str,
        rules: List[SemanticRule],
        doc_lines: Set[int],
    ) -> None:
        self.source = source
        self.rel_path = rel_path
        self.rules = [r for r in rules if "python" in r.languages]
        self.doc_lines = doc_lines
        self.findings: List[Dict[str, Any]] = []
        self.taint = _TaintState()
        self._lines = source.splitlines()

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()[:200]
        return ""

    def _add(self, rule: SemanticRule, lineno: int) -> None:
        if lineno in self.doc_lines or line_is_comment_only(self.source, lineno):
            return
        self.findings.append(
            {
                "rule_id": f"EEG-SEM-{rule.rule_id}",
                "severity": rule.severity.value,
                "category": "ai_practice",
                "file_path": self.rel_path,
                "line_number": lineno,
                "code_snippet": self._snippet(lineno),
                "message": rule.message,
                "recommendation": rule.message,
                "cwe": rule.cwe,
            }
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        is_source = isinstance(value, ast.Call) and (
            _is_llm_api_call(value) or _is_langchain_source_call(value)
        )
        value_tainted = is_source or self.taint.is_tainted(value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if value_tainted or _name_hints_taint(target.id):
                    self.taint.mark(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name) and value_tainted:
                        self.taint.mark(elt.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in _PYTHON_SINK_NAMES:
            self._check_sink(node, node.func.id)
        elif isinstance(node.func, ast.Attribute):
            base = _attr_chain(node.func)
            if len(base) >= 2 and base[-2] == "os" and base[-1] in _PYTHON_OS_SINKS:
                self._check_sink(node, f"os.{base[-1]}")
            elif base and base[0] == "subprocess" and base[-1] in _SUBPROCESS_SHELL_ATTRS:
                if self._call_has_shell_true(node):
                    self._check_sink(node, f"subprocess.{base[-1]}")
        self.generic_visit(node)

    def _call_has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _check_sink(self, node: ast.Call, sink_name: str) -> None:
        if not node.args:
            return
        arg0 = node.args[0]
        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
            return  # literal code string — not LLM-tainted execution in practice
        if not self.taint.is_tainted(arg0):
            return
        for rule in self.rules:
            if rule.mode == "taint":
                self._add(rule, node.lineno)
                return

    def visit_Expr(self, node: ast.Expr) -> None:
        # LangChain source used as expression statement
        if isinstance(node.value, ast.Call) and _is_langchain_source_call(node.value):
            for rule in self.rules:
                if rule.mode == "taint" and any("PythonREPL" in s or "BashProcess" in s for s in rule.sources):
                    self._add(rule, node.lineno)
        self.generic_visit(node)


def _analyze_python(
    source: str,
    rel_path: str,
    rules: List[SemanticRule],
) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return []
    doc_lines = python_docstring_lines(tree)
    visitor = _PythonSemanticVisitor(source, rel_path, rules, doc_lines)
    visitor.visit(tree)
    return visitor.findings


def _analyze_bash(source: str, rel_path: str, rules: List[SemanticRule]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    bash_rules = [r for r in rules if "bash" in r.languages]
    if not bash_rules:
        return findings

    for lineno, line in enumerate(source.splitlines(), start=1):
        if bash_line_is_comment(line):
            continue
        for rule in bash_rules:
            for pat in rule.patterns:
                if "eval" in pat or "exec" in pat:
                    if bash_eval_is_real_command(line):
                        findings.append(
                            {
                                "rule_id": f"EEG-SEM-{rule.rule_id}",
                                "severity": rule.severity.value,
                                "category": "ai_practice",
                                "file_path": rel_path,
                                "line_number": lineno,
                                "code_snippet": line.strip()[:200],
                                "message": rule.message,
                                "recommendation": rule.message,
                                "cwe": rule.cwe,
                            }
                        )
                        break
    return findings


class AiPracticeSemanticEngine:
    """Run semantic / taint analysis for ai_practice_patterns bundle."""

    def __init__(self, bundle_root: str = _BUNDLE_ROOT) -> None:
        self.rules = load_semantic_rules(bundle_root)

    def scan_file(
        self,
        file_path: str,
        rel_path: str,
        extension: str,
    ) -> List[Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                source = handle.read()
        except OSError:
            return []

        if extension == ".py":
            return _analyze_python(source, rel_path, self.rules)
        if extension in (".sh", ".bash"):
            return _analyze_bash(source, rel_path, self.rules)
        return []

    def scan_files(self, files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings: List[Dict[str, Any]] = []
        for finfo in files:
            path = finfo.get("file_path")
            if not path:
                continue
            ext = finfo.get("extension") or os.path.splitext(path)[1].lower()
            rel = finfo.get("relative_path") or path
            all_findings.extend(self.scan_file(path, rel, ext))
        return all_findings

    def scan_to_collector(self, files: List[Dict[str, Any]], collector: Collector, cloud_env: str = "any") -> None:
        for finding in self.scan_files(files):
            sev = _severity_map(finding.get("severity"))
            collector.add_finding(
                Finding(
                    rule_id=finding["rule_id"],
                    severity=sev,
                    category=finding.get("category", "ai_practice"),
                    cloud_env=cloud_env,
                    file_path=finding["file_path"],
                    line_number=finding.get("line_number") or 0,
                    code_snippet=finding.get("code_snippet", ""),
                    message=finding["message"],
                    recommendation=finding.get("recommendation", ""),
                    cwe=finding.get("cwe"),
                    owasp_llm=None,
                )
            )
