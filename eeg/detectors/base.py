"""
EEG - Base Detector
Abstract base class for all security detectors. Loads rules from YAML and
provides AST + regex scanning primitives.
"""

import ast
import os
import re
import yaml
from typing import List, Dict, Optional, Set

from eeg.collector import Collector, Finding, Severity

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


class BaseDetector:
    """Base class for all category-specific detectors."""

    name: str = "base"
    category: str = "base"

    def __init__(self, cloud_env: str):
        self.cloud_env = cloud_env
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict]:
        rule_file = os.path.join(RULES_DIR, self.cloud_env, "rule.yaml")
        if not os.path.isfile(rule_file):
            return []
        with open(rule_file, "r") as f:
            data = yaml.safe_load(f)
        all_rules = data.get("rules", [])
        return [r for r in all_rules if r.get("category") == self.category]

    def scan(self, files: List[Dict], collector: Collector):
        """Run all loaded rules against the provided files."""
        print(f"  [{self.name.upper()}] Scanning {len(files)} files with {len(self.rules)} rules...")
        for rule in self.rules:
            self._run_rule(rule, files, collector)

    def _run_rule(self, rule: Dict, files: List[Dict], collector: Collector):
        patterns = rule.get("patterns", [])
        for pattern_def in patterns:
            ptype = pattern_def.get("type", "regex")
            file_types = set(pattern_def.get("file_types", []))

            matching_files = [
                f for f in files if f["extension"] in file_types
            ] if file_types else files

            if ptype == "regex":
                self._scan_regex(rule, pattern_def, matching_files, collector)
            elif ptype == "ast":
                self._scan_ast(rule, pattern_def, matching_files, collector)
            # regex_absent is handled at file or block level
            elif ptype == "regex_absent":
                self._scan_regex_absent(rule, pattern_def, matching_files, collector)

    def _scan_regex(self, rule: Dict, pattern_def: Dict, files: List[Dict], collector: Collector):
        regex_str = pattern_def.get("match", "")
        try:
            compiled = re.compile(regex_str)
        except re.error:
            return

        for finfo in files:
            try:
                content = self._read_file(finfo["file_path"])
            except Exception:
                continue

            for line_num, line in enumerate(content.splitlines(), start=1):
                if compiled.search(line):
                    collector.add_finding(Finding(
                        rule_id=rule["id"],
                        severity=Severity[rule.get("severity", "MEDIUM")],
                        category=rule.get("category", self.category),
                        cloud_env=self.cloud_env,
                        file_path=finfo["relative_path"],
                        line_number=line_num,
                        code_snippet=line.strip()[:200],
                        message=rule["name"],
                        recommendation=rule.get("recommendation", ""),
                        cwe=rule.get("cwe"),
                        owasp_llm=rule.get("owasp_llm"),
                    ))

    def _scan_ast(self, rule: Dict, pattern_def: Dict, files: List[Dict], collector: Collector):
        """AST-based scanning for Python files — detects f-string injection into prompts."""
        match_type = pattern_def.get("match", "")
        contexts = pattern_def.get("context", [])
        py_files = [f for f in files if f["extension"] == ".py"]

        for finfo in py_files:
            try:
                source = self._read_file(finfo["file_path"])
                tree = ast.parse(source, filename=finfo["file_path"])
            except (SyntaxError, Exception):
                continue

            if match_type == "fstring_in_prompt":
                self._check_fstring_in_prompt(tree, source, finfo, rule, contexts, collector)

    def _check_fstring_in_prompt(self, tree, source: str, finfo: Dict,
                                  rule: Dict, contexts: List[str], collector: Collector):
        """Detect f-strings or .format() used in assignments that match prompt-related contexts."""
        source_lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = self._get_name(target)
                    if not target_name:
                        continue
                    if not any(ctx.lower() in target_name.lower() for ctx in contexts):
                        continue
                    # Check if value is an f-string (JoinedStr)
                    if isinstance(node.value, ast.JoinedStr):
                        line_num = node.lineno
                        snippet = source_lines[line_num - 1].strip() if line_num <= len(source_lines) else ""
                        collector.add_finding(Finding(
                            rule_id=rule["id"],
                            severity=Severity[rule.get("severity", "MEDIUM")],
                            category=rule.get("category", self.category),
                            cloud_env=self.cloud_env,
                            file_path=finfo["relative_path"],
                            line_number=line_num,
                            code_snippet=snippet[:200],
                            message=rule["name"],
                            recommendation=rule.get("recommendation", ""),
                            cwe=rule.get("cwe"),
                            owasp_llm=rule.get("owasp_llm"),
                        ))

            # Check for .format() calls on prompt-like variables
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    if isinstance(node.func.value, ast.Name):
                        var_name = node.func.value.id
                        if any(ctx.lower() in var_name.lower() for ctx in contexts):
                            line_num = node.lineno
                            snippet = source_lines[line_num - 1].strip() if line_num <= len(source_lines) else ""
                            collector.add_finding(Finding(
                                rule_id=rule["id"],
                                severity=Severity[rule.get("severity", "MEDIUM")],
                                category=rule.get("category", self.category),
                                cloud_env=self.cloud_env,
                                file_path=finfo["relative_path"],
                                line_number=line_num,
                                code_snippet=snippet[:200],
                                message=rule["name"],
                                recommendation=rule.get("recommendation", ""),
                                cwe=rule.get("cwe"),
                                owasp_llm=rule.get("owasp_llm"),
                            ))

    # Cloud AI SDK relevance indicators — only check regex_absent in files containing these
    AI_RELEVANCE_PATTERNS = {
        "aws": re.compile(r'bedrock|sagemaker|boto3|invoke_model|invoke_agent|guardrail|knowledge_base|foundation.model', re.IGNORECASE),
        "azure": re.compile(r'openai|cognitive|azure\.ai|AzureOpenAI|foundry|content_safety|azure\.identity|azure\.mgmt', re.IGNORECASE),
        "gcp": re.compile(r'vertexai|vertex_ai|aiplatform|generativeai|GenerativeModel|generate_content|gemini', re.IGNORECASE),
    }

    def _scan_regex_absent(self, rule: Dict, pattern_def: Dict, files: List[Dict], collector: Collector):
        """Flag files where an expected pattern is absent, but ONLY in AI-relevant files."""
        regex_str = pattern_def.get("match", "")
        scope = pattern_def.get("scope", "file")

        try:
            compiled = re.compile(regex_str, re.IGNORECASE)
        except re.error:
            return

        relevance_re = self.AI_RELEVANCE_PATTERNS.get(self.cloud_env)

        for finfo in files:
            try:
                content = self._read_file(finfo["file_path"])
            except Exception:
                continue

            # Only check absence in files that actually contain AI-related code
            if relevance_re and not relevance_re.search(content):
                continue

            if scope == "file" and not compiled.search(content):
                collector.add_finding(Finding(
                    rule_id=rule["id"],
                    severity=Severity[rule.get("severity", "MEDIUM")],
                    category=rule.get("category", self.category),
                    cloud_env=self.cloud_env,
                    file_path=finfo["relative_path"],
                    line_number=0,
                    code_snippet="",
                    message=f"{rule['name']} — pattern not found in file",
                    recommendation=rule.get("recommendation", ""),
                    cwe=rule.get("cwe"),
                    owasp_llm=rule.get("owasp_llm"),
                ))

    @staticmethod
    def _get_name(node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    @staticmethod
    def _read_file(path: str) -> str:
        with open(path, "r", errors="ignore") as f:
            return f.read()
