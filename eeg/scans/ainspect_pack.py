"""Ainspect pack — static checks from EEG-native OWASP / MCP / LangChain YAML.

Rules live under ``eeg/rules/bundles/ainspect_builtin/``. This scan evaluates regex
and simple substring (python_ast ``match`` list) clauses only; complex
detections remain covered by ``agent_forensics`` and dedicated detectors.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from eeg.scans import BaseScan, ScanResult, ScanRegistry

BUNDLE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "rules", "bundles", "ainspect_builtin"
)


def _rule_entries_from_doc(data: Any, source_file: str) -> List[Dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    rules = data.get("rules")
    if not isinstance(rules, list):
        return []
    out: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        if not rid:
            continue
        out.append(
            {
                "source_yaml": source_file,
                "id": str(rid),
                "title": str(r.get("title", "") or "")[:500],
                "severity": str(r.get("severity", "medium") or "medium").lower(),
                "category": str(r.get("category", "ainspect") or "ainspect"),
                "cwe_id": r.get("cwe_id"),
                "owasp_agentic_id": r.get("owasp_agentic_id"),
                "detection": r.get("detection") or {},
            }
        )
    return out


def _extract_regex_patterns(detection: Any) -> List[re.Pattern[str]]:
    if not isinstance(detection, dict):
        return []
    patterns_block = detection.get("patterns")
    if not isinstance(patterns_block, list):
        return []
    compiled: List[re.Pattern[str]] = []
    for block in patterns_block:
        if not isinstance(block, dict):
            continue
        if block.get("type") != "regex":
            continue
        raw_list = block.get("patterns")
        if not isinstance(raw_list, list):
            continue
        for pat in raw_list:
            if not isinstance(pat, str) or not pat.strip():
                continue
            try:
                compiled.append(re.compile(pat))
            except re.error:
                continue
    return compiled


def _extract_python_ast_strings(detection: Any) -> List[str]:
    if not isinstance(detection, dict):
        return []
    patterns_block = detection.get("patterns")
    if not isinstance(patterns_block, list):
        return []
    needles: List[str] = []
    for block in patterns_block:
        if not isinstance(block, dict):
            continue
        if block.get("type") != "python_ast":
            continue
        m = block.get("match")
        if isinstance(m, list):
            for item in m:
                if isinstance(item, str) and item.strip():
                    needles.append(item)
    return needles


def _load_ainspect_rules() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (regex_rules, py_substring_rules)."""
    regex_rules: List[Dict[str, Any]] = []
    py_rules: List[Dict[str, Any]] = []

    if not os.path.isdir(BUNDLE_DIR):
        return regex_rules, py_rules

    for fname in sorted(os.listdir(BUNDLE_DIR)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        fpath = os.path.join(BUNDLE_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            continue

        for meta in _rule_entries_from_doc(data, fname):
            det = meta["detection"]
            rx = _extract_regex_patterns(det)
            if rx:
                regex_rules.append({**meta, "_patterns": rx})
            subs = _extract_python_ast_strings(det)
            if subs:
                py_rules.append({**meta, "_needles": subs})

    return regex_rules, py_rules


@ScanRegistry.register
class AinspectPackScan(BaseScan):
    """OWASP / LangChain / MCP YAML rules (regex + AST name hits)."""

    scan_id = "ainspect_pack"
    scan_type = "static"
    description = "Ainspect YAML pack (regex + python_ast substring heuristics)"
    categories = ["agent", "owasp", "mcp", "langchain", "supply_chain"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._regex_rules, self._py_rules = _load_ainspect_rules()

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        from eeg.utils.repocrawler import RepoCrawler

        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        crawler = RepoCrawler(str(target_path))
        files = crawler.crawl()

        for finfo in files:
            files_scanned += 1
            fpath = finfo.get("file_path")
            rel_path = finfo.get("relative_path", fpath)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            is_py = str(rel_path).lower().endswith(".py")

            for rule in self._regex_rules:
                for pat in rule["_patterns"]:
                    m = pat.search(content)
                    if m:
                        line_num = content[: m.start()].count("\n") + 1
                        findings.append(
                            {
                                "rule_id": rule["id"],
                                "severity": rule["severity"].upper(),
                                "category": rule["category"],
                                "file_path": rel_path,
                                "line_number": line_num,
                                "message": rule["title"],
                                "source_pack": rule["source_yaml"],
                                "cwe_id": rule.get("cwe_id"),
                                "owasp_agentic_id": rule.get("owasp_agentic_id"),
                                "matched": m.group(0)[:200],
                            }
                        )
                        break

            if is_py:
                for rule in self._py_rules:
                    for needle in rule["_needles"]:
                        if needle in content:
                            idx = content.index(needle)
                            line_num = content[:idx].count("\n") + 1
                            findings.append(
                                {
                                    "rule_id": rule["id"],
                                    "severity": rule["severity"].upper(),
                                    "category": rule["category"],
                                    "file_path": rel_path,
                                    "line_number": line_num,
                                    "message": rule["title"],
                                    "source_pack": rule["source_yaml"],
                                    "cwe_id": rule.get("cwe_id"),
                                    "owasp_agentic_id": rule.get("owasp_agentic_id"),
                                    "matched": needle[:200],
                                }
                            )
                            break

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            s = str(f.get("severity", "MEDIUM")).upper()
            if s in sev_counts:
                sev_counts[s] += 1

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={
                "files_scanned": files_scanned,
                "total_findings": len(findings),
                "by_severity": sev_counts,
                "yaml_rules_dir": BUNDLE_DIR,
                "regex_rule_defs": len(self._regex_rules),
                "python_ast_rule_defs": len(self._py_rules),
            },
            metadata={"source": "eeg.rules.bundles.ainspect_builtin"},
        )
