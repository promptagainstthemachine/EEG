"""Heuristics and indexes for the vulnerability relationship graph."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from apps.security.models import SecurityFinding

_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|mocks?|fixtures?|testdata)(/|$)|"
    r"(_test\.|\.test\.|\.spec\.|test_)",
    re.IGNORECASE,
)

_SEMANTIC_RULE_PREFIXES = ("EEG-SEM-", "SEM-")


def is_test_surface_path(file_path: str) -> bool:
    path = (file_path or "").strip().replace("\\", "/")
    if not path:
        return False
    return bool(_TEST_PATH_RE.search(path))


def is_semantic_rule(rule_id: str) -> bool:
    rid = (rule_id or "").upper()
    return any(rid.startswith(p) for p in _SEMANTIC_RULE_PREFIXES)


def snippet_signature(snippet: str, *, max_len: int = 120) -> str:
    """Normalized hash of matched code for clustering similar patterns."""
    raw = (snippet or "").strip().lower()
    if not raw:
        return ""
    normalized = re.sub(r"\s+", " ", raw)[:max_len]
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def location_key(file_path: str, line_number: Optional[int]) -> str:
    path = (file_path or "").strip().replace("\\", "/")
    line = 0 if line_number is None else int(line_number)
    return f"{path}:{line}"


def assess_fp_risk(
    finding: SecurityFinding,
    *,
    rules_at_line: int = 1,
    file_finding_count: int = 1,
    snippet_cluster_size: int = 1,
) -> Tuple[int, List[str]]:
    """
    Estimate false-positive likelihood (0 = likely real, 100 = likely noise).

    Used for graph styling and triage — not a verdict.
    """
    score = 0
    signals: List[str] = []

    if is_test_surface_path(finding.file_path):
        score += 38
        signals.append("test_surface")

    if rules_at_line > 1:
        score += min(30, 12 * (rules_at_line - 1))
        signals.append("multi_rule_line")

    if is_semantic_rule(finding.rule_id):
        score += 12
        signals.append("semantic_rule")

    if (finding.severity or "").lower() in ("low", "info"):
        score += 18
        signals.append("low_severity")

    if not (finding.code_snippet or "").strip():
        score += 22
        signals.append("no_snippet")

    if file_finding_count >= 4:
        score += min(20, 4 * (file_finding_count - 3))
        signals.append("file_hotspot")

    if snippet_cluster_size >= 3:
        score += min(18, 5 * (snippet_cluster_size - 2))
        signals.append("repeated_pattern")

    meta = finding.metadata if isinstance(finding.metadata, dict) else {}
    if meta.get("workflow_lines"):
        score -= 12
        signals.append("has_workflow_context")

    source = (finding.source or "").lower()
    if source and "regex" in source and is_semantic_rule(finding.rule_id):
        score += 8
        signals.append("regex_semantic_stack")

    return max(0, min(100, score)), signals


class FindingGraphIndexes:
    """Precomputed indexes over a finding batch for graph edge generation."""

    def __init__(self, findings: List[SecurityFinding]) -> None:
        self.findings = findings
        self.by_location: Dict[str, List[str]] = defaultdict(list)
        self.by_snippet: Dict[str, List[str]] = defaultdict(list)
        self.by_file: Dict[str, List[str]] = defaultdict(list)
        self.by_rule: Dict[str, List[str]] = defaultdict(list)
        self.by_fingerprint: Dict[str, List[str]] = defaultdict(list)

        for finding in findings:
            fid = f"finding:{finding.pk}"
            self.by_location[location_key(finding.file_path, finding.line_number)].append(fid)
            sig = snippet_signature(finding.code_snippet)
            if sig:
                self.by_snippet[sig].append(fid)
            fpath = (finding.file_path or "").strip()
            if fpath:
                self.by_file[fpath].append(fid)
            self.by_rule[finding.rule_id].append(fid)
            if finding.fingerprint:
                self.by_fingerprint[finding.fingerprint].append(fid)

    def rules_at_line(self, finding: SecurityFinding) -> int:
        key = location_key(finding.file_path, finding.line_number)
        return len(self.by_location.get(key, []))

    def file_finding_count(self, finding: SecurityFinding) -> int:
        fpath = (finding.file_path or "").strip()
        return len(self.by_file.get(fpath, [])) if fpath else 0

    def snippet_cluster_size(self, finding: SecurityFinding) -> int:
        sig = snippet_signature(finding.code_snippet)
        return len(self.by_snippet.get(sig, [])) if sig else 0

    def fp_assessment(self, finding: SecurityFinding) -> Tuple[int, List[str]]:
        return assess_fp_risk(
            finding,
            rules_at_line=self.rules_at_line(finding),
            file_finding_count=self.file_finding_count(finding),
            snippet_cluster_size=self.snippet_cluster_size(finding),
        )
