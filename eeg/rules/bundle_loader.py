"""Load EEG-import bundle YAML rules (patterns, match_mode, targets).

Used by AgentForensicsScan and catalog validation. Supports:
- ``patterns``: list of regex strings or ``{type: regex, value: ...}`` dicts
- ``match_mode``: ``all`` (default) or ``any``
- ``targets``: fnmatch globs on relative file paths
- ``exclude_patterns``: regex strings applied to file content before matching
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

import yaml

BUNDLES_ROOT = os.path.join(os.path.dirname(__file__), "bundles")

_FILE_TYPE_EXT: Dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "bash": (".sh", ".bash"),
    "markdown": (".md",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "text": (".txt",),
    "json": (".json",),
    "yaml": (".yaml", ".yml"),
}


@dataclass
class EegImportRule:
    """Executable row from a single EEG-import YAML file."""

    rule_id: str
    title: str
    category: str
    severity: str
    patterns: List[re.Pattern[str]] = field(default_factory=list)
    exclude_patterns: List[re.Pattern[str]] = field(default_factory=list)
    match_mode: str = "all"
    targets: List[str] = field(default_factory=list)
    file_extensions: Optional[set[str]] = None
    remediation: str = ""
    source_file: str = ""
    bundle_name: str = ""


def _compile_regex(value: str) -> Optional[re.Pattern[str]]:
    try:
        return re.compile(value, re.MULTILINE)
    except re.error:
        return None


def _pattern_strings_from_entry(entry: Any) -> List[str]:
    if isinstance(entry, str) and entry.strip():
        return [entry.strip()]
    if isinstance(entry, dict):
        ptype = str(entry.get("type", "regex")).lower()
        if ptype != "regex":
            return []
        val = entry.get("value")
        if isinstance(val, str) and val.strip():
            return [val.strip()]
    return []


def _compile_pattern_list(raw: Any) -> List[re.Pattern[str]]:
    if not isinstance(raw, list):
        return []
    compiled: List[re.Pattern[str]] = []
    for entry in raw:
        for text in _pattern_strings_from_entry(entry):
            rx = _compile_regex(text)
            if rx is not None:
                compiled.append(rx)
    return compiled


def _extensions_from_file_types(file_types: Any) -> Optional[set[str]]:
    if not isinstance(file_types, list) or not file_types:
        return None
    exts: set[str] = set()
    for ft in file_types:
        mapped = _FILE_TYPE_EXT.get(str(ft).lower())
        if mapped:
            exts.update(mapped)
    return exts or None


def _rule_id_from_doc(data: Dict[str, Any], fname: str) -> str:
    uid = data.get("eeg_rule_uid")
    if isinstance(uid, str) and uid.strip():
        slug = uid.rsplit(".", 1)[-1].upper().replace("-", "_")[:24]
        return f"EEG-{slug}"
    ext = data.get("external_source") or {}
    if isinstance(ext, dict) and ext.get("original_id"):
        return f"EEG-{ext['original_id']}"
    stem = os.path.splitext(fname)[0].split("-")[0].upper()[:20]
    return f"EEG-{stem}"


def _parse_eeg_import_file(
    abs_path: str,
    bundle_name: str,
) -> Optional[EegImportRule]:
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return None

    if not isinstance(data, dict):
        return None

    patterns = _compile_pattern_list(data.get("patterns"))
    if not patterns:
        return None

    fname = os.path.basename(abs_path)
    targets = data.get("targets")
    target_list = [str(t) for t in targets] if isinstance(targets, list) else []

    match_mode = str(data.get("match_mode", "all")).lower()
    if match_mode not in ("all", "any"):
        match_mode = "all"

    return EegImportRule(
        rule_id=_rule_id_from_doc(data, fname),
        title=str(data.get("title", "") or "")[:500],
        category=str(data.get("category", bundle_name)),
        severity=str(data.get("severity_default", "medium")).upper(),
        patterns=patterns,
        exclude_patterns=_compile_pattern_list(data.get("exclude_patterns")),
        match_mode=match_mode,
        targets=target_list,
        file_extensions=_extensions_from_file_types(data.get("file_types")),
        remediation=str(data.get("remediation", "") or "")[:2000],
        source_file=os.path.relpath(abs_path, os.path.join(BUNDLES_ROOT, bundle_name)),
        bundle_name=bundle_name,
    )


def load_eeg_import_bundle(bundle_name: str) -> List[EegImportRule]:
    """Load all EEG-import YAML rules from a bundle directory."""
    bundle_dir = os.path.join(BUNDLES_ROOT, bundle_name)
    if not os.path.isdir(bundle_dir):
        return []

    rules: List[EegImportRule] = []
    for fname in sorted(os.listdir(bundle_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        row = _parse_eeg_import_file(os.path.join(bundle_dir, fname), bundle_name)
        if row is not None:
            rules.append(row)
    return rules


def path_matches_targets(rel_path: str, targets: Sequence[str]) -> bool:
    """Return True if rel_path matches any target glob (or targets is empty)."""
    if not targets:
        return True
    norm = rel_path.replace("\\", "/")
    base = os.path.basename(norm)
    for pat in targets:
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(base, pat):
            return True
    return False


def path_matches_extensions(rel_path: str, extensions: Optional[set[str]]) -> bool:
    if extensions is None:
        return True
    ext = os.path.splitext(rel_path)[1].lower()
    return ext in extensions


def content_excluded(content: str, exclude_patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(rx.search(content) for rx in exclude_patterns)


def rule_matches_content(rule: EegImportRule, content: str) -> Optional[re.Match[str]]:
    """Return first match if rule fires on content, else None."""
    if content_excluded(content, rule.exclude_patterns):
        return None

    if rule.match_mode == "any":
        for rx in rule.patterns:
            m = rx.search(content)
            if m is not None:
                return m
        return None

    last_match: Optional[re.Match[str]] = None
    for rx in rule.patterns:
        m = rx.search(content)
        if m is None:
            return None
        last_match = m
    return last_match


@dataclass
class AegisRule:
    """Aegis aggregate YAML rule (path or content scoped)."""

    rule_id: str
    name: str
    pattern: re.Pattern[str]
    path_only: bool
    category: str
    risk: str
    reason: str


def _aegis_path_only(pattern: str) -> bool:
    """Heuristic: path-scoped rules should not scan full file content."""
    if re.search(r"[\\/]", pattern):
        return True
    if pattern.endswith("$") and ("\\." in pattern or "/" in pattern):
        return True
    return False


def load_aegis_rules() -> List[AegisRule]:
    """Load aegis_rules bundle (top-level ``rules:`` list with ``pattern`` strings)."""
    aegis_dir = os.path.join(BUNDLES_ROOT, "aegis_rules")
    if not os.path.isdir(aegis_dir):
        return []

    rules: List[AegisRule] = []
    for fname in sorted(os.listdir(aegis_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(aegis_dir, fname), "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            continue

        category = data.get("category", fname.replace(".yaml", ""))
        for rule in data.get("rules", []):
            if not isinstance(rule, dict) or not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                continue
            compiled = _compile_regex(pattern)
            if compiled is None:
                continue
            rules.append(
                AegisRule(
                    rule_id=f"EEG-AEGIS-{rule.get('id', 'UNKNOWN')}",
                    name=str(rule.get("name", "")),
                    pattern=compiled,
                    path_only=_aegis_path_only(pattern),
                    category=str(category),
                    risk=str(rule.get("risk", "medium")).upper(),
                    reason=str(rule.get("reason", "")),
                )
            )
    return rules


def scan_eeg_import_rules(
    rules: Sequence[EegImportRule],
    rel_path: str,
    content: str,
) -> List[Dict[str, Any]]:
    """Evaluate EEG-import rules against one file; return finding dicts."""
    findings: List[Dict[str, Any]] = []
    for rule in rules:
        if not path_matches_targets(rel_path, rule.targets):
            continue
        if not path_matches_extensions(rel_path, rule.file_extensions):
            continue
        match = rule_matches_content(rule, content)
        if match is None:
            continue
        line_num = content[: match.start()].count("\n") + 1
        findings.append(
            {
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "category": rule.category,
                "file_path": rel_path,
                "line_number": line_num,
                "message": rule.title,
                "recommendation": rule.remediation,
            }
        )
    return findings


def walk_pattern_regex(obj: Any) -> List[str]:
    """Collect Semgrep ``pattern-regex`` strings from a rule subtree."""
    found: List[str] = []
    if isinstance(obj, dict):
        pr = obj.get("pattern-regex")
        if isinstance(pr, str) and pr.strip():
            found.append(pr)
        for value in obj.values():
            found.extend(walk_pattern_regex(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(walk_pattern_regex(item))
    return found


def scan_aegis_rules(
    rules: Sequence[AegisRule],
    rel_path: str,
    content: str,
) -> List[Dict[str, Any]]:
    """Evaluate aegis rules with path-only vs content-only scoping."""
    findings: List[Dict[str, Any]] = []
    for rule in rules:
        matched = False
        if rule.path_only:
            matched = bool(rule.pattern.search(rel_path))
        else:
            matched = bool(rule.pattern.search(content))
        if not matched:
            continue
        findings.append(
            {
                "rule_id": rule.rule_id,
                "severity": rule.risk,
                "category": rule.category,
                "file_path": rel_path,
                "message": rule.name,
                "recommendation": rule.reason,
            }
        )
    return findings
