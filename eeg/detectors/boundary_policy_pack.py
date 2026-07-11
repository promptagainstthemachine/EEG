"""Embedded regex execution for bundled AI static-practice YAML packs.

Runs only rules expressible as ``pattern-regex`` (including ``pattern-either`` branches)
without invoking external static-analysis CLIs. Taint and metavariable rules are skipped
until ported into ``rules/static`` as EEG-native definitions.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

from eeg.analysis.code_context import match_span_is_non_executable
from eeg.collector import Collector, Finding, Severity

_BUNDLES_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "bundles")
_LANG_EXT: Dict[str, Tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "java": (".java",),
    "go": (".go",),
    "ruby": (".rb",),
    "generic": tuple(),  # any extension the crawler yields
}


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


def _walk_pattern_regex(obj: Any) -> List[str]:
    found: List[str] = []
    if isinstance(obj, dict):
        pr = obj.get("pattern-regex")
        if isinstance(pr, str) and pr.strip():
            found.append(pr)
        for v in obj.values():
            found.extend(_walk_pattern_regex(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_walk_pattern_regex(item))
    return found


def _extensions_for_languages(langs: Optional[Sequence[str]]) -> Optional[Set[str]]:
    """Return allowed extensions, or None = all crawler extensions."""
    if not langs:
        return None
    exts: Set[str] = set()
    for lang in langs:
        key = str(lang).lower()
        mapped = _LANG_EXT.get(key)
        if mapped is None:
            continue
        if not mapped:
            return None
        exts.update(mapped)
    return exts or None


def _paths_match(rel_posix: str, includes: Optional[Sequence[str]], excludes: Optional[Sequence[str]]) -> bool:
    if excludes:
        for pat in excludes:
            if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(os.path.basename(rel_posix), pat):
                return False
    if not includes:
        return True
    for pat in includes:
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(os.path.basename(rel_posix), pat):
            return True
    return False


def _eeg_rule_id(bundle_file: str, rule_index: int) -> str:
    digest = hashlib.sha256(f"{bundle_file}\0{rule_index}".encode()).hexdigest()[:10].upper()
    return f"EEG-BND-{digest}"


def _eeg_category(rule: Dict[str, Any]) -> str:
    msg = (rule.get("message") or "").lower()
    meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    cwe = str(meta.get("cwe") or "").upper()
    rule_id = str(rule.get("id") or "").lower()

    if any(k in msg for k in ("api key", "token", "credential", "secret", "password", "apikey")):
        return "secrets"
    if "CWE-78" in cwe or any(
        k in msg
        for k in (
            "command injection",
            "os command",
            "command execution",
            "code injection",
            "shell injection",
            "subprocess",
            "os.system",
        )
    ) or any(k in rule_id for k in ("command-injection", "mcp-command", "llm-output-to-exec")):
        return "command_injection"
    if any(k in msg for k in ("prompt injection", "jailbreak", "system prompt", "system message")):
        return "prompt_injection"
    if "injection" in msg and any(k in msg for k in ("prompt", "jailbreak", "system")):
        return "prompt_injection"
    if any(k in msg for k in ("ssrf", "url", "request", "network", "socket")):
        return "network"
    return "policy"


def _compile_regexes(patterns: Iterable[str]) -> List[re.Pattern[str]]:
    compiled: List[re.Pattern[str]] = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.MULTILINE))
        except re.error:
            continue
    return compiled


def _iter_bundle_yaml_files(root: str) -> Iterable[str]:
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".yaml") or name.endswith(".yml"):
                yield os.path.join(dirpath, name)


def _parse_pack_rules(bundle_root: str) -> List[Dict[str, Any]]:
    """Flatten YAML rules into executable regex rows."""
    rows: List[Dict[str, Any]] = []
    if not os.path.isdir(bundle_root):
        return rows

    for abs_path in _iter_bundle_yaml_files(bundle_root):
        rel_bundle = os.path.relpath(abs_path, bundle_root)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
                doc = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            continue

        rules = doc.get("rules")
        if not isinstance(rules, list):
            continue

        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            if rule.get("mode") == "taint":
                continue
            if rule.get("pattern-sources") or rule.get("pattern-sinks"):
                continue

            regexes = _walk_pattern_regex(rule)
            if not regexes:
                continue

            langs = rule.get("languages")
            lang_list = langs if isinstance(langs, list) else None
            ext_filter = _extensions_for_languages(lang_list)

            paths_cfg = rule.get("paths") or {}
            includes = paths_cfg.get("include") if isinstance(paths_cfg, dict) else None
            excludes = paths_cfg.get("exclude") if isinstance(paths_cfg, dict) else None
            if includes is not None and not isinstance(includes, (list, tuple)):
                includes = None
            if excludes is not None and not isinstance(excludes, (list, tuple)):
                excludes = None

            compiled = _compile_regexes(regexes)
            if not compiled:
                continue

            meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
            cwe = meta.get("cwe")
            cwe_str = str(cwe) if cwe else None

            msg = rule.get("message")
            message = str(msg).strip().split("\n", 1)[0] if msg else "Bundled static pattern matched"

            rows.append(
                {
                    "eeg_rule_id": _eeg_rule_id(rel_bundle, idx),
                    "severity": _severity_map(rule.get("severity")),
                    "category": _eeg_category(rule),
                    "cloud_env": "any",
                    "message": message[:500],
                    "recommendation": message[:2000],
                    "cwe": cwe_str,
                    "compiled": compiled,
                    "ext_filter": ext_filter,
                    "includes": list(includes) if includes else None,
                    "excludes": list(excludes) if excludes else None,
                    "source_pack": rel_bundle,
                }
            )
    return rows


class BoundaryPolicyPackDetector:
    """Runs regex-only rows from ALL ``eeg/rules/bundles/`` (embedded static engine)."""

    name = "boundary_policy_pack"
    category = "boundary_pack"
    
    # Semgrep-style packs with ``pattern-regex`` only. EEG-import bundles run in AgentForensicsScan.
    ALL_BUNDLES = [
        "ai_practice_patterns",
        "redteam_marker_bundle",
    ]

    def __init__(self, cloud_env: str, *, bundles: Optional[List[str]] = None):
        self.cloud_env = cloud_env
        self._rows: List[Dict[str, Any]] = []

        if bundles is None:
            try:
                from eeg.rules.catalog_loader import get_bundles_for_scan

                catalog_bundles = get_bundles_for_scan("code_security")
                target_bundles = catalog_bundles or self.ALL_BUNDLES
            except Exception:
                target_bundles = self.ALL_BUNDLES
        else:
            target_bundles = bundles
        
        for bundle_name in target_bundles:
            pack_dir = os.path.join(_BUNDLES_ROOT, bundle_name)
            if os.path.isdir(pack_dir):
                bundle_rows = _parse_pack_rules(pack_dir)
                self._rows.extend(bundle_rows)

    def scan(self, files: List[Dict], collector: Collector) -> None:
        print(f"  [BOUNDARY_POLICY_PACK] Scanning {len(files)} files with {len(self._rows)} bundled regex rules...")
        for row in self._rows:
            exts = row["ext_filter"]
            includes = row["includes"]
            excludes = row["excludes"]
            for finfo in files:
                ext = finfo.get("extension") or ""
                if exts is not None and ext not in exts:
                    continue
                rel = (finfo.get("relative_path") or "").replace("\\", "/")
                if not _paths_match(rel, includes, excludes):
                    continue
                self._apply_row(row, finfo, collector)

    def _apply_row(self, row: Dict[str, Any], finfo: Dict, collector: Collector) -> None:
        path = finfo.get("file_path")
        if not path or not os.path.isfile(path):
            return
        try:
            if os.path.getsize(path) > 2 * 1024 * 1024:
                return
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except OSError:
            return

        for rx in row["compiled"]:
            for m in rx.finditer(content):
                start = m.start()
                end = m.end()
                if match_span_is_non_executable(content, start, end):
                    continue
                ln = content.count("\n", 0, start) + 1
                line_begin = content.rfind("\n", 0, start) + 1
                line_end = content.find("\n", start)
                if line_end < 0:
                    line_end = len(content)
                snippet = content[line_begin:line_end].strip()[:200]
                collector.add_finding(
                    Finding(
                        rule_id=row["eeg_rule_id"],
                        severity=row["severity"],
                        category=row["category"],
                        cloud_env=self.cloud_env,
                        file_path=finfo.get("relative_path") or path,
                        line_number=ln,
                        code_snippet=snippet,
                        message=row["message"],
                        recommendation=row["recommendation"],
                        cwe=row.get("cwe"),
                        owasp_llm=None,
                    )
                )
                return
