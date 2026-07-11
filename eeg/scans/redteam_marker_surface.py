"""Red-team marker surface scan — distinctive phrases in repo text.

Detects accidental inclusion of red-team template markers in documentation,
tests, or prompt files using bundled substring/regex rules.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from eeg.scans import BaseScan, ScanResult, ScanRegistry

_BUNDLE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "rules",
    "bundles",
    "redteam_marker_bundle",
    "markers.yaml",
)


def _load_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    try:
        with open(_BUNDLE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return rules
    for r in data.get("rules", []) or []:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        pats = r.get("patterns") or []
        compiled: List[re.Pattern[str]] = []
        if isinstance(pats, list):
            for p in pats:
                if isinstance(p, str):
                    try:
                        compiled.append(re.compile(p, re.I))
                    except re.error:
                        continue
        if rid and compiled:
            rules.append(
                {
                    "id": str(rid),
                    "title": str(r.get("title", "")),
                    "severity": str(r.get("severity", "MEDIUM")).upper(),
                    "category": str(r.get("category", "redteam_marker")),
                    "patterns": compiled,
                }
            )
    return rules


@ScanRegistry.register
class RedteamMarkerSurfaceScan(BaseScan):
    """Detect red-team / jailbreak template markers in text files."""

    scan_id = "redteam_marker_surface"
    scan_type = "static"
    description = "Red-team template markers in repo text"
    categories = ["jailbreak", "redteam", "prompt_injection"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._rules = _load_rules()

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        max_kb = int(opts.get("max_file_kb", 512))
        exts = tuple(
            opts.get(
                "extensions",
                (".py", ".md", ".txt", ".json", ".yaml", ".yml", ".ts", ".tsx", ".js", ".html"),
            )
        )
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        from eeg.utils.repocrawler import RepoCrawler

        for finfo in RepoCrawler(str(target_path)).crawl():
            rel = str(finfo.get("relative_path") or finfo.get("file_path") or "")
            if not rel.lower().endswith(exts):
                continue
            fpath = finfo.get("file_path")
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if len(content) > max_kb * 1024:
                continue
            files_scanned += 1
            for rule in self._rules:
                for pat in rule["patterns"]:
                    m = pat.search(content)
                    if m:
                        line_no = content[: m.start()].count("\n") + 1
                        findings.append(
                            {
                                "rule_id": rule["id"],
                                "severity": rule["severity"],
                                "category": rule["category"],
                                "file_path": rel,
                                "line_number": line_no,
                                "message": rule["title"],
                                "matched_excerpt": m.group(0)[:120],
                            }
                        )
                        break

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={"files_scanned": files_scanned, "total_findings": len(findings)},
            metadata={"source": "eeg.rules.bundles.redteam_marker_bundle"},
        )
