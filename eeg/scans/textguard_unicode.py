"""Textguard — input surface checks for invisible Unicode and credential patterns.

Detects Unicode categories Cf, Co, Cn and a compact regex list for offline
repository scans. Does not run external ML classifiers.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from eeg.scans import BaseScan, ScanResult, ScanRegistry

_BANNED_CATEGORIES = frozenset({"Cf", "Co", "Cn"})

_EXTRA_PATTERNS: List[Tuple[str, str, re.Pattern[str]]] = [
    (
        "EEG-TG-RE-001",
        "Bearer token pattern in source",
        re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    ),
    (
        "EEG-TG-RE-002",
        "OpenAI-style API key material",
        re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
    ),
    (
        "EEG-TG-RE-003",
        "Anthropic API key material",
        re.compile(r"\bsk-ant-[a-zA-Z0-9\-]{20,}\b"),
    ),
]


def _scan_invisible_line(line: str, line_no: int, rel_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for i, ch in enumerate(line):
        cat = unicodedata.category(ch)
        if cat in _BANNED_CATEGORIES:
            findings.append(
                {
                    "rule_id": "EEG-TG-INVISIBLE",
                    "severity": "MEDIUM",
                    "category": "unicode_obfuscation",
                    "file_path": rel_path,
                    "line_number": line_no,
                    "message": f"Invisible / format-control Unicode (category {cat}).",
                    "context": {"codepoint": hex(ord(ch)), "column": i + 1},
                }
            )
            if len(findings) >= 20:
                break
    return findings


@ScanRegistry.register
class TextguardUnicodeScan(BaseScan):
    """Invisible Unicode plus high-signal secret regex heuristics."""

    scan_id = "textguard_unicode"
    scan_type = "static"
    description = "Invisible Unicode and API token regex heuristics"
    categories = ["prompt", "unicode", "secrets", "pii"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        max_kb = int(opts.get("max_file_kb", 256))
        text_ext = tuple(
            opts.get(
                "text_extensions",
                (
                    ".py",
                    ".md",
                    ".txt",
                    ".json",
                    ".yaml",
                    ".yml",
                    ".ts",
                    ".tsx",
                    ".js",
                    ".jsx",
                    ".html",
                    ".css",
                    ".rs",
                    ".go",
                    ".java",
                ),
            )
        )

        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        from eeg.utils.repocrawler import RepoCrawler

        for finfo in RepoCrawler(str(target_path)).crawl():
            rel = str(finfo.get("relative_path") or finfo.get("file_path") or "")
            if not rel.lower().endswith(text_ext):
                continue
            fpath = finfo.get("file_path")
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if len(content) > max_kb * 1024:
                continue
            files_scanned += 1
            inv_count = 0
            for rid, msg, pat in _EXTRA_PATTERNS:
                for m in pat.finditer(content):
                    line_no = content[: m.start()].count("\n") + 1
                    findings.append(
                        {
                            "rule_id": rid,
                            "severity": "HIGH",
                            "category": "credential_exposure",
                            "file_path": rel,
                            "line_number": line_no,
                            "message": msg,
                            "matched_excerpt": m.group(0)[:80],
                        }
                    )
                    break

            for ln, line in enumerate(content.splitlines(), start=1):
                if inv_count >= 40:
                    break
                if any(ord(c) > 127 for c in line):
                    chunk = _scan_invisible_line(line, ln, rel)
                    findings.extend(chunk)
                    inv_count += len(chunk)

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={"files_scanned": files_scanned, "total_findings": len(findings)},
            metadata={"source": "eeg.scans.textguard_unicode"},
        )
