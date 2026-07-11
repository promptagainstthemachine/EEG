"""Memoryguard — static memory / RAG poisoning heuristics (EEG-native).

Implements offline heuristics for memory-integrity framing (imperative hijack
language, instruction override, behavioral directives in knowledge-shaped text).
Does not call external LLMs; use runtime validation elsewhere when configured.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from eeg.scans import BaseScan, ScanResult, ScanRegistry

_POISON_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    (
        "EEG-MG-001",
        re.compile(
            r"(?is)\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+"
            r"(instructions|rules|guidelines|directives)\b"
        ),
        "Instruction override / context break common in memory poisoning.",
    ),
    (
        "EEG-MG-002",
        re.compile(
            r"(?is)\b(you\s+are\s+now|new\s+system\s+prompt|developer\s+mode|DAN\s+mode)\b"
        ),
        "Role or system prompt hijack phrasing embedded in knowledge text.",
    ),
    (
        "EEG-MG-003",
        re.compile(
            r"(?is)\b(always|never)\s+(obey|follow|execute|run|delete|exfiltrate|send)\b"
        ),
        "Imperative behavioral directive in stored knowledge.",
    ),
    (
        "EEG-MG-004",
        re.compile(r"(?is)\b(base64|curl|wget|/etc/passwd|metadata\.google)\b"),
        "Possible exfiltration or env hint inside memory-like content.",
    ),
]

_MEMORY_LIKE_SUFFIXES = (
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".csv",
)


@dataclass
class _BaselineProfile:
    """Lightweight drift helper (stdlib only)."""

    category_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_reads: int = 0
    content_length_sum: float = 0.0
    content_length_sq_sum: float = 0.0

    def record(self, content: str, category: str = "default") -> None:
        self.total_reads += 1
        self.category_counts[category] += 1
        ln = float(len(content))
        self.content_length_sum += ln
        self.content_length_sq_sum += ln * ln

    @property
    def mean_len(self) -> float:
        if self.total_reads == 0:
            return 0.0
        return self.content_length_sum / self.total_reads

    def std_len(self) -> float:
        if self.total_reads < 2:
            return 0.0
        n = float(self.total_reads)
        variance = self.content_length_sq_sum / n - (self.content_length_sum / n) ** 2
        return math.sqrt(max(0.0, variance))


@ScanRegistry.register
class MemoryguardSurfaceScan(BaseScan):
    """Static scan for poisoned-memory indicators in text-like artifacts."""

    scan_id = "memoryguard_surface"
    scan_type = "static"
    description = "Memory poisoning and length-drift heuristics on text artifacts"
    categories = ["memory", "rag", "poisoning", "agent"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        max_file_kb = int(opts.get("max_file_kb", 512))
        drift_z = float(opts.get("drift_zscore", 3.0))
        min_files_for_drift = int(opts.get("min_files_for_drift", 8))

        findings: List[Dict[str, Any]] = []
        baseline = _BaselineProfile()

        from eeg.utils.repocrawler import RepoCrawler

        text_files: List[tuple[str, str]] = []
        crawler = RepoCrawler(str(target_path))
        for finfo in crawler.crawl():
            rel = str(finfo.get("relative_path") or finfo.get("file_path") or "")
            low = rel.lower()
            if not any(low.endswith(s) for s in _MEMORY_LIKE_SUFFIXES):
                continue
            fpath = finfo.get("file_path")
            try:
                raw = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if len(raw) > max_file_kb * 1024:
                continue
            text_files.append((rel, raw))

        for rel, content in text_files:
            baseline.record(content, "memory_like")

        mean_len = baseline.mean_len
        std_len = baseline.std_len()

        for rel, content in text_files:
            for rule_id, pattern, reason in _POISON_PATTERNS:
                m = pattern.search(content)
                if not m:
                    continue
                line_num = content[: m.start()].count("\n") + 1
                findings.append(
                    {
                        "rule_id": rule_id,
                        "severity": "HIGH",
                        "category": "memory_poisoning",
                        "file_path": rel,
                        "line_number": line_num,
                        "message": reason,
                        "matched_excerpt": m.group(0)[:240],
                    }
                )

            if baseline.total_reads >= min_files_for_drift and std_len > 0:
                z = abs(len(content) - mean_len) / std_len
                if z >= drift_z:
                    findings.append(
                        {
                            "rule_id": "EEG-MG-DRIFT",
                            "severity": "MEDIUM",
                            "category": "memory_drift",
                            "file_path": rel,
                            "line_number": 1,
                            "message": (
                                f"File length deviates from repo baseline "
                                f"(z≈{z:.1f}, mean={mean_len:.0f}, std={std_len:.0f})."
                            ),
                        }
                    )

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={
                "memory_like_files": len(text_files),
                "total_findings": len(findings),
                "baseline_mean_length": mean_len,
                "baseline_std_length": std_len,
            },
            metadata={"source": "eeg.scans.memoryguard_surface"},
        )
