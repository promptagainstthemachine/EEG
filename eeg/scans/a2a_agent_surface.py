"""A2A / agent-card surface heuristics (EEG-native).

Ports core regex and JSON heuristics from Cisco ``a2a-scanner``
``HeuristicAnalyzer`` for offline assessment of JSON agent cards and related
text in repositories (no async backend required).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.scans import BaseScan, ScanResult, ScanRegistry


class _A2AHeuristics:
    """Synchronous clone of a2ascanner heuristic_analyzer patterns."""

    def __init__(self) -> None:
        self.superlative_pattern = re.compile(
            r"\b(always|never|best|perfect|ultimate|superior|guaranteed|"
            r"100%|all tasks|everything|pick me|choose me)\b",
            re.I,
        )
        self.suspicious_url_pattern = re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{4,5}",
            re.I,
        )
        self.metadata_pattern = re.compile(
            r"(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)",
            re.I,
        )
        self.command_pattern = re.compile(
            r"\b(?:eval|exec|system)\s*\(|"
            r"\bsubprocess\s*\.|"
            r"\bpopen\s*\(|"
            r"shell\s*=\s*True",
            re.I,
        )
        self.credential_pattern = re.compile(
            r"(?:password|api[_-]?key|secret|token|credential)\s*[:=]",
            re.I,
        )
        self.http_field_pattern = re.compile(
            r"http://(?!localhost|127\.0\.0\.1)", re.I
        )

    def findings_for_text(self, text: str, rel_path: str, field: str = "content") -> List[Dict[str, Any]]:
        return self._text_checks(text, field, rel_path)

    def findings_for_json_tree(self, data: Any, rel_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            if "id" in data:
                agent_id = str(data["id"])
                if re.match(r"(agent|bot|helper)-\d{3,}", agent_id):
                    findings.append(
                        self._f(
                            "EEG-A2A-001",
                            "MEDIUM",
                            "discovery_poisoning",
                            rel_path,
                            f"Suspicious sequential agent id: {agent_id}",
                        )
                    )
            if "priority" in data:
                pr = data["priority"]
                if isinstance(pr, (int, float)) and pr >= 999:
                    findings.append(
                        self._f(
                            "EEG-A2A-002",
                            "MEDIUM",
                            "routing_manipulation",
                            rel_path,
                            f"Abnormally high priority value: {pr}",
                        )
                    )
        self._walk(data, "", rel_path, findings)
        return findings

    def _walk(self, obj: Any, path: str, rel_path: str, findings: List[Dict[str, Any]]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{path}.{k}" if path else k
                if isinstance(v, str):
                    findings.extend(self._text_checks(v, p, rel_path))
                else:
                    self._walk(v, p, rel_path, findings)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                p = f"{path}[{i}]" if path else f"[{i}]"
                if isinstance(item, str):
                    findings.extend(self._text_checks(item, p, rel_path))
                else:
                    self._walk(item, p, rel_path, findings)
        elif isinstance(obj, str):
            findings.extend(self._text_checks(obj, path or "content", rel_path))

    def _text_checks(self, text: str, field: str, rel_path: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        sup = self.superlative_pattern.findall(text)
        if len(sup) >= 2:
            out.append(
                self._f(
                    "EEG-A2A-003",
                    "MEDIUM",
                    "agent_card_spoofing",
                    rel_path,
                    f"Multiple superlative claims in {field}",
                )
            )
        if self.metadata_pattern.search(text):
            out.append(
                self._f(
                    "EEG-A2A-004",
                    "HIGH",
                    "cloud_metadata_access",
                    rel_path,
                    f"Cloud metadata reference in {field}",
                )
            )
        if self.command_pattern.search(text):
            out.append(
                self._f(
                    "EEG-A2A-005",
                    "HIGH",
                    "code_execution",
                    rel_path,
                    f"Command execution pattern in {field}",
                )
            )
        if self.suspicious_url_pattern.findall(text):
            out.append(
                self._f(
                    "EEG-A2A-006",
                    "MEDIUM",
                    "suspicious_endpoint",
                    rel_path,
                    f"Localhost / raw IP URL in {field}",
                )
            )
        low_field = field.lower()
        if low_field in ("url", "endpoint", "callback") and self.http_field_pattern.search(text):
            out.append(
                self._f(
                    "EEG-A2A-007",
                    "MEDIUM",
                    "insecure_network",
                    rel_path,
                    f"Insecure HTTP in sensitive field {field}",
                )
            )
        ext = Path(rel_path).suffix.lower()
        if ext not in (
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".go",
            ".rs",
            ".java",
            ".c",
            ".cpp",
            ".h",
        ):
            cm = self.credential_pattern.findall(text)
            if len(cm) >= 2 and re.search(
                r"\b(input|prompt|enter|provide|supply)\b", text, re.I
            ):
                out.append(
                    self._f(
                        "EEG-A2A-008",
                        "HIGH",
                        "credential_harvesting",
                        rel_path,
                        f"Potential credential harvesting phrasing in {field}",
                    )
                )
        return out

    @staticmethod
    def _f(
        rule_id: str,
        severity: str,
        category: str,
        rel_path: str,
        message: str,
    ) -> Dict[str, Any]:
        return {
            "rule_id": rule_id,
            "severity": severity,
            "category": category,
            "file_path": rel_path,
            "message": message,
        }


@ScanRegistry.register
class A2AAgentSurfaceScan(BaseScan):
    """Heuristic scan for A2A-style JSON and agent-card text."""

    scan_id = "a2a_agent_surface"
    scan_type = "static"
    description = "A2A scanner–style heuristics on JSON agent artifacts and text fields"
    categories = ["a2a", "agent", "protocol", "ssrf", "credentials"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        max_kb = int(opts.get("max_file_kb", 512))
        hints = tuple(
            opts.get(
                "path_hints",
                ("agent-card", "agent_card", "a2a", ".well-known", "card.json"),
            )
        )
        engine = _A2AHeuristics()
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        from eeg.utils.repocrawler import RepoCrawler

        for finfo in RepoCrawler(str(target_path)).crawl():
            rel = str(finfo.get("relative_path") or finfo.get("file_path") or "")
            low = rel.lower()
            if not low.endswith(".json"):
                continue
            if not any(h in low for h in hints) and "card" not in low:
                continue
            fpath = finfo.get("file_path")
            try:
                raw = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if len(raw) > max_kb * 1024:
                continue
            files_scanned += 1
            try:
                data = json.loads(raw)
                findings.extend(engine.findings_for_json_tree(data, rel))
            except json.JSONDecodeError:
                findings.extend(engine.findings_for_text(raw, rel))

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={"json_files_scanned": files_scanned, "total_findings": len(findings)},
            metadata={"source": "Agentsec-Tools/a2a-scanner (HeuristicAnalyzer)"},
        )
