"""MCP tool return credential-leak heuristics (EEG-native).

Inspired by semgrep-ai-best-practices ``mcp-credential-in-response`` (MCP tool
handlers returning dict literals with credential-like keys). Uses regex only;
does not require the Semgrep CLI.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.scans import BaseScan, ScanResult, ScanRegistry

# Return dict containing sensitive keys (Python MCP / FastAPI style)
_RETURN_SECRET_KEYS = re.compile(
    r"return\s*\{[^}]{0,4000}?(?:[\"'](?:api_key|password|secret|token|access_token|"
    r"secret_key|private_key)[\"']\s*:)",
    re.I | re.DOTALL,
)


@ScanRegistry.register
class MCPToolResponseLeakScan(BaseScan):
    """Static scan for MCP-style tool functions returning credential maps."""

    scan_id = "mcp_tool_response_leak"
    scan_type = "static"
    description = "MCP tool handlers returning dicts with credential-like keys (regex)"
    categories = ["mcp", "credentials", "owasp"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        from eeg.utils.repocrawler import RepoCrawler

        for finfo in RepoCrawler(str(target_path)).crawl():
            rel = str(finfo.get("relative_path") or finfo.get("file_path") or "")
            if not rel.lower().endswith(".py"):
                continue
            fpath = finfo.get("file_path")
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if _RETURN_SECRET_KEYS.search(content):
                files_scanned += 1
                for m in _RETURN_SECRET_KEYS.finditer(content):
                    line_no = content[: m.start()].count("\n") + 1
                    findings.append(
                        {
                            "rule_id": "EEG-MCP-RET-CRED",
                            "severity": "HIGH",
                            "category": "credential_leak",
                            "file_path": rel,
                            "line_number": line_no,
                            "message": "Possible MCP tool return dict exposing credential-like keys.",
                            "matched_excerpt": m.group(0)[:200],
                        }
                    )

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={"python_mcp_files_scanned": files_scanned, "total_findings": len(findings)},
            metadata={
                "source": "semgrep-ai-best-practices/mcp-credential-in-response (regex port)"
            },
        )
