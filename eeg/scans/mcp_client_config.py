"""MCP client configuration static audit (EEG-native).

Derives checks from Agentsec-Tools ``mcp-context-protector`` (MCP JSON layouts),
``agent-scan`` discovery targets (VS Code / Cursor / Claude paths), and MCP-Sec
research themes (transport, least-privilege paths). Walks a repository for JSON
files that look like MCP client configs and flags risky server entries.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.scans import BaseScan, ScanResult, ScanRegistry

_CONFIG_NAME_HINTS = (
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
)

_HTTP_URL = re.compile(r"^https?://", re.I)
_DANGEROUS_FS = re.compile(
    r'(?:^|[\s"\'])(/|~|/etc/|/usr/|/var/|/root/|\$HOME|%USERPROFILE%|C:\\\\)(?:\s|"|\'|,|\]|$)',
    re.I,
)


def _looks_like_mcp_config(path: str, data: Any) -> bool:
    low = path.replace("\\", "/").lower()
    if any(h in low for h in _CONFIG_NAME_HINTS):
        return True
    if not isinstance(data, dict):
        return False
    if "mcpServers" in data:
        return True
    if "servers" in data and isinstance(data.get("servers"), dict):
        return True
    return False


def _iter_server_entries(data: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """Yield (server_name, server_dict) from common MCP client shapes."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    if not isinstance(data, dict):
        return out
    mcp = data.get("mcpServers")
    if isinstance(mcp, dict):
        for name, cfg in mcp.items():
            if isinstance(cfg, dict):
                out.append((str(name), cfg))
    servers = data.get("servers")
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if isinstance(cfg, dict):
                out.append((str(name), cfg))
    return out


def _check_server(name: str, cfg: Dict[str, Any], rel_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    url = cfg.get("url")
    if isinstance(url, str) and url.strip():
        if url.lower().startswith("http://"):
            findings.append(
                {
                    "rule_id": "EEG-MCP-CFG-HTTP",
                    "severity": "HIGH",
                    "category": "mcp_transport",
                    "file_path": rel_path,
                    "message": f"MCP server '{name}' uses cleartext HTTP URL.",
                    "context": {"url": url[:200]},
                }
            )
        if _HTTP_URL.match(url) and "localhost" not in url.lower():
            pass

    command = cfg.get("command")
    args = cfg.get("args")
    if isinstance(command, str) and command:
        arg_list: List[str] = []
        if isinstance(args, list):
            arg_list = [str(a) for a in args]
        joined = " ".join([command] + arg_list)
        if "npx" in command or "npx" in joined:
            if "-y" in arg_list:
                findings.append(
                    {
                        "rule_id": "EEG-MCP-CFG-NPX",
                        "severity": "LOW",
                        "category": "supply_chain",
                        "file_path": rel_path,
                        "message": f"MCP server '{name}' uses npx -y; prefer pinned installs for supply-chain control.",
                        "context": {"command": command, "args_preview": str(arg_list)[:300]},
                    }
                )
        if _DANGEROUS_FS.search(joined):
            findings.append(
                {
                    "rule_id": "EEG-MCP-CFG-PATH",
                    "severity": "HIGH",
                    "category": "mcp_privilege",
                    "file_path": rel_path,
                    "message": f"MCP server '{name}' may reference broad filesystem paths.",
                    "context": {"snippet": joined[:400]},
                }
            )

    env = cfg.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            ks = str(k).lower()
            vs = str(v).lower() if v is not None else ""
            if any(s in ks for s in ("api_key", "secret", "token", "password")) and vs and len(vs) > 12:
                findings.append(
                    {
                        "rule_id": "EEG-MCP-CFG-ENV-SECRET",
                        "severity": "CRITICAL",
                        "category": "credential_exposure",
                        "file_path": rel_path,
                        "message": f"MCP server '{name}' env may embed secret material for key '{k}'.",
                        "context": {"hint": "Prefer env_file or secret manager references, not inline values"},
                    }
                )

    return findings


@ScanRegistry.register
class MCPClientConfigScan(BaseScan):
    """Static audit of MCP client JSON (Cursor, Claude, VS Code style)."""

    scan_id = "mcp_client_config"
    scan_type = "static"
    description = "MCP client JSON configs (transport, npx supply chain, env secrets, paths)"
    categories = ["mcp", "configuration", "supply_chain", "credentials"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        max_bytes = int(opts.get("max_file_bytes", 2_000_000))
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        from eeg.utils.repocrawler import RepoCrawler

        for finfo in RepoCrawler(str(target_path)).crawl():
            rel = str(finfo.get("relative_path") or finfo.get("file_path") or "")
            if not rel.lower().endswith(".json"):
                continue
            fpath = finfo.get("file_path")
            try:
                sz = os.path.getsize(fpath)
            except OSError:
                continue
            if sz > max_bytes:
                continue
            try:
                raw = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                data = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                continue
            if not _looks_like_mcp_config(rel, data):
                continue
            files_scanned += 1
            for name, cfg in _iter_server_entries(data):
                findings.extend(_check_server(name, cfg, rel))

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={
                "mcp_config_files": files_scanned,
                "total_findings": len(findings),
            },
            metadata={
                "sources": [
                    "Agentsec-Tools/mcp-context-protector",
                    "Agentsec-Tools/agent-scan",
                    "Agentsec-Tools/MCP-Sec",
                ]
            },
        )
