"""Gateway OSS surface scan — unsafe upstream / credential patterns in repos."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.scans import BaseScan, ScanRegistry, ScanResult
from eeg.utils.repocrawler import RepoCrawler

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build"}

_RULES = [
    {
        "rule_id": "EEG-GW-OSS-001",
        "severity": "CRITICAL",
        "category": "gateway_secrets",
        "pattern": re.compile(
            r"(?i)(provider_key|api_key|openai_api_key|anthropic_api_key)\s*[:=]\s*[\"']sk-[A-Za-z0-9_-]{20,}",
        ),
        "message": "Hardcoded LLM provider API key in gateway-related configuration.",
        "recommendation": "Use environment variables or GatewayConnector config loaded at runtime.",
    },
    {
        "rule_id": "EEG-GW-OSS-002",
        "severity": "HIGH",
        "category": "gateway_ssrf",
        "pattern": re.compile(
            r"(?i)(upstream_url|base_url|X-EEG-Upstream-URL).{0,40}https?://"
            r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|metadata\.google\.internal)",
        ),
        "message": "Gateway upstream URL targets loopback or cloud metadata (SSRF risk).",
        "recommendation": "Point upstreams at public provider endpoints; rely on eeg.gateway.url_safety.",
    },
    {
        "rule_id": "EEG-GW-OSS-003",
        "severity": "MEDIUM",
        "category": "gateway_transport",
        "pattern": re.compile(
            r"(?i)(upstream_url|chat/completions).{0,80}http://(?!localhost|127\.0\.0\.1)",
        ),
        "message": "Gateway upstream uses cleartext HTTP.",
        "recommendation": "Use HTTPS for provider APIs to protect keys and prompt content.",
    },
    {
        "rule_id": "EEG-GW-OSS-004",
        "severity": "MEDIUM",
        "category": "gateway_config",
        "pattern": re.compile(
            r"(?i)EEG_ALLOW_PRIVATE_UPSTREAM\s*[:=]\s*[\"']?(1|true|yes|on)",
        ),
        "message": "Private upstream allow-list is enabled (widens SSRF exposure).",
        "recommendation": "Keep EEG_ALLOW_PRIVATE_UPSTREAM disabled except for controlled local testing.",
    },
]

_FILE_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".toml",
    ".md",
}


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


@ScanRegistry.register
class GatewayOssSurfaceScan(BaseScan):
    """Heuristic scan for unsafe EEG gateway / LLM proxy configuration patterns."""

    scan_id = "gateway_oss_surface"
    scan_type = "static"
    description = "Gateway upstream SSRF, cleartext HTTP, and hardcoded provider key heuristics"
    categories = ["gateway", "ssrf", "secrets", "transport"]

    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        _ = options
        root = Path(target_path).resolve()
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        try:
            crawler = RepoCrawler(str(root))
            paths = [Path(p) for p in crawler.crawl()]
        except Exception:
            paths = [
                p
                for p in root.rglob("*")
                if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts)
            ]

        for path in paths:
            if path.suffix.lower() not in _FILE_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            rel = _rel(path, root)
            for rule in _RULES:
                for match in rule["pattern"].finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    findings.append(
                        {
                            "rule_id": rule["rule_id"],
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "file_path": rel,
                            "line": line,
                            "message": rule["message"],
                            "recommendation": rule["recommendation"],
                            "context": {"matched": match.group(0)[:160]},
                        }
                    )

        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=findings,
            summary={
                "files_scanned": files_scanned,
                "finding_count": len(findings),
            },
            metadata={"heuristic": True, "surface": "gateway"},
        )
