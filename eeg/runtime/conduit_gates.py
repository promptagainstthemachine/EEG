"""Conduit gates — egress URL admission for gateway wrap and tool fetches."""

from __future__ import annotations

import ipaddress
import math
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_PASTE_EXFIL = re.compile(
    r"(?i)(^|\.)(pastebin\.com|hastebin\.com|paste\.ee|transfer\.sh|file\.io|requestbin\.com|webhook\.site)$"
)
_CRLF = re.compile(r"[\r\n]")
_TRAVERSAL = re.compile(r"(?i)(^|/)\.\.(/|$)")


@dataclass
class ConduitVerdict:
    allowed: bool
    action: str  # allow | warn | block
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    result_class: str = "ok"  # threat | protective | config | infrastructure | ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "score": round(self.score, 4),
            "reasons": list(self.reasons),
            "result_class": self.result_class,
        }


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _host_blocked_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def gate_url(
    url: str,
    *,
    allow_private: bool = False,
    entropy_threshold: float = 4.8,
    max_length: int = 2048,
) -> ConduitVerdict:
    """
    Ordered egress gate: scheme → CRLF/traversal → paste-exfil → entropy → SSRF.
    """
    raw = (url or "").strip()
    reasons: list[str] = []
    if not raw:
        return ConduitVerdict(False, "block", 1.0, ["empty_url"], "threat")
    if len(raw) > max_length:
        return ConduitVerdict(False, "block", 0.8, ["url_too_long"], "protective")
    if _CRLF.search(raw):
        return ConduitVerdict(False, "block", 0.95, ["crlf_injection"], "threat")

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return ConduitVerdict(False, "block", 0.9, ["scheme_forbidden"], "threat")
    if not parsed.hostname:
        return ConduitVerdict(False, "block", 0.9, ["missing_host"], "threat")
    if _TRAVERSAL.search(parsed.path or ""):
        return ConduitVerdict(False, "block", 0.85, ["path_traversal"], "threat")

    host = parsed.hostname.lower()
    if _PASTE_EXFIL.search(host):
        return ConduitVerdict(False, "block", 0.88, ["paste_exfil_host"], "threat")

    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    ent = _shannon(path_q)
    if path_q and ent >= entropy_threshold and len(path_q) >= 24:
        reasons.append("high_path_entropy")
        return ConduitVerdict(False, "block", 0.75, reasons, "threat")

    if not allow_private:
        if host in {"localhost", "metadata.google.internal"} or host.endswith(".localhost"):
            return ConduitVerdict(False, "block", 0.95, ["blocked_hostname"], "threat")
        if host.startswith("169.254.") or _host_blocked_private(host):
            return ConduitVerdict(False, "block", 0.95, ["private_literal"], "threat")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            for _fam, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                ip = ipaddress.ip_address(sockaddr[0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return ConduitVerdict(False, "block", 0.95, ["ssrf_resolved_private"], "threat")
        except socket.gaierror:
            return ConduitVerdict(False, "block", 0.6, ["dns_failure"], "infrastructure")

    action = "warn" if reasons else "allow"
    return ConduitVerdict(True, action, 0.2 if reasons else 0.0, reasons, "ok")
