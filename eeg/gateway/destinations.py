"""AI destination catalog — classify Host/SNI/DNS against known LLM vendor hosts."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

DestClass = Literal["known_ai", "unknown", "private"]


@dataclass(frozen=True)
class DestinationHit:
    dest_class: DestClass
    vendor: str
    host: str
    matched_pattern: str = ""


# Extra well-known AI hosts not always present as full base_url in the catalog.
_EXTRA_HOST_PATTERNS: tuple[tuple[str, str], ...] = (
    ("openai.com", "openai"),
    ("api.openai.com", "openai"),
    ("chatgpt.com", "openai"),
    ("anthropic.com", "anthropic"),
    ("api.anthropic.com", "anthropic"),
    ("claude.ai", "anthropic"),
    ("googleapis.com", "google"),
    ("generativelanguage.googleapis.com", "google"),
    ("ai.google.dev", "google"),
    ("bedrock.amazonaws.com", "bedrock"),
    ("bedrock-runtime", "bedrock"),
    ("openai.azure.com", "azure-openai"),
    ("cognitiveservices.azure.com", "azure-openai"),
    ("cohere.ai", "cohere"),
    ("cohere.com", "cohere"),
    ("groq.com", "groq"),
    ("together.xyz", "together-ai"),
    ("deepseek.com", "deepseek"),
    ("mistral.ai", "mistral-ai"),
    ("fireworks.ai", "fireworks-ai"),
    ("perplexity.ai", "perplexity-ai"),
    ("openrouter.ai", "openrouter"),
    ("x.ai", "x-ai"),
    ("api.x.ai", "x-ai"),
    ("huggingface.co", "huggingface"),
    ("hf.co", "huggingface"),
    ("replicate.com", "replicate"),
    ("api.replicate.com", "replicate"),
    ("ollama.com", "ollama"),
    ("localhost", "ollama"),
    ("127.0.0.1", "ollama"),
)


def _host_from_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        return host
    except Exception:
        return ""


@lru_cache(maxsize=1)
def _vendor_host_index() -> tuple[tuple[str, str], ...]:
    """Build (host_or_suffix, vendor_id) pairs from provider catalog + extras."""
    rows: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(host: str, vendor: str) -> None:
        host = (host or "").lower().rstrip(".")
        vendor = (vendor or "").strip().lower()
        if not host or not vendor:
            return
        # Drop template placeholders like {resource}
        if "{" in host or "}" in host:
            # Keep static suffix after last template segment when possible
            parts = [p for p in host.split(".") if p and "{" not in p and "}" not in p]
            if len(parts) >= 2:
                host = ".".join(parts[-3:]) if len(parts) >= 3 else ".".join(parts)
            else:
                return
        key = (host, vendor)
        if key in seen:
            return
        seen.add(key)
        rows.append(key)

    try:
        from eeg.gateway.providers.catalog.definitions import PROVIDER_DEFINITIONS

        for defn in PROVIDER_DEFINITIONS:
            host = _host_from_url(getattr(defn, "base_url", "") or "")
            if host:
                _add(host, getattr(defn, "id", "") or "")
    except Exception:
        pass

    for host, vendor in _EXTRA_HOST_PATTERNS:
        _add(host, vendor)

    # Longer / more specific hosts first for matching
    rows.sort(key=lambda x: (-len(x[0]), x[0]))
    return tuple(rows)


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # Strip port if present without brackets
    if h.count(":") == 1 and not re.search(r"[a-fA-F].*:", h):
        h = h.split(":", 1)[0]
    return h


def is_private_host(host: str) -> bool:
    h = normalize_host(host)
    if not h:
        return False
    if h in ("localhost", "localhost.localdomain"):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def classify_host(host: str) -> DestinationHit:
    """Classify a hostname/SNI as known_ai, private, or unknown."""
    h = normalize_host(host)
    if not h:
        return DestinationHit(dest_class="unknown", vendor="", host="")

    if is_private_host(h):
        # Still check if it matches a known local AI runtime (ollama etc.)
        for pattern, vendor in _vendor_host_index():
            if h == pattern or h.endswith("." + pattern) or pattern in h:
                if vendor in ("ollama", "triton"):
                    return DestinationHit(
                        dest_class="known_ai",
                        vendor=vendor,
                        host=h,
                        matched_pattern=pattern,
                    )
        return DestinationHit(dest_class="private", vendor="", host=h)

    for pattern, vendor in _vendor_host_index():
        if h == pattern or h.endswith("." + pattern):
            return DestinationHit(
                dest_class="known_ai",
                vendor=vendor,
                host=h,
                matched_pattern=pattern,
            )
        # Substring for compound AWS-style hosts
        if pattern in h and "." in pattern:
            return DestinationHit(
                dest_class="known_ai",
                vendor=vendor,
                host=h,
                matched_pattern=pattern,
            )

    return DestinationHit(dest_class="unknown", vendor="", host=h)


def classify_url(url: str) -> DestinationHit:
    return classify_host(_host_from_url(url) or url)


def known_ai_hosts() -> list[str]:
    return sorted({h for h, _ in _vendor_host_index()})


def known_ai_vendors() -> list[str]:
    return sorted({v for _, v in _vendor_host_index()})
