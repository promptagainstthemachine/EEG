"""Upstream URL validation to reduce SSRF risk."""

from __future__ import annotations

import ipaddress
import os
import socket
from functools import lru_cache
from urllib.parse import urlparse

from eeg.rules.text_matcher import load_policy_document


class UnsafeUpstreamURLError(ValueError):
    """Raised when an upstream URL is not safe to fetch."""


@lru_cache(maxsize=1)
def _ssrf_host_policy() -> dict[str, frozenset[str]]:
    doc = load_policy_document("ssrf_hosts")
    return {
        "blocked_hostnames": frozenset(str(x).lower() for x in (doc.get("blocked_hostnames") or ())),
        "blocked_hostname_suffixes": frozenset(
            str(x).lower() for x in (doc.get("blocked_hostname_suffixes") or ())
        ),
        "blocked_hostname_prefixes": frozenset(
            str(x).lower() for x in (doc.get("blocked_hostname_prefixes") or ())
        ),
        "blocked_exact_hosts": frozenset(
            str(x).lower() for x in (doc.get("blocked_exact_hosts") or ())
        ),
    }


def _allow_private_upstream() -> bool:
    raw = (os.environ.get("EEG_ALLOW_PRIVATE_UPSTREAM") or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    try:
        from django.conf import settings

        return bool(getattr(settings, "EEG_ALLOW_PRIVATE_UPSTREAM", False))
    except Exception:
        return False


def validate_upstream_url(url: str, *, allow_private: bool | None = None) -> str:
    if allow_private is None:
        allow_private = _allow_private_upstream()
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise UnsafeUpstreamURLError("Upstream URL must use http or https")
    if not parsed.hostname:
        raise UnsafeUpstreamURLError("Upstream URL must include a hostname")
    host = parsed.hostname.lower()
    policy = _ssrf_host_policy()
    if not allow_private:
        if host in policy["blocked_hostnames"] or any(
            host.endswith(suf) for suf in policy["blocked_hostname_suffixes"]
        ):
            raise UnsafeUpstreamURLError("Upstream hostname is not allowed")
        if host in policy["blocked_exact_hosts"] or any(
            host.startswith(pref) for pref in policy["blocked_hostname_prefixes"]
        ):
            raise UnsafeUpstreamURLError("Upstream hostname is not allowed")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            for _family, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                ip = ipaddress.ip_address(sockaddr[0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise UnsafeUpstreamURLError(
                        "Upstream resolves to a private or reserved address"
                    )
        except socket.gaierror as exc:
            raise UnsafeUpstreamURLError(f"Cannot resolve upstream host: {host}") from exc
    return url.strip()
