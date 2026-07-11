"""Simple per-organization rate limits for high-cost API routes."""

from __future__ import annotations

import time
from typing import Optional, Tuple

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse

# (max_requests, window_seconds) per path prefix
DEFAULT_LIMITS: dict[str, Tuple[int, int]] = {
    "/api/v1/gateway/": (60, 60),
    "/api/v1/scan/": (20, 60),
    "/api/v1/traces/": (120, 60),
    "/api/v1/probe/": (20, 60),
}


def _limits() -> dict[str, Tuple[int, int]]:
    custom = getattr(settings, "EEG_API_RATE_LIMITS", None)
    return custom if isinstance(custom, dict) else DEFAULT_LIMITS


def _match_limit(path: str) -> Optional[Tuple[str, int, int]]:
    for prefix, (limit, window) in _limits().items():
        if path.startswith(prefix):
            return prefix, limit, window
    return None


def check_api_rate_limit(request) -> Optional[JsonResponse]:
    """Return 429 response if the org/IP exceeded limits for this route class."""
    if request.method not in ("POST", "PUT", "PATCH"):
        return None

    matched = _match_limit(request.path)
    if not matched:
        return None

    prefix, limit, window = matched
    org = getattr(request, "organization", None)
    org_part = f"org:{org.pk}" if org and getattr(org, "pk", None) else "org:anon"
    ip = (request.META.get("REMOTE_ADDR") or "unknown")[:45]
    bucket = f"eeg:rl:{prefix}:{org_part}:{ip}"
    now = int(time.time())
    window_start = now - (now % window)

    try:
        data = cache.get(bucket)
        if not isinstance(data, dict) or data.get("window") != window_start:
            cache.set(bucket, {"window": window_start, "count": 1}, timeout=window + 5)
            return None
        count = int(data.get("count", 0)) + 1
        if count > limit:
            return JsonResponse(
                {
                    "error": "Rate limit exceeded. Try again later.",
                    "code": "rate_limit_exceeded",
                    "limit": limit,
                    "window_seconds": window,
                },
                status=429,
            )
        cache.set(bucket, {"window": window_start, "count": count}, timeout=window + 5)
    except Exception:
        return None
    return None
