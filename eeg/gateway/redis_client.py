"""Shared Redis client for gateway cache, quotas, and SLO metrics."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

logger = logging.getLogger("eeg.gateway.redis")

_redis_client: Any = None
_redis_unavailable = False
_init_lock = threading.Lock()


def _redis_url() -> str | None:
    url = (os.environ.get("EEG_REDIS_URL") or os.environ.get("REDIS_URL") or "").strip()
    if url:
        return url
    try:
        from django.conf import settings

        return (getattr(settings, "EEG_REDIS_URL", None) or "").strip() or None
    except Exception:
        return None


def _use_redis() -> bool:
    raw = (os.environ.get("EEG_USE_REDIS") or "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return bool(_redis_url())


def get_redis_client(*, force_memory: bool = False):
    """Return a Redis client or None (caller must fall back to memory)."""
    global _redis_client, _redis_unavailable
    if force_memory or _redis_unavailable:
        return None
    if _redis_client is not None:
        return _redis_client
    with _init_lock:
        if _redis_unavailable:
            return None
        if _redis_client is not None:
            return _redis_client
        if not _use_redis():
            _redis_unavailable = True
            return None
        url = _redis_url()
        if not url:
            _redis_unavailable = True
            return None
        try:
            import redis

            client = redis.from_url(
                url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
            client.ping()
            _redis_client = client
            logger.info("Gateway Redis connected (%s)", url.split("@")[-1])
            return _redis_client
        except Exception as exc:  # noqa: BLE001
            _redis_unavailable = True
            logger.warning("Gateway Redis unavailable, using in-process fallback: %s", exc)
            return None


def reset_redis_state_for_tests() -> None:
    global _redis_client, _redis_unavailable
    _redis_client = None
    _redis_unavailable = False
