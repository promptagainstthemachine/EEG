"""Org-level gateway quotas (RPM / daily) with Redis + in-memory fallback."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

from eeg.gateway.redis_client import get_redis_client

logger = logging.getLogger("eeg.gateway.quotas")

_MEM: dict[str, list[float]] = {}
_MEM_DAILY: dict[str, tuple[str, int]] = {}
_LOCK = threading.Lock()


@dataclass
class QuotaPolicy:
    enabled: bool = False
    requests_per_minute: int = 0
    requests_per_day: int = 0


def parse_quota_policy(config: dict[str, Any] | None) -> QuotaPolicy:
    cfg = config or {}
    raw = cfg.get("quotas") if isinstance(cfg.get("quotas"), dict) else {}
    routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
    if not raw and isinstance(routing.get("quotas"), dict):
        raw = routing["quotas"]
    rpm = int(raw.get("requests_per_minute", raw.get("rpm", 0)) or 0)
    rpd = int(raw.get("requests_per_day", raw.get("rpd", 0)) or 0)
    enabled = bool(raw.get("enabled", rpm > 0 or rpd > 0))
    return QuotaPolicy(
        enabled=enabled,
        requests_per_minute=max(0, rpm),
        requests_per_day=max(0, rpd),
    )


def check_and_consume_quota(
    *,
    org_id: int,
    policy: QuotaPolicy,
    label: str = "default",
) -> tuple[bool, str]:
    """
    Atomically check + consume one request against org quotas.

    Returns (allowed, reason). reason is empty when allowed.
    """
    if not policy.enabled:
        return True, ""
    if policy.requests_per_minute <= 0 and policy.requests_per_day <= 0:
        return True, ""

    if policy.requests_per_minute > 0:
        ok = _consume_window(
            f"org:{org_id}:{label}:rpm",
            limit=policy.requests_per_minute,
            window_sec=60,
        )
        if not ok:
            return False, f"Gateway RPM quota exceeded ({policy.requests_per_minute}/min)"

    if policy.requests_per_day > 0:
        day = time.strftime("%Y%m%d", time.gmtime())
        ok = _consume_daily(f"org:{org_id}:{label}:rpd:{day}", limit=policy.requests_per_day)
        if not ok:
            return False, f"Gateway daily quota exceeded ({policy.requests_per_day}/day)"

    return True, ""


def _consume_window(key: str, *, limit: int, window_sec: int) -> bool:
    client = get_redis_client()
    if client is not None:
        try:
            redis_key = f"eeg:gw:quota:{key}"
            pipe = client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, window_sec, nx=True)
            count, _ = pipe.execute()
            return int(count) <= limit
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis quota window failed: %s", exc)

    now = time.time()
    with _LOCK:
        bucket = _MEM.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < window_sec]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


def _consume_daily(key: str, *, limit: int) -> bool:
    client = get_redis_client()
    if client is not None:
        try:
            redis_key = f"eeg:gw:quota:{key}"
            pipe = client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, 86400 + 3600, nx=True)
            count, _ = pipe.execute()
            return int(count) <= limit
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis daily quota failed: %s", exc)

    day = key.rsplit(":", 1)[-1]
    with _LOCK:
        stored_day, count = _MEM_DAILY.get(key, (day, 0))
        if stored_day != day:
            count = 0
        if count >= limit:
            return False
        _MEM_DAILY[key] = (day, count + 1)
        return True


def reset_quotas_for_tests() -> None:
    with _LOCK:
        _MEM.clear()
        _MEM_DAILY.clear()
