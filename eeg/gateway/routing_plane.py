"""Gateway routing plane: retries, weighted fallback, circuit breaker, Redis/memory cache."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from eeg.gateway.redis_client import get_redis_client

logger = logging.getLogger("eeg.gateway.routing")


@dataclass
class RouteTarget:
    provider: str
    weight: float = 1.0
    api_key: str | None = None
    base_url: str | None = None
    label: str | None = None


@dataclass
class CircuitBreakerPolicy:
    enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    half_open_max_calls: int = 1


@dataclass
class RoutingPolicy:
    max_retries: int = 0
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    retry_backoff_ms: int = 100
    retry_backoff_max_ms: int = 2000
    targets: list[RouteTarget] = field(default_factory=list)
    cache_ttl_seconds: int = 0
    cache_enabled: bool = False
    circuit_breaker: CircuitBreakerPolicy = field(default_factory=CircuitBreakerPolicy)


@dataclass
class _CacheEntry:
    expires_at: float
    status: int
    body: dict[str, Any]


@dataclass
class _CircuitState:
    failures: int = 0
    opened_at: float = 0.0
    state: str = "closed"  # closed | open | half_open
    half_open_successes: int = 0


_CACHE: dict[str, _CacheEntry] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 4096

_CIRCUITS: dict[str, _CircuitState] = {}
_CIRCUIT_LOCK = threading.Lock()

_CACHE_PREFIX = "eeg:gw:cache:"
_CIRCUIT_PREFIX = "eeg:gw:cb:"


def parse_routing_policy(config: dict[str, Any] | None) -> RoutingPolicy:
    """Read routing knobs from connector / workspace config."""
    cfg = config or {}
    routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
    max_retries = int(routing.get("max_retries", cfg.get("max_retries", 0)) or 0)
    cache_ttl = int(routing.get("cache_ttl_seconds", cfg.get("cache_ttl_seconds", 0)) or 0)
    cache_enabled = bool(routing.get("cache_enabled", cfg.get("cache_enabled", False))) or cache_ttl > 0

    cb_raw = routing.get("circuit_breaker") if isinstance(routing.get("circuit_breaker"), dict) else {}
    circuit = CircuitBreakerPolicy(
        enabled=bool(cb_raw.get("enabled", routing.get("circuit_breaker_enabled", True))),
        failure_threshold=max(1, int(cb_raw.get("failure_threshold", 5) or 5)),
        recovery_timeout_seconds=float(cb_raw.get("recovery_timeout_seconds", 30) or 30),
        half_open_max_calls=max(1, int(cb_raw.get("half_open_max_calls", 1) or 1)),
    )

    targets: list[RouteTarget] = []
    raw_targets = routing.get("targets") or cfg.get("fallback_providers") or []
    if isinstance(raw_targets, list):
        for item in raw_targets:
            if not isinstance(item, dict):
                continue
            provider = str(item.get("provider") or "").strip().lower()
            if not provider:
                continue
            targets.append(
                RouteTarget(
                    provider=provider,
                    weight=float(item.get("weight") or 1.0),
                    api_key=(str(item["api_key"]) if item.get("api_key") else None),
                    base_url=(str(item["base_url"]).rstrip("/") if item.get("base_url") else None),
                    label=(str(item["label"]) if item.get("label") else None),
                )
            )

    backoff = int(routing.get("retry_backoff_ms", 100) or 100)
    backoff_max = int(routing.get("retry_backoff_max_ms", 2000) or 2000)
    return RoutingPolicy(
        max_retries=max(0, min(max_retries, 8)),
        targets=targets,
        cache_ttl_seconds=max(0, min(cache_ttl, 86400)),
        cache_enabled=cache_enabled and cache_ttl > 0,
        circuit_breaker=circuit,
        retry_backoff_ms=max(0, min(backoff, 10_000)),
        retry_backoff_max_ms=max(backoff, min(backoff_max, 30_000)),
    )


def pick_weighted_target(targets: list[RouteTarget]) -> RouteTarget | None:
    if not targets:
        return None
    weights = [max(0.0, t.weight) for t in targets]
    if sum(weights) <= 0:
        return random.choice(targets)
    return random.choices(targets, weights=weights, k=1)[0]


def merge_target_into_config(config: dict[str, Any], target: RouteTarget) -> dict[str, Any]:
    out = dict(config)
    out["provider"] = target.provider
    out["backend"] = target.provider
    if target.api_key:
        out["api_key"] = target.api_key
    if target.base_url:
        out["base_url"] = target.base_url
    return out


def cache_key(*, provider: str, model: str, body: dict[str, Any], capability: str) -> str:
    material = {
        "provider": provider,
        "model": model,
        "capability": capability,
        "messages": body.get("messages"),
        "input": body.get("input"),
        "prompt": body.get("prompt"),
        "tools": body.get("tools"),
        "temperature": body.get("temperature"),
    }
    blob = json.dumps(material, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def cache_get(key: str) -> tuple[int, dict[str, Any]] | None:
    client = get_redis_client()
    if client is not None:
        try:
            raw = client.get(f"{_CACHE_PREFIX}{key}")
            if not raw:
                return None
            payload = json.loads(raw)
            return int(payload["status"]), dict(payload["body"])
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis cache_get failed: %s", exc)

    now = time.monotonic()
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if not entry:
            return None
        if entry.expires_at < now:
            _CACHE.pop(key, None)
            return None
        return entry.status, dict(entry.body)


def cache_set(key: str, status: int, body: dict[str, Any], ttl: int) -> None:
    if ttl <= 0 or status >= 400:
        return
    client = get_redis_client()
    if client is not None:
        try:
            client.setex(
                f"{_CACHE_PREFIX}{key}",
                int(ttl),
                json.dumps({"status": status, "body": body}, default=str),
            )
            return
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis cache_set failed: %s", exc)

    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX:
            now = time.monotonic()
            expired = [k for k, v in _CACHE.items() if v.expires_at < now]
            for k in expired[:128] or list(_CACHE.keys())[:128]:
                _CACHE.pop(k, None)
        _CACHE[key] = _CacheEntry(
            expires_at=time.monotonic() + ttl,
            status=status,
            body=dict(body),
        )


def circuit_key(provider: str, *, label: str | None = None) -> str:
    return f"{provider.strip().lower()}:{label or 'default'}"


def circuit_allow(provider: str, policy: RoutingPolicy, *, label: str | None = None) -> bool:
    """Return False when the circuit is open and still cooling down."""
    if not policy.circuit_breaker.enabled:
        return True
    key = circuit_key(provider, label=label)
    now = time.monotonic()
    cb = policy.circuit_breaker

    client = get_redis_client()
    if client is not None:
        try:
            raw = client.hgetall(f"{_CIRCUIT_PREFIX}{key}")
            if not raw:
                return True
            state = raw.get("state") or "closed"
            opened_at = float(raw.get("opened_at") or 0)
            if state == "open":
                if now - opened_at >= cb.recovery_timeout_seconds:
                    client.hset(f"{_CIRCUIT_PREFIX}{key}", mapping={"state": "half_open", "half_open_successes": 0})
                    return True
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis circuit_allow failed: %s", exc)

    with _CIRCUIT_LOCK:
        st = _CIRCUITS.get(key) or _CircuitState()
        if st.state == "open":
            if now - st.opened_at >= cb.recovery_timeout_seconds:
                st.state = "half_open"
                st.half_open_successes = 0
                _CIRCUITS[key] = st
                return True
            return False
        return True


def circuit_record_success(provider: str, policy: RoutingPolicy, *, label: str | None = None) -> None:
    if not policy.circuit_breaker.enabled:
        return
    key = circuit_key(provider, label=label)
    client = get_redis_client()
    if client is not None:
        try:
            client.delete(f"{_CIRCUIT_PREFIX}{key}")
            return
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis circuit_record_success failed: %s", exc)
    with _CIRCUIT_LOCK:
        _CIRCUITS[key] = _CircuitState()


def circuit_record_failure(provider: str, policy: RoutingPolicy, *, label: str | None = None) -> None:
    if not policy.circuit_breaker.enabled:
        return
    key = circuit_key(provider, label=label)
    cb = policy.circuit_breaker
    now = time.monotonic()
    client = get_redis_client()
    if client is not None:
        try:
            redis_key = f"{_CIRCUIT_PREFIX}{key}"
            failures = int(client.hincrby(redis_key, "failures", 1))
            client.hsetnx(redis_key, "state", "closed")
            client.expire(redis_key, int(cb.recovery_timeout_seconds * 4) + 60)
            if failures >= cb.failure_threshold:
                client.hset(
                    redis_key,
                    mapping={"state": "open", "opened_at": str(now)},
                )
            return
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis circuit_record_failure failed: %s", exc)

    with _CIRCUIT_LOCK:
        st = _CIRCUITS.get(key) or _CircuitState()
        st.failures += 1
        if st.failures >= cb.failure_threshold:
            st.state = "open"
            st.opened_at = now
        _CIRCUITS[key] = st


def execute_with_retries(
    *,
    attempt: Callable[[], tuple[int, dict[str, Any]]],
    policy: RoutingPolicy,
) -> tuple[int, dict[str, Any], int]:
    """
    Run ``attempt`` with exponential backoff on configured upstream status codes.

    Returns (status, body, attempts_used).
    """
    attempts = 0
    last_status = 502
    last_body: dict[str, Any] = {
        "error": {"message": "upstream unavailable", "type": "upstream_error"}
    }
    max_tries = 1 + int(policy.max_retries)
    for i in range(max_tries):
        attempts += 1
        try:
            status, body = attempt()
        except Exception as exc:  # noqa: BLE001
            # Policy blocks must not be rewritten as generic upstream failures.
            from eeg.gateway.proxy import GatewayBlockedError

            if isinstance(exc, GatewayBlockedError):
                raise
            last_status = 502
            last_body = {
                "error": {
                    "message": f"Upstream request failed: {exc}",
                    "type": "upstream_error",
                    "code": "upstream_error",
                }
            }
            _sleep_backoff(policy, i)
            continue
        last_status, last_body = status, body
        if status < 400 or status not in policy.retry_on_status:
            return status, body, attempts
        _sleep_backoff(policy, i)
    return last_status, last_body, attempts


def _sleep_backoff(policy: RoutingPolicy, attempt_index: int) -> None:
    base = policy.retry_backoff_ms
    if base <= 0:
        return
    delay = min(policy.retry_backoff_max_ms, base * (2**attempt_index))
    jitter = random.uniform(0, delay * 0.2)
    time.sleep((delay + jitter) / 1000.0)


def ordered_fallback_configs(
    primary: dict[str, Any],
    policy: RoutingPolicy,
) -> list[dict[str, Any]]:
    """Primary config first (if circuit allows), then weighted fallback targets."""
    configs: list[dict[str, Any]] = []
    primary_provider = str(primary.get("provider") or "").lower()
    if circuit_allow(primary_provider or "unknown", policy):
        configs.append(dict(primary))

    remaining = list(policy.targets)
    while remaining:
        picked = pick_weighted_target(remaining)
        if picked is None:
            break
        remaining = [t for t in remaining if t is not picked]
        if picked.provider == primary_provider and not picked.api_key and not picked.base_url:
            continue
        if not circuit_allow(picked.provider, policy, label=picked.label):
            continue
        configs.append(merge_target_into_config(primary, picked))

    # Fail-open: if every circuit is open, still attempt primary once.
    if not configs:
        configs.append(dict(primary))
    return configs


def reset_routing_state_for_tests() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
    with _CIRCUIT_LOCK:
        _CIRCUITS.clear()
