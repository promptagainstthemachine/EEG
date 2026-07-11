"""Gateway SLO metrics: latency histograms, error rates, cache/circuit counters."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from eeg.gateway.redis_client import get_redis_client

_LOCK = threading.Lock()
_WINDOW_SEC = 300  # 5-minute rolling window for in-memory SLO
_MAX_SAMPLES = 10_000

_latencies: dict[str, deque[tuple[float, float]]] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))
_counts: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))
_counters: dict[str, int] = defaultdict(int)


@dataclass
class RequestSample:
    provider: str
    capability: str
    status: int
    latency_ms: float
    cache_hit: bool = False
    circuit_open: bool = False


def record_request(sample: RequestSample) -> None:
    key = f"{sample.provider}:{sample.capability}"
    now = time.time()
    with _LOCK:
        _latencies[key].append((now, float(sample.latency_ms)))
        outcome = "error" if sample.status >= 500 else ("client_error" if sample.status >= 400 else "ok")
        _counts[key].append((now, outcome))
        _counters["requests_total"] += 1
        if sample.status >= 500:
            _counters["errors_5xx"] += 1
        elif sample.status >= 400:
            _counters["errors_4xx"] += 1
        if sample.cache_hit:
            _counters["cache_hits"] += 1
        if sample.circuit_open:
            _counters["circuit_skips"] += 1

    client = get_redis_client()
    if client is None:
        return
    try:
        pipe = client.pipeline()
        pipe.hincrby("eeg:gw:slo:counters", "requests_total", 1)
        if sample.status >= 500:
            pipe.hincrby("eeg:gw:slo:counters", "errors_5xx", 1)
        elif sample.status >= 400:
            pipe.hincrby("eeg:gw:slo:counters", "errors_4xx", 1)
        if sample.cache_hit:
            pipe.hincrby("eeg:gw:slo:counters", "cache_hits", 1)
        # Keep a short list of latencies per key (capped)
        lat_key = f"eeg:gw:slo:lat:{key}"
        pipe.lpush(lat_key, f"{sample.latency_ms:.3f}")
        pipe.ltrim(lat_key, 0, 999)
        pipe.expire(lat_key, _WINDOW_SEC * 2)
        pipe.execute()
    except Exception:  # noqa: BLE001
        pass


def snapshot(*, window_sec: int = _WINDOW_SEC) -> dict[str, Any]:
    now = time.time()
    cutoff = now - window_sec
    by_route: dict[str, Any] = {}

    with _LOCK:
        keys = set(_latencies.keys()) | set(_counts.keys())
        for key in keys:
            lats = [v for ts, v in _latencies.get(key, ()) if ts >= cutoff]
            outcomes = [o for ts, o in _counts.get(key, ()) if ts >= cutoff]
            total = len(outcomes) or len(lats)
            errors = sum(1 for o in outcomes if o == "error")
            client_errors = sum(1 for o in outcomes if o == "client_error")
            by_route[key] = {
                "requests": total,
                "error_rate_5xx": (errors / total) if total else 0.0,
                "error_rate_4xx": (client_errors / total) if total else 0.0,
                "latency_ms": _percentiles(lats),
            }
        counters = dict(_counters)

    return {
        "window_seconds": window_sec,
        "generated_at": int(now),
        "counters": counters,
        "routes": by_route,
        "slo": {
            "availability_target": 0.999,
            "latency_p95_target_ms": 2000,
            "observed_availability": _overall_availability(by_route),
            "observed_p95_ms": _overall_p95(by_route),
        },
    }


def _percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0, "max": 0.0}
    ordered = sorted(values)
    n = len(ordered)

    def pct(p: float) -> float:
        idx = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
        return float(ordered[idx])

    return {
        "p50": pct(50),
        "p95": pct(95),
        "p99": pct(99),
        "avg": float(sum(ordered) / n),
        "max": float(ordered[-1]),
    }


def _overall_availability(by_route: dict[str, Any]) -> float:
    total = sum(int(r.get("requests") or 0) for r in by_route.values())
    if not total:
        return 1.0
    errors = sum(
        int(r.get("requests") or 0) * float(r.get("error_rate_5xx") or 0.0) for r in by_route.values()
    )
    return max(0.0, 1.0 - (errors / total))


def _overall_p95(by_route: dict[str, Any]) -> float:
    p95s = [
        float((r.get("latency_ms") or {}).get("p95") or 0.0)
        for r in by_route.values()
        if (r.get("latency_ms") or {}).get("p95")
    ]
    return max(p95s) if p95s else 0.0


def reset_slo_for_tests() -> None:
    with _LOCK:
        _latencies.clear()
        _counts.clear()
        _counters.clear()
