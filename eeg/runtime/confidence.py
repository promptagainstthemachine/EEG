"""Assessment confidence helpers for multi-signal runtime decisions."""

from __future__ import annotations

from typing import Iterable, Sequence


def _variance(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def layer_agreement_confidence(
    scores: Iterable[float],
    strong_floor: float = 0.8,
    strong_min_confidence: float = 0.75,
) -> float:
    """Higher when independent scoring layers agree; single layer returns 1.0."""
    invoked = [float(s) for s in scores if s is not None]
    if len(invoked) <= 1:
        return 1.0
    variance = _variance(invoked)
    confidence = 1.0 / (1.0 + variance * 5.0)
    if max(invoked) >= strong_floor:
        confidence = max(confidence, strong_min_confidence)
    return round(min(confidence, 1.0), 4)


def guardrail_confidence(
    signal_score: float,
    block_threshold: float = 0.7,
    sanitize_threshold: float = 0.4,
) -> float:
    """Tiered confidence for deterministic guardrail hits (PII, toxicity)."""
    if signal_score >= block_threshold:
        raw = 0.90 + (min(signal_score, 1.0) - block_threshold) * 0.05
        return round(min(raw, 0.95), 4)
    if signal_score >= sanitize_threshold:
        raw = 0.70 + (signal_score - sanitize_threshold) * 0.20
        return round(min(raw, 0.84), 4)
    return 0.0


def confidence_band(confidence: float) -> str:
    if confidence >= 0.7:
        return "HIGH"
    if confidence >= 0.4:
        return "MEDIUM"
    return "LOW"


def combined_assessment_confidence(
    rule_score: float = 0.0,
    heuristic_score: float = 0.0,
    guardrail_score: float = 0.0,
    guardrail_triggered: bool = False,
) -> tuple[float, str]:
    """Return (confidence, band). Guardrail hits take priority over layer agreement."""
    if guardrail_triggered:
        conf = guardrail_confidence(guardrail_score)
    else:
        conf = layer_agreement_confidence([rule_score, heuristic_score])
    return conf, confidence_band(conf)
