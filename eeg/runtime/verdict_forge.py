"""Verdict forge — guardrail-first tiering and session escalation."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Literal

Tier = Literal["allow", "sanitize", "block"]
Action = Literal["allow", "sanitize", "block"]


@dataclass
class ForgedVerdict:
    action: Action
    tier: Tier
    primary_reason: str
    risk_score: float
    confidence: float
    confidence_band: str
    layer_scores: dict[str, float] = field(default_factory=dict)
    threats: list[str] = field(default_factory=list)
    sanitized_text: str | None = None
    escalated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "tier": self.tier,
            "primary_reason": self.primary_reason,
            "risk_score": round(self.risk_score, 4),
            "confidence": round(self.confidence, 4),
            "confidence_band": self.confidence_band,
            "layer_scores": {k: round(v, 4) for k, v in self.layer_scores.items()},
            "threats": list(self.threats),
            "sanitized": self.sanitized_text is not None,
            "escalated": self.escalated,
        }


def fuse_detection_score(
    *,
    sigil: float = 0.0,
    spectral: float = 0.0,
    heuristic: float = 0.0,
    tool: float = 0.0,
    shard: float = 0.0,
    weight_sigil: float = 0.34,
    weight_spectral: float = 0.28,
    weight_heuristic: float = 0.18,
    weight_tool: float = 0.12,
    weight_shard: float = 0.08,
    boost_threshold: float = 0.5,
) -> tuple[float, bool]:
    """Weighted fuse with anti-dilution boost when any layer fires hard."""
    layers = {
        "sigil": max(0.0, min(1.0, sigil)),
        "spectral": max(0.0, min(1.0, spectral)),
        "heuristic": max(0.0, min(1.0, heuristic)),
        "tool": max(0.0, min(1.0, tool)),
        "shard": max(0.0, min(1.0, shard)),
    }
    weighted = (
        layers["sigil"] * weight_sigil
        + layers["spectral"] * weight_spectral
        + layers["heuristic"] * weight_heuristic
        + layers["tool"] * weight_tool
        + layers["shard"] * weight_shard
    )
    peak = max(layers.values())
    boosted = False
    if peak >= boost_threshold:
        weighted = max(weighted, peak)
        boosted = True
    return min(1.0, weighted), boosted


def forge_verdict(
    *,
    detection_score: float,
    pii_score: float = 0.0,
    toxicity_score: float = 0.0,
    threats: list[str] | None = None,
    layer_scores: dict[str, float] | None = None,
    block_threshold: float = 0.75,
    sanitize_threshold: float = 0.4,
    pii_block_threshold: float = 0.7,
    toxicity_block_threshold: float = 0.7,
    confidence: float = 0.0,
    confidence_band: str = "LOW",
    sanitized_text: str | None = None,
    active: bool = True,
) -> ForgedVerdict:
    """Guardrails first (PII/toxicity), then detection thresholds."""
    threats = list(threats or [])
    layers = dict(layer_scores or {})
    if not active:
        return ForgedVerdict(
            action="allow",
            tier="allow",
            primary_reason="NO_THREAT_DETECTED",
            risk_score=detection_score,
            confidence=max(confidence, 1.0 if detection_score <= 0 else confidence),
            confidence_band="HIGH" if detection_score <= 0 else confidence_band,
            layer_scores=layers,
            threats=threats,
        )

    if pii_score >= pii_block_threshold:
        return ForgedVerdict(
            action="block",
            tier="block",
            primary_reason="PII_GUARDRAIL_BLOCK",
            risk_score=max(detection_score, pii_score),
            confidence=max(confidence, 0.9),
            confidence_band="HIGH",
            layer_scores=layers,
            threats=sorted(set(threats + ["pii"])),
        )
    if toxicity_score >= toxicity_block_threshold:
        return ForgedVerdict(
            action="block",
            tier="block",
            primary_reason="TOXICITY_GUARDRAIL_BLOCK",
            risk_score=max(detection_score, toxicity_score),
            confidence=max(confidence, 0.9),
            confidence_band="HIGH",
            layer_scores=layers,
            threats=sorted(set(threats + ["toxicity"])),
        )
    if pii_score >= sanitize_threshold and sanitized_text is not None:
        return ForgedVerdict(
            action="sanitize",
            tier="sanitize",
            primary_reason="PII_GUARDRAIL_SANITIZE",
            risk_score=max(detection_score, pii_score),
            confidence=max(confidence, 0.75),
            confidence_band="HIGH",
            layer_scores=layers,
            threats=sorted(set(threats + ["pii"])),
            sanitized_text=sanitized_text,
        )

    if detection_score >= block_threshold:
        reason = _primary_from_layers(layers, threats) or "POLICY_BLOCK"
        return ForgedVerdict(
            action="block",
            tier="block",
            primary_reason=reason,
            risk_score=detection_score,
            confidence=confidence,
            confidence_band=confidence_band,
            layer_scores=layers,
            threats=threats,
        )
    if detection_score >= sanitize_threshold and sanitized_text is not None:
        return ForgedVerdict(
            action="sanitize",
            tier="sanitize",
            primary_reason="CONTENT_SANITIZED",
            risk_score=detection_score,
            confidence=confidence,
            confidence_band=confidence_band,
            layer_scores=layers,
            threats=threats,
            sanitized_text=sanitized_text,
        )
    if detection_score <= 0 and not threats:
        primary = "NO_THREAT_DETECTED"
    else:
        primary = "ALLOW"
    return ForgedVerdict(
        action="allow",
        tier="allow",
        primary_reason=primary,
        risk_score=detection_score,
        confidence=confidence if detection_score > 0 else 1.0,
        confidence_band=confidence_band if detection_score > 0 else "HIGH",
        layer_scores=layers,
        threats=threats,
    )


def _primary_from_layers(layers: dict[str, float], threats: list[str]) -> str:
    if not layers:
        if threats:
            return f"THREAT_{threats[0].upper().replace('-', '_').replace(' ', '_')}"
        return "POLICY_BLOCK"
    top = max(layers.items(), key=lambda kv: kv[1])
    return f"LAYER_{top[0].upper()}"


class SessionEscalator:
    """Escalate repeated blocks/quarantines within a rolling window."""

    def __init__(self, *, window_sec: float = 3600.0, flag_at: int = 3, block_at: int = 5):
        self.window_sec = window_sec
        self.flag_at = flag_at
        self.block_at = block_at
        self._events: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)

    def record(self, session_id: str, action: str) -> None:
        now = time.time()
        q = self._events[session_id]
        q.append((now, action))
        self._prune(q, now)

    def upgrade(self, session_id: str, verdict: ForgedVerdict) -> ForgedVerdict:
        now = time.time()
        q = self._events[session_id]
        self._prune(q, now)
        harsh = sum(1 for _, a in q if a in {"block", "sanitize"})
        if harsh >= self.block_at and verdict.action != "block":
            verdict.action = "block"
            verdict.tier = "block"
            verdict.primary_reason = "SESSION_ESCALATION_BLOCK"
            verdict.escalated = True
            verdict.risk_score = max(verdict.risk_score, 0.9)
        elif harsh >= self.flag_at and verdict.action == "allow":
            verdict.action = "sanitize"
            verdict.tier = "sanitize"
            verdict.primary_reason = "SESSION_ESCALATION_FLAG"
            verdict.escalated = True
            verdict.risk_score = max(verdict.risk_score, 0.55)
        return verdict

    def _prune(self, q: Deque[tuple[float, str]], now: float) -> None:
        while q and now - q[0][0] > self.window_sec:
            q.popleft()
