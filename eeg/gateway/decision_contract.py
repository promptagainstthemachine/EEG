"""Stable gateway decision contract for scan-only and proxy paths."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from eeg.runtime.confidence import combined_assessment_confidence
from eeg.runtime.guard import GuardDecision

DECISION_VERSION = "eeg-1.0"

ExecutionMode = Literal["scan_only", "proxy"]
DetectionMode = Literal["fast", "full"]
ExecutionStatus = Literal[
    "SUCCESS",
    "BLOCKED",
    "OUTPUT_BLOCKED",
    "FAILED",
    "TIMEOUT",
]


def derive_primary_reason(decision: GuardDecision) -> str:
    """Map a guard decision to a stable primary_reason code."""
    if decision.policy_action == "block" or decision.blocked:
        if decision.guardrail_categories:
            cat = decision.guardrail_categories[0].upper().replace(" ", "_")
            return f"GUARDRAIL_{cat}"
        tags = [t for t in decision.detection_tags if t]
        if tags:
            return f"THREAT_{tags[0].upper().replace('-', '_').replace(' ', '_')}"
        if decision.reason:
            return "POLICY_BLOCK"
        return "POLICY_BLOCK"
    if decision.policy_action == "sanitize":
        if decision.guardrail_categories:
            cat = decision.guardrail_categories[0].upper().replace(" ", "_")
            return f"SANITIZE_{cat}"
        return "CONTENT_SANITIZED"
    if decision.risk_score <= 0.0 and not decision.detection_tags:
        return "NO_THREAT_DETECTED"
    return "ALLOW"


def enrich_guard_decision(decision: GuardDecision) -> GuardDecision:
    """Attach primary_reason / confidence fields when missing."""
    if not getattr(decision, "primary_reason", None):
        decision.primary_reason = derive_primary_reason(decision)
    guardrail_triggered = bool(decision.guardrail_categories) or decision.policy_action in {
        "block",
        "sanitize",
    }
    if decision.policy_action == "allow" and float(decision.risk_score or 0.0) <= 0.0:
        conf, band = 1.0, "HIGH"
    else:
        conf, band = combined_assessment_confidence(
            rule_score=float(decision.risk_score or 0.0),
            heuristic_score=float(decision.risk_score or 0.0),
            guardrail_score=float(decision.risk_score or 0.0),
            guardrail_triggered=guardrail_triggered and decision.policy_action != "allow",
        )
    decision.confidence = conf
    decision.confidence_band = band
    decision.decision_version = DECISION_VERSION
    return decision


@dataclass
class GatewayDecisionPayload:
    """Canonical decision object returned by scan-only and proxy paths."""

    decision: str
    primary_reason: str
    risk_score: float
    confidence: float
    confidence_band: str
    decision_version: str = DECISION_VERSION
    execution_mode: ExecutionMode = "scan_only"
    detection_mode: DetectionMode = "fast"
    threats: list[str] = field(default_factory=list)
    detection_tags: list[str] = field(default_factory=list)
    sanitized: bool = False
    sanitized_text: str | None = None
    phase: str = "request"
    tier: str = "allow"
    policy_action: str = "allow"
    blocked: bool = False
    allowed: bool = True
    layer_scores: dict[str, float] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self, *, include_debug: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "decision": self.decision,
            "decision_version": self.decision_version,
            "primary_reason": self.primary_reason,
            "risk_score": round(float(self.risk_score), 4),
            "confidence": round(float(self.confidence), 4),
            "confidence_band": self.confidence_band,
            "threats": list(self.threats),
            "detection_tags": list(self.detection_tags),
            "sanitized": self.sanitized,
            "blocked": self.blocked,
            "allowed": self.allowed,
            "tier": self.tier,
            "policy_action": self.policy_action,
            "phase": self.phase,
            "processing": {
                "execution_mode": self.execution_mode,
                "detection_mode": self.detection_mode,
                "latency_ms": round(float(self.latency_ms), 2),
            },
        }
        if self.sanitized and self.sanitized_text is not None:
            out["sanitized_text"] = self.sanitized_text
        if include_debug and self.layer_scores:
            out["debug"] = {"layer_scores": dict(self.layer_scores)}
        return out


def decision_from_guard(
    decision: GuardDecision,
    *,
    execution_mode: ExecutionMode = "scan_only",
    detection_mode: DetectionMode = "fast",
    latency_ms: float = 0.0,
    include_debug: bool = False,
) -> dict[str, Any]:
    enriched = enrich_guard_decision(decision)
    action = enriched.policy_action or ("block" if enriched.blocked else "allow")
    label = "BLOCK" if action == "block" or enriched.blocked else "SANITIZE" if action == "sanitize" else "ALLOW"
    threats = [
        str(t.get("category") if isinstance(t, dict) else t)
        for t in (enriched.risk_signals or [])
    ]
    payload = GatewayDecisionPayload(
        decision=label,
        primary_reason=enriched.primary_reason or derive_primary_reason(enriched),
        risk_score=float(enriched.risk_score or 0.0),
        confidence=float(getattr(enriched, "confidence", 1.0) or 1.0),
        confidence_band=str(getattr(enriched, "confidence_band", "HIGH") or "HIGH"),
        decision_version=str(getattr(enriched, "decision_version", DECISION_VERSION)),
        execution_mode=execution_mode,
        detection_mode=detection_mode,
        threats=[t for t in threats if t],
        detection_tags=list(enriched.detection_tags or []),
        sanitized=action == "sanitize",
        sanitized_text=enriched.sanitized_text,
        phase=enriched.phase,
        tier=enriched.tier,
        policy_action=action,
        blocked=bool(enriched.blocked),
        allowed=not bool(enriched.blocked),
        layer_scores={"risk": float(enriched.risk_score or 0.0)},
        latency_ms=latency_ms,
    )
    return payload.to_dict(include_debug=include_debug)


def normalize_detection_mode(raw: str | None) -> DetectionMode:
    value = (raw or "fast").strip().lower()
    return "full" if value == "full" else "fast"
