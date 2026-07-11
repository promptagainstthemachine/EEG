"""Policy decisions for runtime gateway and trace ingest."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from eeg.runtime.risk_scorer import RiskAssessment

DEFAULT_BLOCK_THRESHOLD = 0.75
DEFAULT_INGEST_THRESHOLD = 0.9


@dataclass
class PolicyDecision:
    blocked: bool
    reason: str
    risk_score: float
    risk_signals: list
    phase: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "risk_signals": self.risk_signals,
            "phase": self.phase,
        }


def evaluate_policy(
    assessment: RiskAssessment,
    *,
    phase: str = "request",
    enforcement_enabled: bool = True,
    runtime_protection_enabled: bool = True,
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
    ingest_threshold: float = DEFAULT_INGEST_THRESHOLD,
) -> PolicyDecision:
    """
    Decide whether to block a live request/response or trace ingest.

    Gateway uses ``block_threshold``; ingest uses ``ingest_threshold`` when
  ``phase`` is ``ingest``.
    """
    if not enforcement_enabled and not runtime_protection_enabled:
        return PolicyDecision(
            blocked=False,
            reason="",
            risk_score=assessment.risk_score,
            risk_signals=[s.to_dict() for s in assessment.risk_signals],
            phase=phase,
        )

    threshold = ingest_threshold if phase == "ingest" else block_threshold
    active = runtime_protection_enabled if phase in ("request", "response") else enforcement_enabled

    if not active:
        return PolicyDecision(
            blocked=False,
            reason="",
            risk_score=assessment.risk_score,
            risk_signals=[s.to_dict() for s in assessment.risk_signals],
            phase=phase,
        )

    if assessment.risk_score >= threshold:
        return PolicyDecision(
            blocked=True,
            reason=f"Server risk_score {assessment.risk_score:.2f} exceeds threshold {threshold}",
            risk_score=assessment.risk_score,
            risk_signals=[s.to_dict() for s in assessment.risk_signals],
            phase=phase,
        )

    for sig in assessment.risk_signals:
        if sig.severity_band == "critical":
            return PolicyDecision(
                blocked=True,
                reason=f"Critical runtime signal: {sig.category}",
                risk_score=assessment.risk_score,
                risk_signals=[s.to_dict() for s in assessment.risk_signals],
                phase=phase,
            )

    return PolicyDecision(
        blocked=False,
        reason="",
        risk_score=assessment.risk_score,
        risk_signals=[s.to_dict() for s in assessment.risk_signals],
        phase=phase,
    )
