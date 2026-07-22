"""Runtime ML wrap — multi-model inspection before agent dispatch."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.confidence import combined_assessment_confidence
from eeg.runtime.policy_config import RuntimePolicyConfig
from eeg.runtime.risk_scorer import RiskAssessment, score_text
from eeg.runtime.runtime_ml_guard import assess_runtime_text, assess_tool_runtime
from eeg.runtime.verdict_forge import (
    ForgedVerdict,
    SessionEscalator,
    forge_verdict,
)

_DEFAULT_ESCALATOR = SessionEscalator()


@dataclass
class LatticeResult:
    assessment: RiskAssessment
    verdict: ForgedVerdict
    layer_scores: dict[str, float] = field(default_factory=dict)
    raw_layers: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict.action == "block"


def _tool_text(tool_name: str, tool_arguments: Any) -> str:
    parts: list[str] = []
    if tool_name:
        parts.append(str(tool_name))
    if tool_arguments is not None:
        parts.append(str(tool_arguments))
    return " ".join(parts).strip()


def inspect_lattice(
    text: str,
    *,
    phase: str = "request",
    prior_prompt: str = "",
    config: RuntimePolicyConfig | None = None,
    session_id: str = "default",
    tool_name: str = "",
    tool_arguments: Any = None,
    shard_buffer: Any = None,
    escalator: SessionEscalator | None = None,
) -> LatticeResult:
    cfg = config or RuntimePolicyConfig()
    esc = escalator or _DEFAULT_ESCALATOR

    heuristic = score_text(text, phase=phase, prior_prompt=prior_prompt)
    ml = assess_runtime_text(text or "", phase=phase)

    tool_ml = None
    tool_payload = _tool_text(tool_name, tool_arguments)
    if tool_payload:
        tool_ml = assess_tool_runtime(tool_payload)

    layer_scores = dict(ml.layer_scores)
    if tool_ml:
        for k, v in tool_ml.layer_scores.items():
            layer_scores[k] = max(layer_scores.get(k, 0.0), v)

    fused = max(
        heuristic.risk_score,
        ml.score,
        tool_ml.score if tool_ml else 0.0,
    )
    layer_scores["neural_runtime"] = fused
    layer_scores["fused"] = fused

    threats = sorted(set(heuristic.categories) | set(ml.categories) | (set(tool_ml.categories) if tool_ml else set()))
    signals = list(heuristic.risk_signals)

    pii_score = float(layer_scores.get("pii", 0.0))
    toxicity_score = float(layer_scores.get("toxicity", 0.0))
    guardrail_triggered = (
        pii_score >= cfg.pii_sanitize_threshold or toxicity_score >= cfg.toxicity_sanitize_threshold
    )

    conf, band = combined_assessment_confidence(
        rule_score=ml.score,
        heuristic_score=fused,
        guardrail_score=max(pii_score, toxicity_score),
        guardrail_triggered=guardrail_triggered,
    )

    assessment = RiskAssessment(
        risk_score=fused,
        risk_signals=signals,
        categories=threats,
    )

    verdict = forge_verdict(
        detection_score=fused,
        pii_score=pii_score,
        toxicity_score=toxicity_score,
        threats=threats,
        layer_scores=layer_scores,
        block_threshold=cfg.block_threshold,
        sanitize_threshold=cfg.sanitize_threshold,
        pii_block_threshold=cfg.pii_block_threshold,
        toxicity_block_threshold=cfg.toxicity_block_threshold,
        confidence=conf,
        confidence_band=band,
        active=cfg.active,
    )
    if session_id and session_id != "default":
        verdict = esc.upgrade(session_id, verdict)
        if verdict.action in {"block", "sanitize"}:
            esc.record(session_id, verdict.action)

    raw_layers: dict[str, Any] = {
        "runtime_ml": ml.to_layer_dict(),
        "heuristic": heuristic.to_dict(),
    }
    if tool_ml:
        raw_layers["runtime_tool_ml"] = tool_ml.to_layer_dict()

    return LatticeResult(
        assessment=assessment,
        verdict=verdict,
        layer_scores=layer_scores,
        raw_layers=raw_layers,
    )


def lattice_result_payload(result: LatticeResult) -> dict[str, Any]:
    verdict = result.verdict
    assessment = result.assessment
    return {
        "blocked": verdict.action == "block",
        "allowed": verdict.action != "block",
        "action": verdict.action,
        "tier": verdict.tier,
        "primary_reason": verdict.primary_reason,
        "risk_score": round(assessment.risk_score, 4),
        "confidence": round(verdict.confidence, 4),
        "confidence_band": verdict.confidence_band,
        "threats": list(assessment.categories),
        "detection_tags": list(assessment.categories),
        "layer_scores": {k: round(float(v), 4) for k, v in result.layer_scores.items()},
        "layers": dict(result.raw_layers),
        "risk_signals": [s.to_dict() for s in assessment.risk_signals],
        "sanitized_text": verdict.sanitized_text,
        "escalated": bool(verdict.escalated),
    }
