"""Lattice pipeline — multi-layer runtime inspection orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from eeg.runtime.confidence import combined_assessment_confidence
from eeg.runtime.policy_config import RuntimePolicyConfig
from eeg.runtime.risk_scorer import RiskAssessment, RiskSignal, score_text
from eeg.runtime.shard_buffer import ShardBuffer, ShardAssessment
from eeg.runtime.sigil_weave import weave_sigils
from eeg.runtime.spectral_probe import probe_spectrum
from eeg.runtime.tool_weave import ToolChainTracker, ToolWeaveAssessment, weave_tools
from eeg.runtime.verdict_forge import (
    ForgedVerdict,
    SessionEscalator,
    forge_verdict,
    fuse_detection_score,
)

_DEFAULT_SHARDS = ShardBuffer()
_DEFAULT_ESCALATOR = SessionEscalator()
_DEFAULT_TOOL_TRACKERS: dict[str, ToolChainTracker] = {}


@dataclass
class LatticeResult:
    assessment: RiskAssessment
    verdict: ForgedVerdict
    layer_scores: dict[str, float] = field(default_factory=dict)
    raw_layers: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict.action == "block"


def _pii_score_from_heuristic(assessment: RiskAssessment) -> float:
    for sig in assessment.risk_signals:
        if sig.category == "pii":
            return max(0.7, _band_to_score(sig.severity_band))
    return 0.0


def _toxicity_score_from_layers(
    assessment: RiskAssessment,
    spectral_label: str,
    spectral_score: float,
) -> float:
    score = 0.0
    if spectral_label in {"toxicity", "weapons_harm", "malicious_intent"}:
        score = max(score, spectral_score)
    for sig in assessment.risk_signals:
        if sig.category in {"toxicity", "weapons_harm"}:
            score = max(score, _band_to_score(sig.severity_band))
    return score


def _band_to_score(band: str) -> float:
    return {
        "critical": 0.95,
        "high": 0.85,
        "medium": 0.55,
        "low": 0.3,
        "info": 0.1,
    }.get((band or "").lower(), 0.4)


def inspect_lattice(
    text: str,
    *,
    phase: str = "request",
    prior_prompt: str = "",
    config: RuntimePolicyConfig | None = None,
    session_id: str = "default",
    tool_name: str = "",
    tool_arguments: Any = None,
    shard_buffer: ShardBuffer | None = None,
    escalator: SessionEscalator | None = None,
) -> LatticeResult:
    """
    Run sigil + spectral + heuristic + tool + shard layers, fuse, and forge a verdict.
    """
    cfg = config or RuntimePolicyConfig()
    shards = shard_buffer or _DEFAULT_SHARDS
    esc = escalator or _DEFAULT_ESCALATOR

    heuristic = score_text(text, phase=phase, prior_prompt=prior_prompt)
    sigils = weave_sigils(text)
    spectral = probe_spectrum(text)

    tracker = _DEFAULT_TOOL_TRACKERS.setdefault(session_id, ToolChainTracker())
    tools = (
        weave_tools(tool_name=tool_name, arguments=tool_arguments, tracker=tracker)
        if (tool_name or tool_arguments)
        else ToolWeaveAssessment()
    )

    shard: ShardAssessment = ShardAssessment()
    if phase == "request" and text and len(str(text).strip()) >= 12:
        shard = shards.ingest(session_id, text)

    fused, boosted = fuse_detection_score(
        sigil=sigils.score,
        spectral=spectral.score,
        heuristic=heuristic.risk_score,
        tool=tools.score,
        shard=shard.score if shard.triggered else 0.0,
    )

    layer_scores = {
        "sigil": sigils.score,
        "spectral": spectral.score,
        "heuristic": heuristic.risk_score,
        "tool": tools.score,
        "shard": shard.score,
        "fused": fused,
    }

    threats: list[str] = []
    threats.extend(sigils.categories)
    if spectral.score >= 0.35 and spectral.label != "benign":
        threats.append(spectral.label)
    threats.extend(heuristic.categories)
    for hit in tools.hits:
        threats.extend(hit.categories or [hit.kind])
    threats.extend(shard.categories)
    threats = sorted({t for t in threats if t})

    signals = list(heuristic.risk_signals)
    for hit in sigils.hits:
        signals.append(
            RiskSignal(
                category=hit.category,
                severity_band=hit.severity,
                message=f"Sigil {hit.sigil_id}: {hit.matched[:80]}",
                context={"pack": hit.pack, "layer": "sigil"},
            )
        )
    if spectral.score >= 0.28:
        signals.append(
            RiskSignal(
                category=spectral.label,
                severity_band="critical" if spectral.score >= 0.75 else "high",
                message=f"Spectral probe labeled {spectral.label}",
                context={
                    "layer": "spectral",
                    "neural_assist": spectral.neural_assist,
                    "ember_assist": spectral.ember_assist,
                },
            )
        )
    for hit in tools.hits:
        signals.append(
            RiskSignal(
                category="tool_abuse",
                severity_band="high",
                message=f"Tool weave {hit.kind}: {hit.detail}",
                context={"layer": "tool", "categories": hit.categories},
            )
        )
    if shard.triggered:
        signals.append(
            RiskSignal(
                category="shard_reassembly",
                severity_band="high",
                message="Reassembled shard crossed detection threshold",
                context={"layer": "shard", "len": shard.reassembled_len},
            )
        )

    assessment = RiskAssessment(
        risk_score=fused,
        risk_signals=signals,
        categories=threats,
    )

    pii_score = _pii_score_from_heuristic(heuristic)
    toxicity_score = _toxicity_score_from_layers(heuristic, spectral.label, spectral.score)
    guardrail_triggered = pii_score >= cfg.pii_sanitize_threshold or toxicity_score >= cfg.toxicity_sanitize_threshold
    conf, band = combined_assessment_confidence(
        rule_score=sigils.score,
        heuristic_score=max(heuristic.risk_score, spectral.score),
        guardrail_score=max(pii_score, toxicity_score),
        guardrail_triggered=guardrail_triggered,
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

    return LatticeResult(
        assessment=assessment,
        verdict=verdict,
        layer_scores=layer_scores,
        raw_layers={
            "sigil": sigils.to_layer_dict(),
            "spectral": spectral.to_layer_dict(),
            "tool": tools.to_layer_dict(),
            "shard": shard.to_layer_dict(),
            "boosted": boosted,
        },
    )


def lattice_result_payload(result: LatticeResult) -> dict[str, Any]:
    """Serialize a lattice inspection for API / UI consumers."""
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
