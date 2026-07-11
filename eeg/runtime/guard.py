"""OSS runtime guard: lattice inspection → allow / sanitize / block."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.lattice_pipeline import LatticeResult, inspect_lattice
from eeg.runtime.policy_config import RuntimePolicyConfig
from eeg.runtime.risk_scorer import RiskAssessment


@dataclass
class GuardDecision:
    blocked: bool
    reason: str
    risk_score: float
    risk_signals: list
    phase: str
    tier: str = "allow"
    policy_action: str = "allow"
    detection_tags: list[str] = field(default_factory=list)
    sanitized_text: str | None = None
    guardrail_categories: list[str] = field(default_factory=list)
    primary_reason: str = ""
    confidence: float = 0.0
    confidence_band: str = "LOW"
    decision_version: str = "eeg-1.0"
    layer_scores: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "risk_signals": self.risk_signals,
            "phase": self.phase,
            "tier": self.tier,
            "policy_action": self.policy_action,
            "detection_tags": self.detection_tags,
            "sanitized_text": self.sanitized_text,
            "guardrail_categories": self.guardrail_categories,
            "primary_reason": self.primary_reason,
            "confidence": self.confidence,
            "confidence_band": self.confidence_band,
            "decision_version": self.decision_version,
            "layer_scores": dict(self.layer_scores),
        }


def _message_content(msg: Any) -> str:
    if isinstance(msg, str):
        return msg
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            str(block.get("text", ""))
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return ""


def _format_conversation(messages: list[Any]) -> str:
    lines: list[str] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "user")
        text = _message_content(msg).strip()
        if text:
            lines.append(f"[{role}]: {text}")
    return "\n".join(lines)


def _lattice_to_decision(result: LatticeResult, *, phase: str) -> GuardDecision:
    verdict = result.verdict
    assessment = result.assessment
    blocked = verdict.action == "block"
    reason = ""
    if blocked:
        reason = verdict.primary_reason or "Blocked by EEG runtime lattice"
    elif verdict.action == "sanitize":
        reason = verdict.primary_reason or "Content sanitized by EEG runtime lattice"
    return GuardDecision(
        blocked=blocked,
        reason=reason,
        risk_score=assessment.risk_score,
        risk_signals=[s.to_dict() for s in assessment.risk_signals],
        phase=phase,
        tier=verdict.tier,
        policy_action=verdict.action,
        detection_tags=list(assessment.categories),
        sanitized_text=verdict.sanitized_text,
        guardrail_categories=[
            t for t in assessment.categories if t in {"pii", "toxicity"}
        ],
        primary_reason=verdict.primary_reason,
        confidence=verdict.confidence,
        confidence_band=verdict.confidence_band,
        layer_scores=dict(result.layer_scores),
    )


def _finalize_decision(decision: GuardDecision) -> GuardDecision:
    from eeg.gateway.decision_contract import enrich_guard_decision

    return enrich_guard_decision(decision)


def guard_text(
    text: str,
    *,
    phase: str = "request",
    prior_prompt: str = "",
    config: RuntimePolicyConfig | None = None,
    session_id: str = "default",
    tool_name: str = "",
    tool_arguments: Any = None,
) -> GuardDecision:
    cfg = config or RuntimePolicyConfig()
    if not text or not str(text).strip():
        return _finalize_decision(
            GuardDecision(
                blocked=False,
                reason="",
                risk_score=0.0,
                risk_signals=[],
                phase=phase,
                tier="allow",
                policy_action="allow",
                primary_reason="NO_THREAT_DETECTED",
                confidence=1.0,
                confidence_band="HIGH",
            )
        )
    result = inspect_lattice(
        str(text),
        phase=phase,
        prior_prompt=prior_prompt,
        config=cfg,
        session_id=session_id,
        tool_name=tool_name,
        tool_arguments=tool_arguments,
    )
    return _finalize_decision(_lattice_to_decision(result, phase=phase))


def guard_messages(
    messages: list[Any],
    *,
    phase: str = "request",
    config: RuntimePolicyConfig | None = None,
    enforcement_enabled: bool | None = None,
    runtime_protection_enabled: bool | None = None,
    block_threshold: float | None = None,
    session_id: str = "default",
) -> tuple[GuardDecision, list[dict[str, Any]] | None]:
    cfg = config or RuntimePolicyConfig()
    if enforcement_enabled is not None:
        cfg.enforcement_enabled = enforcement_enabled
    if runtime_protection_enabled is not None:
        cfg.runtime_protection_enabled = runtime_protection_enabled
    if block_threshold is not None:
        cfg.block_threshold = block_threshold

    if phase == "response":
        assistant_parts: list[str] = []
        for msg in messages or []:
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                text = _message_content(msg)
                if text:
                    assistant_parts.append(text)
        prior = _format_conversation(
            [m for m in (messages or []) if isinstance(m, dict) and m.get("role") != "assistant"]
        )
        text = assistant_parts[-1] if assistant_parts else _format_conversation(messages or [])
        decision = guard_text(text, phase="response", prior_prompt=prior, config=cfg, session_id=session_id)
        if decision.policy_action == "sanitize" and decision.sanitized_text is not None:
            sanitized = copy.deepcopy(messages)
            for msg in reversed(sanitized):
                if isinstance(msg, dict) and msg.get("role") == "assistant":
                    msg["content"] = decision.sanitized_text
                    break
            return decision, sanitized
        return decision, None

    conversation = _format_conversation(messages or []) or _message_content(
        (messages or [None])[-1]
    )
    decision = guard_text(conversation, phase="request", config=cfg, session_id=session_id)
    if decision.policy_action == "sanitize" and decision.sanitized_text is not None:
        sanitized = copy.deepcopy(messages)
        if sanitized and isinstance(sanitized[-1], dict):
            sanitized[-1]["content"] = decision.sanitized_text
        return decision, sanitized
    return decision, None


def apply_response_sanitization(data: dict[str, Any], decision: GuardDecision) -> dict[str, Any]:
    if decision.policy_action != "sanitize" or not decision.sanitized_text:
        return data
    out = copy.deepcopy(data)
    choices = out.get("choices") or []
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message")
        if isinstance(msg, dict):
            msg["content"] = decision.sanitized_text
    return out


def attach_eeg_metadata(
    data: dict[str, Any],
    *,
    request_decision: GuardDecision,
    response_decision: GuardDecision | None = None,
    latency_ms: int = 0,
    vendor: str | None = None,
) -> dict[str, Any]:
    from eeg.gateway.decision_contract import enrich_guard_decision

    enrich_guard_decision(request_decision)
    resp = response_decision or request_decision
    if response_decision is not None:
        enrich_guard_decision(response_decision)
    eeg_meta: dict[str, Any] = {
        "risk_score": max(request_decision.risk_score, resp.risk_score),
        "request_risk_score": request_decision.risk_score,
        "response_risk_score": resp.risk_score,
        "request_tier": request_decision.tier,
        "response_tier": resp.tier,
        "request_policy_action": request_decision.policy_action,
        "response_policy_action": resp.policy_action,
        "request_primary_reason": request_decision.primary_reason,
        "response_primary_reason": resp.primary_reason,
        "request_confidence": request_decision.confidence,
        "response_confidence": resp.confidence,
        "detection_tags": list(
            dict.fromkeys(request_decision.detection_tags + resp.detection_tags)
        ),
        "latency_ms": latency_ms,
        "decision_version": request_decision.decision_version,
        "layer_scores": dict(request_decision.layer_scores or {}),
    }
    if vendor:
        eeg_meta["vendor"] = vendor
    if resp.policy_action == "sanitize":
        eeg_meta["sanitized"] = True
    data.setdefault("eeg", {})
    if isinstance(data["eeg"], dict):
        data["eeg"].update(eeg_meta)
    return data
