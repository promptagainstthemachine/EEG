"""Server-side runtime risk scoring — multi-model ML wrap (no regex/heuristics)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from eeg.runtime.runtime_ml_guard import RuntimeMLHit, assess_runtime_text
from eeg.runtime.text_normalize import normalize_for_scoring

_CATEGORY_BAND = {
    "prompt_injection": ("critical", 0.85),
    "jailbreak": ("critical", 0.65),
    "toxicity": ("high", 0.50),
    "pii": ("high", 0.50),
    "tool_abuse": ("high", 0.55),
}


@dataclass
class RiskSignal:
    category: str
    severity_band: str
    message: str
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity_band": self.severity_band,
            "message": self.message,
            "context": self.context,
        }


@dataclass
class RiskAssessment:
    risk_score: float
    risk_signals: List[RiskSignal] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 4),
            "risk_signals": [s.to_dict() for s in self.risk_signals],
            "categories": self.categories,
        }


def _band_weight(band: str) -> float:
    return {
        "critical": 1.0,
        "high": 0.85,
        "medium": 0.55,
        "low": 0.25,
        "info": 0.1,
    }.get(band.lower(), 0.4)


def _aggregate_score(signals: List[RiskSignal]) -> float:
    if not signals:
        return 0.0
    weights = [_band_weight(s.severity_band) for s in signals]
    base = max(weights)
    bonus = min(0.15 * (len(weights) - 1), 1.0 - base)
    return min(1.0, base + bonus)


def _severity_for_hit(hit: RuntimeMLHit) -> str:
    default_band, critical_floor = _CATEGORY_BAND.get(hit.category, ("high", 0.85))
    raw = float((hit.details or {}).get("raw_score") or hit.score or 0.0)
    if raw >= critical_floor:
        return "critical"
    return default_band


def _signals_from_ml(result, *, phase: str) -> List[RiskSignal]:
    signals: List[RiskSignal] = []
    for hit in result.hits:
        if not hit.triggered:
            continue
        signals.append(
            RiskSignal(
                category=hit.category,
                severity_band=_severity_for_hit(hit),
                message=f"Runtime ML ({hit.provider_id}) flagged {hit.category}",
                context={
                    "layer": "runtime_ml",
                    "phase": phase,
                    "score": hit.score,
                    "model_id": hit.model_id,
                    "provider_id": hit.provider_id,
                    "engine": "runtime_ml_guard",
                    **hit.details,
                },
            )
        )
    return signals


def score_text(
    text: str,
    *,
    phase: str = "request",
    prior_prompt: str = "",
) -> RiskAssessment:
    if not text or not str(text).strip():
        return RiskAssessment(risk_score=0.0)

    content = normalize_for_scoring(str(text))
    ml = assess_runtime_text(content, phase=phase)
    signals = _signals_from_ml(ml, phase=phase)
    categories = sorted({s.category for s in signals})
    return RiskAssessment(
        risk_score=_aggregate_score(signals) if signals else ml.score,
        risk_signals=signals,
        categories=categories,
    )


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


def _format_conversation(messages: List[Any]) -> str:
    lines: List[str] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "user")
        text = _message_content(msg).strip()
        if text:
            lines.append(f"[{role}]: {text}")
    return "\n".join(lines)


def score_messages(messages: List[Any], *, phase: str = "request") -> RiskAssessment:
    conversation = _format_conversation(messages)
    if phase == "response":
        assistant_parts: List[str] = []
        for msg in messages or []:
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                text = _message_content(msg)
                if text:
                    assistant_parts.append(text)
        return score_text(
            assistant_parts[-1] if assistant_parts else conversation,
            phase="response",
        )
    return score_text(conversation or _message_content(messages[-1] if messages else ""), phase="request")


def score_trace_content(
    *,
    input_text: str = "",
    output_text: str = "",
    trace_type: str = "llm_call",
    metadata: Optional[Dict[str, Any]] = None,
) -> RiskAssessment:
    signals: List[RiskSignal] = []
    meta = metadata or {}

    if input_text:
        signals.extend(score_text(input_text, phase="request").risk_signals)

    if output_text:
        signals.extend(score_text(output_text, phase="response").risk_signals)

    tool_payload = meta.get("tool_arguments") or meta.get("tool_input")
    if trace_type == "tool_call" and tool_payload:
        from eeg.runtime.runtime_ml_guard import assess_tool_runtime

        tool_text = tool_payload if isinstance(tool_payload, str) else str(tool_payload)
        tool_name = str(meta.get("tool_name") or "")
        combined = f"{tool_name} {tool_text}".strip()
        ml = assess_tool_runtime(combined)
        signals.extend(_signals_from_ml(ml, phase="request"))

    categories = sorted({s.category for s in signals})
    return RiskAssessment(
        risk_score=_aggregate_score(signals),
        risk_signals=signals,
        categories=categories,
    )


def merge_client_and_server_risk(
    client_score: float,
    client_signals: List[Any],
    server: RiskAssessment,
) -> tuple[float, List[Dict[str, Any]]]:
    score = max(float(client_score or 0), server.risk_score)
    merged: List[Dict[str, Any]] = []
    for sig in client_signals or []:
        if isinstance(sig, dict):
            merged.append(sig)
    for sig in server.risk_signals:
        d = sig.to_dict()
        d["source"] = "eeg_server"
        merged.append(d)
    return score, merged
