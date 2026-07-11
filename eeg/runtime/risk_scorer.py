"""Server-side risk scoring for live prompts, responses, and trace ingest.

Scores are computed on the server from ``input_text`` / ``output_text`` (and tool
payloads). Client-supplied ``risk_score`` values are not trusted for enforcement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from eeg.runtime.text_normalize import normalize_for_scoring
from eeg.probes.auto_redteam import (
    INJECTION_PROMPTS,
    JAILBREAK_PROMPTS,
    PII_DETECTION_PATTERNS,
    TOXICITY_PATTERNS,
    evaluate_jailbreak_success,
    evaluate_response_pii,
    evaluate_response_toxicity,
)

# Compiled heuristics for request-phase (prompt) inspection.
_PROMPT_INJECTION_RE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"disregard\s+(your\s+)?(system|safety)\s+(prompt|instructions)",
        r"you\s+are\s+now\s+DAN\b",
        r"\[SYSTEM\].*override",
        r"```\s*system\s*\n",
        r"<\s*script\b",
        r"\{\{.*\}\}",
        r";\s*DROP\s+TABLE\b",
        r"\$\{.*\}",
    )
]

_TOOL_ABUSE_RE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"os\.system\s*\(",
        r"subprocess\.(run|call|Popen)\s*\(",
        r"__import__\s*\(",
        r"rm\s+-rf\s+/",
        r"curl\s+.*169\.254\.169\.254",
        r"metadata\.google\.internal",
    )
]

_HARM_REQUEST_RE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"how\s+to\s+(make|build|create|assemble|craft)\s+(an?\s+)?(bomb|explosive|ied|pipe[\s-]?bomb|molotov)",
        r"\b(make|build|craft|assemble)\s+(an?\s+)?(bomb|explosive|ied|pipe[\s-]?bomb)\b",
        r"\b(instructions?|recipe|tutorial)\s+(for|to)\s+(making|building)\s+(an?\s+)?(bomb|explosive)",
        r"\bkill\s+yourself\b",
    )
]

_SECRET_IN_TEXT_RE = [
    re.compile(p)
    for p in (
        r"sk-[a-zA-Z0-9]{20,}",
        r"sk-ant-[a-zA-Z0-9\-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[a-zA-Z0-9]{36,}",
    )
]


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
    # Boost when multiple independent signals fire (capped at 1.0).
    bonus = min(0.15 * (len(weights) - 1), 1.0 - base)
    return min(1.0, base + bonus)


def _match_patterns(
    text: str,
    patterns: List[re.Pattern],
    label: str,
    *,
    critical: bool = False,
) -> List[RiskSignal]:
    found: List[RiskSignal] = []
    for rx in patterns:
        m = rx.search(text)
        if m:
            if critical or label == "jailbreak":
                band = "critical"
            elif label in ("injection", "tool_abuse"):
                band = "high"
            else:
                band = "medium"
            found.append(
                RiskSignal(
                    category=label,
                    severity_band=band,
                    message=f"Pattern match ({label}): {m.group(0)[:80]}",
                    context={"matched": m.group(0)[:120]},
                )
            )
            break
    return found


def _check_literal_prompts(text: str, prompts: List[str], category: str, band: str) -> List[RiskSignal]:
    lower = text.lower()
    for p in prompts:
        if p.lower() in lower:
            return [
                RiskSignal(
                    category=category,
                    severity_band=band,
                    message=f"Known adversarial {category} substring detected",
                    context={"sample": p[:80]},
                )
            ]
    return []


def score_text(
    text: str,
    *,
    phase: str = "request",
    prior_prompt: str = "",
) -> RiskAssessment:
    """Score a single text blob (user prompt or model response)."""
    if not text or not str(text).strip():
        return RiskAssessment(risk_score=0.0)

    content = normalize_for_scoring(str(text))
    signals: List[RiskSignal] = []

    if phase == "request":
        signals.extend(
            _match_patterns(content, _PROMPT_INJECTION_RE, "injection", critical=True)
        )
        signals.extend(_check_literal_prompts(content, JAILBREAK_PROMPTS, "jailbreak", "critical"))
        signals.extend(_check_literal_prompts(content, INJECTION_PROMPTS, "injection", "high"))
        signals.extend(_match_patterns(content, _TOOL_ABUSE_RE, "tool_abuse"))
        signals.extend(
            _match_patterns(content, _HARM_REQUEST_RE, "weapons_harm", critical=True)
        )
    else:
        toxicity = evaluate_response_toxicity(content)
        if toxicity.get("is_toxic"):
            signals.append(
                RiskSignal(
                    category="toxicity",
                    severity_band="high",
                    message="Toxic content detected in model output",
                    context=toxicity,
                )
            )
        pii = evaluate_response_pii(content)
        if pii.get("has_pii"):
            signals.append(
                RiskSignal(
                    category="pii",
                    severity_band="high",
                    message="PII pattern detected in model output",
                    context=pii,
                )
            )
        if prior_prompt:
            jb = evaluate_jailbreak_success(prior_prompt, content)
            if jb.get("appears_jailbroken"):
                signals.append(
                    RiskSignal(
                        category="jailbreak",
                        severity_band="critical",
                        message="Model output suggests jailbreak success",
                        context=jb,
                    )
                )

    signals.extend(_match_patterns(content, _SECRET_IN_TEXT_RE, "secrets"))
    for pattern, label in PII_DETECTION_PATTERNS:
        if re.search(pattern, content):
            signals.append(
                RiskSignal(
                    category="pii",
                    severity_band="medium",
                    message=f"PII pattern in {phase}: {label}",
                    context={"type": label},
                )
            )
            break

    for pattern, label in TOXICITY_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE) and phase == "request":
            signals.append(
                RiskSignal(
                    category="toxicity",
                    severity_band="medium",
                    message=f"Toxic pattern in prompt: {label}",
                    context={"type": label},
                )
            )
            break

    categories = sorted({s.category for s in signals})
    return RiskAssessment(
        risk_score=_aggregate_score(signals),
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
    """Label roles so multi-turn jailbreaks in assistant history are visible."""
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
    """Score full OpenAI-style ``messages`` (multi-turn context, not last turn only)."""
    conversation = _format_conversation(messages)
    if phase == "response":
        assistant_parts: List[str] = []
        user_parts: List[str] = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role")
            text = _message_content(msg)
            if role == "assistant" and text:
                assistant_parts.append(text)
            elif role == "user" and text:
                user_parts.append(text)
        return score_text(
            assistant_parts[-1] if assistant_parts else conversation,
            phase="response",
            prior_prompt=_format_conversation(
                [m for m in messages if isinstance(m, dict) and m.get("role") != "assistant"]
            ) or "\n".join(user_parts),
        )
    return score_text(conversation or _message_content(messages[-1] if messages else ""), phase="request")


def score_trace_content(
    *,
    input_text: str = "",
    output_text: str = "",
    trace_type: str = "llm_call",
    metadata: Optional[Dict[str, Any]] = None,
) -> RiskAssessment:
    """Score trace fields for ingest-time enforcement."""
    signals: List[RiskSignal] = []
    meta = metadata or {}

    if input_text:
        req = score_text(input_text, phase="request")
        signals.extend(req.risk_signals)

    if output_text:
        resp = score_text(
            output_text,
            phase="response",
            prior_prompt=input_text,
        )
        signals.extend(resp.risk_signals)

    tool_payload = meta.get("tool_arguments") or meta.get("tool_input")
    if trace_type == "tool_call" and tool_payload:
        tool_text = tool_payload if isinstance(tool_payload, str) else str(tool_payload)
        tool_assessment = score_text(tool_text, phase="request")
        for sig in tool_assessment.risk_signals:
            signals.append(
                RiskSignal(
                    category="tool_abuse",
                    severity_band=sig.severity_band,
                    message=sig.message,
                    context={**sig.context, "trace_type": "tool_call"},
                )
            )

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
    """Use the higher of client vs server score; append server signals."""
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
