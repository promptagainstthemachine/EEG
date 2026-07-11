"""HTTP response header contract for EEG gateway proxy responses."""

from __future__ import annotations

from typing import Any

from eeg.gateway.decision_contract import ExecutionStatus
from eeg.runtime.guard import GuardDecision

# Request headers (ingress)
HEADER_DETECTION_MODE = "X-EEG-Detection-Mode"
HEADER_SCAN_ALL_MESSAGES = "X-EEG-Scan-All-Messages"
HEADER_INLINE_META = "X-EEG-Inline-Meta"
HEADER_PROVIDER = "X-EEG-Provider"
HEADER_PASS_THROUGH_KEY = "X-EEG-Provider-Key"

# Response headers (egress)
HEADER_TRACE_ID = "X-EEG-Trace-Id"
HEADER_INPUT_DECISION = "X-EEG-Input-Decision"
HEADER_INPUT_REASON = "X-EEG-Input-Primary-Reason"
HEADER_INPUT_CONFIDENCE = "X-EEG-Input-Confidence"
HEADER_INPUT_SANITIZED = "X-EEG-Input-Sanitized"
HEADER_OUTPUT_DECISION = "X-EEG-Output-Decision"
HEADER_OUTPUT_SANITIZED = "X-EEG-Output-Sanitized"
HEADER_EXECUTION_STATUS = "X-EEG-Execution-Status"
HEADER_PROVIDER_OUT = "X-EEG-Provider"
HEADER_MODEL = "X-EEG-Model"
HEADER_LATENCY_MS = "X-EEG-Latency-Ms"

REQUEST_HEADER_NAMES = (
    HEADER_DETECTION_MODE,
    HEADER_SCAN_ALL_MESSAGES,
    HEADER_INLINE_META,
    HEADER_PROVIDER,
    HEADER_PASS_THROUGH_KEY,
)

RESPONSE_HEADER_NAMES = (
    HEADER_TRACE_ID,
    HEADER_INPUT_DECISION,
    HEADER_INPUT_REASON,
    HEADER_INPUT_CONFIDENCE,
    HEADER_INPUT_SANITIZED,
    HEADER_OUTPUT_DECISION,
    HEADER_OUTPUT_SANITIZED,
    HEADER_EXECUTION_STATUS,
    HEADER_PROVIDER_OUT,
    HEADER_MODEL,
    HEADER_LATENCY_MS,
)


def _decision_label(decision: GuardDecision | None) -> str:
    if decision is None:
        return "N/A"
    if decision.blocked or decision.policy_action == "block":
        return "BLOCK"
    if decision.policy_action == "sanitize":
        return "SANITIZE"
    return "ALLOW"


def build_gateway_headers(
    *,
    trace_id: str,
    input_decision: GuardDecision | None = None,
    output_decision: GuardDecision | None = None,
    execution_status: ExecutionStatus | str = "SUCCESS",
    provider: str | None = None,
    model: str | None = None,
    latency_ms: int = 0,
    input_primary_reason: str | None = None,
    input_confidence: float | None = None,
) -> dict[str, str]:
    """Build the standard X-EEG-* response header set."""
    in_label = _decision_label(input_decision)
    out_label = _decision_label(output_decision) if output_decision is not None else "N/A"
    reason = input_primary_reason
    if reason is None and input_decision is not None:
        reason = getattr(input_decision, "primary_reason", None) or input_decision.reason or "N/A"
    conf = input_confidence
    if conf is None and input_decision is not None:
        conf = float(getattr(input_decision, "confidence", 0.0) or 0.0)
    sanitized_in = (
        input_decision is not None and input_decision.policy_action == "sanitize"
    )
    sanitized_out = (
        output_decision is not None and output_decision.policy_action == "sanitize"
    )
    return {
        HEADER_TRACE_ID: str(trace_id),
        HEADER_INPUT_DECISION: in_label,
        HEADER_INPUT_REASON: str(reason or "N/A"),
        HEADER_INPUT_CONFIDENCE: str(round(float(conf or 0.0), 4)),
        HEADER_INPUT_SANITIZED: "true" if sanitized_in else "false",
        HEADER_OUTPUT_DECISION: out_label,
        HEADER_OUTPUT_SANITIZED: "true" if sanitized_out else "false",
        HEADER_EXECUTION_STATUS: str(execution_status),
        HEADER_PROVIDER_OUT: provider or "N/A",
        HEADER_MODEL: model or "N/A",
        HEADER_LATENCY_MS: str(int(latency_ms)),
    }


def attach_inline_meta(
    body: dict[str, Any],
    *,
    trace_id: str,
    headers: dict[str, str],
    enabled: bool,
) -> dict[str, Any]:
    """Optionally mirror header contract into ``body['eeg']['gateway']``."""
    if not enabled or not isinstance(body, dict):
        return body
    gateway_meta = {
        "trace_id": trace_id,
        "input_decision": headers.get(HEADER_INPUT_DECISION),
        "input_primary_reason": headers.get(HEADER_INPUT_REASON),
        "input_confidence": headers.get(HEADER_INPUT_CONFIDENCE),
        "input_sanitized": headers.get(HEADER_INPUT_SANITIZED) == "true",
        "output_decision": headers.get(HEADER_OUTPUT_DECISION),
        "output_sanitized": headers.get(HEADER_OUTPUT_SANITIZED) == "true",
        "execution_status": headers.get(HEADER_EXECUTION_STATUS),
        "provider": headers.get(HEADER_PROVIDER_OUT),
        "model": headers.get(HEADER_MODEL),
        "latency_ms": int(headers.get(HEADER_LATENCY_MS) or 0),
    }
    body.setdefault("eeg", {})
    if isinstance(body["eeg"], dict):
        body["eeg"]["gateway"] = gateway_meta
    return body
