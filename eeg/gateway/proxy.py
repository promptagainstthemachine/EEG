"""OpenAI-compatible chat completion proxy with server-side risk enforcement."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4

import requests

from eeg.gateway.url_safety import UnsafeUpstreamURLError, validate_upstream_url
from eeg.runtime.guard import (
    GuardDecision,
    apply_response_sanitization,
    attach_eeg_metadata,
    guard_messages as unified_guard_messages,
)
from eeg.runtime.policy_config import RuntimePolicyConfig


class GatewayBlockedError(Exception):
    """Request or response blocked by EEG runtime policy."""

    def __init__(self, decision: GuardDecision):
        self.decision = decision
        super().__init__(decision.reason or "Blocked by EEG runtime policy")


def _openai_error(code: str, message: str) -> Dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": "eeg_runtime_policy",
            "code": code,
        }
    }


def blocked_response(decision: GuardDecision, *, status: int = 403) -> Tuple[int, Dict[str, Any]]:
    from eeg.gateway.decision_contract import decision_from_guard, enrich_guard_decision

    enrich_guard_decision(decision)
    body = _openai_error(
        "content_policy_violation",
        (
            "EEG noticed potentially malicious or unsafe content in this request and blocked it. "
            "Please contact us if you think this was a mistake."
        ),
    )
    body["eeg"] = decision.to_dict()
    body["eeg"].update(
        decision_from_guard(
            decision,
            execution_mode="proxy",
            detection_mode="fast",
        )
    )
    body["eeg"]["internal_reason"] = decision.reason or ""
    body["eeg"]["user_message"] = body["error"]["message"]
    return status, body


def _extract_assistant_content(data: Dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
    if isinstance(msg, dict):
        content = msg.get("content", "")
        return content if isinstance(content, str) else str(content)
    return ""


def guard_messages_legacy(
    messages: List[Any],
    *,
    phase: str = "request",
    enforcement_enabled: bool = True,
    runtime_protection_enabled: bool = True,
    block_threshold: float = 0.75,
    config: RuntimePolicyConfig | None = None,
    session_id: str = "default",
) -> GuardDecision:
    """Backward-compatible wrapper around unified guard_messages."""
    cfg = config or RuntimePolicyConfig(
        enforcement_enabled=enforcement_enabled,
        runtime_protection_enabled=runtime_protection_enabled,
        block_threshold=block_threshold,
    )
    decision, _ = unified_guard_messages(
        messages, phase=phase, config=cfg, session_id=session_id
    )
    return decision


def guard_messages(
    messages: List[Any],
    *,
    phase: str = "request",
    enforcement_enabled: bool = True,
    runtime_protection_enabled: bool = True,
    block_threshold: float = 0.75,
    config: RuntimePolicyConfig | None = None,
    session_id: str = "default",
) -> GuardDecision:
    """Backward-compatible wrapper around unified guard_messages."""
    return guard_messages_legacy(
        messages,
        phase=phase,
        enforcement_enabled=enforcement_enabled,
        runtime_protection_enabled=runtime_protection_enabled,
        block_threshold=block_threshold,
        config=config,
        session_id=session_id,
    )


def proxy_chat_completion(
    body: Dict[str, Any],
    *,
    upstream_url: str,
    upstream_headers: Optional[Dict[str, str]] = None,
    enforcement_enabled: bool = True,
    runtime_protection_enabled: bool = True,
    block_threshold: float = 0.75,
    config: RuntimePolicyConfig | None = None,
    timeout: float = 120.0,
    ingest_callback: Optional[Callable[..., None]] = None,
    session_id: str = "default",
) -> Tuple[int, Dict[str, Any]]:
    """
    Inspect prompt, optionally forward to *upstream_url*, inspect response.

    Returns ``(http_status, json_body)``. Raises :class:`GatewayBlockedError` when
    blocked (caller may convert to HTTP 403).
    """
    cfg = config or RuntimePolicyConfig(
        enforcement_enabled=enforcement_enabled,
        runtime_protection_enabled=runtime_protection_enabled,
        block_threshold=block_threshold,
    )
    messages = body.get("messages") or []
    if not isinstance(messages, list):
        return 400, _openai_error("invalid_request", "messages must be an array")

    req_decision, sanitized_messages = unified_guard_messages(
        messages, phase="request", config=cfg, session_id=session_id
    )
    if req_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=req_decision,
                input_text=_user_text_from_messages(messages),
                output_text="",
                model=str(body.get("model", "")),
                blocked=True,
            )
        raise GatewayBlockedError(req_decision)

    forward_body = body
    if sanitized_messages is not None:
        forward_body = {**body, "messages": sanitized_messages}

    try:
        validate_upstream_url(upstream_url)
    except UnsafeUpstreamURLError as exc:
        return 400, _openai_error("invalid_upstream_url", str(exc))

    headers = dict(upstream_headers or {})
    headers.setdefault("Content-Type", "application/json")
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)

    try:
        resp = requests.post(
            upstream_url,
            json=forward_body,
            headers=headers,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return 502, _openai_error("upstream_error", f"Upstream request failed: {exc}")

    latency_ms = int((time.monotonic() - started) * 1000)

    try:
        data = resp.json()
    except ValueError:
        return resp.status_code, {
            "error": {
                "message": "Upstream returned non-JSON",
                "type": "upstream_error",
                "code": "invalid_upstream_response",
            }
        }

    if resp.status_code >= 400:
        return resp.status_code, data if isinstance(data, dict) else {"raw": data}

    assistant_text = _extract_assistant_content(data)
    user_text = _user_text_from_messages(messages)

    resp_messages = list(forward_body.get("messages") or [])
    resp_messages.append({"role": "assistant", "content": assistant_text})
    resp_decision, sanitized_resp_messages = unified_guard_messages(
        resp_messages, phase="response", config=cfg, session_id=session_id
    )

    if resp_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=resp_decision,
                input_text=user_text,
                output_text=assistant_text,
                model=str(body.get("model", "")),
                blocked=True,
                latency_ms=latency_ms,
                started_at=started_at,
                response_body=data if isinstance(data, dict) else None,
            )
        raise GatewayBlockedError(resp_decision)

    if isinstance(data, dict):
        if resp_decision.policy_action == "sanitize" and sanitized_resp_messages is not None:
            data = apply_response_sanitization(data, resp_decision)
        attach_eeg_metadata(
            data,
            request_decision=req_decision,
            response_decision=resp_decision,
            latency_ms=latency_ms,
        )

    if ingest_callback:
        final_output = _extract_assistant_content(data) if isinstance(data, dict) else assistant_text
        _safe_ingest(
            ingest_callback,
            decision=resp_decision,
            input_text=user_text,
            output_text=final_output,
            model=str(body.get("model", "")),
            blocked=False,
            latency_ms=latency_ms,
            started_at=started_at,
            request_decision=req_decision,
            response_body=data if isinstance(data, dict) else None,
        )

    return resp.status_code, data


def _user_text_from_messages(messages: list[Any]) -> str:
    from eeg.gateway.prompt_text import user_text_from_messages

    return user_text_from_messages(messages)


def _safe_ingest(
    ingest_callback: Callable[..., None],
    *,
    decision: GuardDecision,
    input_text: str,
    output_text: str,
    model: str,
    blocked: bool,
    latency_ms: int = 0,
    started_at: datetime | None = None,
    request_decision: GuardDecision | None = None,
    response_body: dict | None = None,
) -> None:
    try:
        req = request_decision or decision
        kwargs: Dict[str, Any] = {
            "trace_id": f"gw-{uuid4().hex[:16]}",
            "input_text": input_text,
            "output_text": output_text,
            "risk_score": max(req.risk_score, decision.risk_score),
            "risk_signals": req.risk_signals + decision.risk_signals,
            "detection_tags": list(dict.fromkeys(req.detection_tags + decision.detection_tags)),
            "model": model,
            "latency_ms": latency_ms,
            "started_at": started_at or datetime.now(timezone.utc),
            "blocked_by_policy": blocked,
            "policy_action": decision.policy_action,
            "tier": decision.tier,
        }
        if response_body is not None:
            kwargs["response_body"] = response_body
        ingest_callback(**kwargs)
    except Exception:
        pass

