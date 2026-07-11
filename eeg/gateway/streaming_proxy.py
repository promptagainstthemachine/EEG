"""SSE streaming chat proxy with per-chunk EEG runtime scoring."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional
from uuid import uuid4

import requests

from eeg.gateway.proxy import GatewayBlockedError, _openai_error, _safe_ingest, _user_text_from_messages
from eeg.gateway.url_safety import validate_upstream_url
from eeg.runtime.guard import GuardDecision, guard_text
from eeg.runtime.policy_config import RuntimePolicyConfig
from eeg.runtime.guard import guard_messages as unified_guard_messages


def stream_chat_completion(
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
) -> Generator[str, None, None]:
    """
    Yield SSE lines (OpenAI-style) while scanning streamed assistant deltas.
    Raises GatewayBlockedError before upstream call or on toxic chunk.
    """
    cfg = config or RuntimePolicyConfig(
        enforcement_enabled=enforcement_enabled,
        runtime_protection_enabled=runtime_protection_enabled,
        block_threshold=block_threshold,
    )
    messages = body.get("messages") or []
    if not isinstance(messages, list):
        yield _sse_error("messages must be an array")
        return

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

    forward_messages = sanitized_messages if sanitized_messages is not None else messages
    validate_upstream_url(upstream_url)
    stream_body = {**body, "messages": forward_messages, "stream": True}
    headers = dict(upstream_headers or {})
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "text/event-stream")

    user_text = _user_text_from_messages(forward_messages)
    accumulated = ""
    prev_redacted = ""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    last_decision: GuardDecision = req_decision

    try:
        with requests.post(
            upstream_url,
            json=stream_body,
            headers=headers,
            timeout=timeout,
            stream=True,
        ) as resp:
            if resp.status_code >= 400:
                yield _sse_error(f"upstream status {resp.status_code}")
                return
            for raw_line in resp.iter_lines(decode_unicode=True):
                if not raw_line:
                    continue
                line = raw_line.strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    yield "data: [DONE]\n\n"
                    break
                delta_text = _extract_stream_delta(payload)
                if delta_text:
                    accumulated += delta_text
                    last_decision = guard_text(
                        accumulated,
                        phase="response",
                        prior_prompt=user_text,
                        config=cfg,
                        session_id=session_id,
                    )
                    if last_decision.blocked:
                        if ingest_callback:
                            _safe_ingest(
                                ingest_callback,
                                decision=last_decision,
                                input_text=user_text,
                                output_text=accumulated,
                                model=str(body.get("model", "")),
                                blocked=True,
                                latency_ms=int((time.monotonic() - started) * 1000),
                                started_at=started_at,
                                request_decision=req_decision,
                            )
                        raise GatewayBlockedError(last_decision)
                    if (
                        last_decision.policy_action == "sanitize"
                        and last_decision.sanitized_text is not None
                    ):
                        redacted = last_decision.sanitized_text
                        new_suffix = redacted[len(prev_redacted) :]
                        prev_redacted = redacted
                        accumulated = redacted
                        if new_suffix:
                            payload = _replace_stream_delta(payload, new_suffix)
                yield f"data: {payload}\n\n"
    except GatewayBlockedError:
        raise
    except requests.RequestException as exc:
        yield _sse_error(str(exc))
        return

    if ingest_callback and accumulated:
        _safe_ingest(
            ingest_callback,
            decision=last_decision,
            input_text=user_text,
            output_text=accumulated[:4000],
            model=str(body.get("model", "")),
            blocked=False,
            latency_ms=int((time.monotonic() - started) * 1000),
            started_at=started_at,
            request_decision=req_decision,
        )


def _extract_stream_delta(payload: str) -> str:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return ""
    choices = data.get("choices") or []
    if not choices:
        return ""
    delta = choices[0].get("delta") if isinstance(choices[0], dict) else {}
    if isinstance(delta, dict):
        content = delta.get("content", "")
        return content if isinstance(content, str) else ""
    return ""


def _replace_stream_delta(payload: str, new_text: str) -> str:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return payload
    choices = data.get("choices") or []
    if choices and isinstance(choices[0], dict):
        delta = choices[0].get("delta")
        if isinstance(delta, dict):
            delta["content"] = new_text
    return json.dumps(data)


def _sse_error(message: str) -> str:
    body = _openai_error("stream_error", message)
    return f"data: {json.dumps(body)}\n\n"
