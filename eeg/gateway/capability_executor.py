"""Generic capability proxy for EEG gateway (embed, image, speech, batch, files, realtime)."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Generator, Optional, Tuple

import requests

from eeg.gateway.mcp_tools import normalize_mcp_toolsets
from eeg.gateway.providers.types import VendorPlan
from eeg.gateway.proxy import GatewayBlockedError, _openai_error, _safe_ingest, _user_text_from_messages
from eeg.gateway.url_safety import validate_upstream_url
from eeg.gateway.vendor_executor import proxy_chat_via_plan, stream_chat_via_plan
from eeg.runtime.guard import GuardDecision, guard_messages, guard_text
from eeg.runtime.policy_config import RuntimePolicyConfig


def _extract_text_for_guard(capability: str, body: dict[str, Any]) -> str:
    if capability in {"chat", "mcp_toolsets"}:
        messages = body.get("messages") or []
        if isinstance(messages, list):
            return _user_text_from_messages(messages)
    if capability == "embed":
        inp = body.get("input")
        if isinstance(inp, list):
            return " ".join(str(x) for x in inp)
        return str(inp or "")
    if capability in {"image", "speech"}:
        return str(body.get("prompt") or body.get("input") or "")
    return json.dumps(body, ensure_ascii=False)[:4000]


def _guard_capability_request(
    capability: str,
    body: dict[str, Any],
    *,
    config: RuntimePolicyConfig,
    session_id: str = "default",
) -> GuardDecision:
    text = _extract_text_for_guard(capability, body)
    if capability in {"chat", "mcp_toolsets"} and isinstance(body.get("messages"), list):
        decision, _ = guard_messages(
            body["messages"], phase="request", config=config, session_id=session_id
        )
        return decision
    return guard_text(text, phase="request", config=config, session_id=session_id)


def _guard_capability_response(
    capability: str,
    body: dict[str, Any],
    response_text: str,
    *,
    config: RuntimePolicyConfig,
    session_id: str = "default",
) -> GuardDecision:
    if capability in {"chat", "mcp_toolsets"} and isinstance(body.get("messages"), list):
        msgs = list(body["messages"])
        msgs.append({"role": "assistant", "content": response_text})
        decision, _ = guard_messages(
            msgs, phase="response", config=config, session_id=session_id
        )
        return decision
    prior = _extract_text_for_guard(capability, body)
    return guard_text(
        response_text,
        phase="response",
        prior_prompt=prior,
        config=config,
        session_id=session_id,
    )


def dispatch_capability(
    capability: str,
    body: dict[str, Any],
    plan: VendorPlan,
    *,
    config: RuntimePolicyConfig,
    timeout: float = 120.0,
    ingest_callback: Optional[Callable[..., None]] = None,
    stream: bool = False,
    session_id: str = "default",
) -> Any:
    if capability in {"chat", "mcp_toolsets"}:
        payload = normalize_mcp_toolsets(body) if capability == "mcp_toolsets" else body
        if stream or payload.get("stream"):
            return stream_chat_via_plan(
                payload,
                plan,
                config=config,
                timeout=timeout,
                ingest_callback=ingest_callback,
                session_id=session_id,
            )
        return proxy_chat_via_plan(
            payload,
            plan,
            config=config,
            timeout=timeout,
            ingest_callback=ingest_callback,
            session_id=session_id,
        )

    req_decision = _guard_capability_request(
        capability, body, config=config, session_id=session_id
    )
    if req_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=req_decision,
                input_text=_extract_text_for_guard(capability, body),
                output_text="",
                model=str(body.get("model", "")),
                blocked=True,
            )
        raise GatewayBlockedError(req_decision)

    if plan.transport == "bedrock_invoke":
        from eeg.gateway.vendor_executor import execute_bedrock_invoke_capability

        return execute_bedrock_invoke_capability(
            plan,
            body,
            capability=capability,
            config=config,
            timeout=timeout,
            ingest_callback=ingest_callback,
            request_decision=req_decision,
        )

    if stream and plan.stream_shape != "none":
        return _stream_http_capability(
            plan,
            body,
            capability=capability,
            config=config,
            timeout=timeout,
            ingest_callback=ingest_callback,
            request_decision=req_decision,
            session_id=session_id,
        )

    # Vertex embeddings: one instance per predict call for gemini-embedding-001
    if (
        plan.vendor_slug == "vertex"
        and capability == "embed"
        and isinstance(plan.request_body, dict)
        and plan.request_body.get("_eeg_batch")
    ):
        return _proxy_vertex_embed_batch(
            plan,
            body,
            config=config,
            timeout=timeout,
            ingest_callback=ingest_callback,
            request_decision=req_decision,
            session_id=session_id,
        )

    status, data = proxy_http_capability(
        plan,
        body,
        capability=capability,
        config=config,
        timeout=timeout,
        ingest_callback=ingest_callback,
        request_decision=req_decision,
        session_id=session_id,
    )
    return status, data


def _proxy_vertex_embed_batch(
    plan: VendorPlan,
    body: dict[str, Any],
    *,
    config: RuntimePolicyConfig,
    timeout: float,
    ingest_callback: Optional[Callable[..., None]],
    request_decision: GuardDecision | None,
    session_id: str = "default",
) -> Tuple[int, dict[str, Any]]:
    from eeg.gateway.providers.vendor_router import normalize_vendor_response

    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    validate_upstream_url(plan.request_url)
    instances = list((plan.request_body or {}).get("instances") or [])
    parameters = dict((plan.request_body or {}).get("parameters") or {})
    parameters.pop("_eeg_batch", None)
    all_predictions: list[Any] = []

    try:
        for instance in instances:
            resp = requests.post(
                plan.request_url,
                json={"instances": [instance], "parameters": parameters},
                headers=plan.request_headers,
                timeout=timeout,
            )
            if resp.status_code >= 400:
                try:
                    err = resp.json()
                except ValueError:
                    err = _openai_error("upstream_error", resp.text[:500])
                return resp.status_code, err if isinstance(err, dict) else {"error": err}
            raw = resp.json()
            preds = raw.get("predictions") if isinstance(raw, dict) else None
            if isinstance(preds, list):
                all_predictions.extend(preds)
    except requests.RequestException as exc:
        return 502, _openai_error("upstream_error", f"Upstream request failed: {exc}")

    data = normalize_vendor_response(
        plan,
        {"predictions": all_predictions},
        model=str(body.get("model") or plan.vertex_model),
    )
    response_text = json.dumps(data, ensure_ascii=False)[:4000]
    resp_decision = _guard_capability_response(
        "embed", body, response_text, config=config, session_id=session_id
    )
    if resp_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=resp_decision,
                input_text=_extract_text_for_guard("embed", body),
                output_text=response_text,
                model=str(body.get("model", "")),
                blocked=True,
                latency_ms=int((time.monotonic() - started) * 1000),
                started_at=started_at,
                request_decision=request_decision,
            )
        raise GatewayBlockedError(resp_decision)

    if ingest_callback:
        _safe_ingest(
            ingest_callback,
            decision=resp_decision,
            input_text=_extract_text_for_guard("embed", body),
            output_text=response_text,
            model=str(body.get("model", "")),
            blocked=False,
            latency_ms=int((time.monotonic() - started) * 1000),
            started_at=started_at,
            request_decision=request_decision,
        )
    return 200, data

def proxy_http_capability(
    plan: VendorPlan,
    body: dict[str, Any],
    *,
    capability: str,
    config: RuntimePolicyConfig,
    timeout: float = 120.0,
    ingest_callback: Optional[Callable[..., None]] = None,
    request_decision: GuardDecision | None = None,
    session_id: str = "default",
) -> Tuple[int, dict[str, Any]]:
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    validate_upstream_url(plan.request_url)
    method = (plan.http_method or "POST").upper()

    try:
        if method == "GET":
            resp = requests.get(plan.request_url, headers=plan.request_headers, timeout=timeout)
        elif plan.multipart:
            resp = requests.request(
                method,
                plan.request_url,
                headers=plan.request_headers,
                data=body if isinstance(body, dict) else None,
                timeout=timeout,
            )
        else:
            resp = requests.request(
                method,
                plan.request_url,
                json=plan.request_body if plan.request_body else body,
                headers=plan.request_headers,
                timeout=timeout,
            )
    except requests.RequestException as exc:
        return 502, _openai_error("upstream_error", f"Upstream request failed: {exc}")

    status = resp.status_code
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if status < 400 and (
        "audio/" in content_type
        or "octet-stream" in content_type
        or capability == "speech"
    ):
        # OpenAI /audio/speech returns raw audio; wrap for JSON gateway responses.
        from eeg.gateway.multimodal import b64_audio_response

        data = b64_audio_response(
            audio_bytes=resp.content,
            content_type=content_type.split(";")[0].strip() or "audio/mpeg",
        )
        data["model"] = str(body.get("model") or "")
    else:
        try:
            data = resp.json()
        except ValueError:
            return status, _openai_error("invalid_upstream_response", resp.text[:500])

    if status >= 400:
        if isinstance(data, dict):
            return status, data
        return status, _openai_error("upstream_error", str(data))

    if isinstance(data, dict) and plan.response_shape not in {"openai_json", ""}:
        from eeg.gateway.providers.vendor_router import normalize_vendor_response

        data = normalize_vendor_response(
            plan,
            data,
            model=str(body.get("model") or plan.bedrock_model_id or plan.vertex_model or ""),
        )

    response_text = json.dumps(data, ensure_ascii=False)[:4000]
    resp_decision = _guard_capability_response(
        capability, body, response_text, config=config, session_id=session_id
    )
    if resp_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=resp_decision,
                input_text=_extract_text_for_guard(capability, body),
                output_text=response_text,
                model=str(body.get("model", "")),
                blocked=True,
                latency_ms=int((time.monotonic() - started) * 1000),
                started_at=started_at,
                request_decision=request_decision,
            )
        raise GatewayBlockedError(resp_decision)

    if isinstance(data, dict):
        data.setdefault("eeg", {})
        if isinstance(data["eeg"], dict):
            data["eeg"].update(
                {
                    "vendor": plan.vendor_slug,
                    "capability": capability,
                    "risk_score": resp_decision.risk_score,
                    "policy_action": resp_decision.policy_action,
                }
            )

    if ingest_callback:
        _safe_ingest(
            ingest_callback,
            decision=resp_decision,
            input_text=_extract_text_for_guard(capability, body),
            output_text=response_text,
            model=str(body.get("model", "")),
            blocked=False,
            latency_ms=int((time.monotonic() - started) * 1000),
            started_at=started_at,
            request_decision=request_decision,
        )

    return status, data if isinstance(data, dict) else {"result": data}


def _stream_http_capability(
    plan: VendorPlan,
    body: dict[str, Any],
    *,
    capability: str,
    config: RuntimePolicyConfig,
    timeout: float,
    ingest_callback: Optional[Callable[..., None]],
    request_decision: GuardDecision,
    session_id: str = "default",
) -> Generator[str, None, None]:
    validate_upstream_url(plan.request_url)
    accumulated = ""
    try:
        with requests.post(
            plan.request_url,
            json=plan.request_body or body,
            headers=plan.request_headers,
            timeout=timeout,
            stream=True,
        ) as resp:
            if resp.status_code >= 400:
                yield f"data: {json.dumps(_openai_error('upstream_error', f'status {resp.status_code}'))}\n\n"
                return
            for raw_line in resp.iter_lines(decode_unicode=True):
                if not raw_line:
                    continue
                line = raw_line.strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload and payload != "[DONE]":
                        accumulated += payload[:200]
                yield f"{line}\n\n" if not line.endswith("\n\n") else line
    except requests.RequestException as exc:
        yield f"data: {json.dumps(_openai_error('stream_error', str(exc)))}\n\n"
        return

    if ingest_callback and accumulated:
        decision = _guard_capability_response(
            capability, body, accumulated, config=config, session_id=session_id
        )
        _safe_ingest(
            ingest_callback,
            decision=decision,
            input_text=_extract_text_for_guard(capability, body),
            output_text=accumulated[:4000],
            model=str(body.get("model", "")),
            blocked=False,
        )
