"""Vendor-aware chat completion execution for the EEG AI proxy gateway."""
from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, Optional, Tuple
from uuid import uuid4

import requests

from eeg.gateway.providers.anthropic_vendor import anthropic_stream_line_to_openai
from eeg.gateway.providers.bedrock_vendor import bedrock_stream_event_to_openai
from eeg.gateway.providers.types import VendorPlan
from eeg.gateway.providers.vendor_router import normalize_vendor_response
from eeg.gateway.providers.vertex_vendor import vertex_stream_line_to_openai
from eeg.gateway.proxy import (
    GatewayBlockedError,
    _openai_error,
    _safe_ingest,
    _user_text_from_messages,
)
from eeg.gateway.url_safety import validate_upstream_url
from eeg.runtime.guard import (
    GuardDecision,
    apply_response_sanitization,
    attach_eeg_metadata,
    guard_messages,
    guard_text,
)
from eeg.runtime.policy_config import RuntimePolicyConfig


def _bedrock_runtime_client(plan: VendorPlan):
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required for Bedrock gateway routing") from exc
    creds = plan.bedrock_credentials
    session = boto3.Session(
        aws_access_key_id=creds.get("access_key_id"),
        aws_secret_access_key=creds.get("secret_access_key"),
        aws_session_token=creds.get("session_token"),
        region_name=plan.bedrock_region,
    )
    return session.client("bedrock-runtime")


def _extract_assistant_content(data: Dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
    if isinstance(msg, dict):
        content = msg.get("content", "")
        return content if isinstance(content, str) else str(content)
    return ""


def _patch_plan_messages(plan: VendorPlan, messages: list[Any]) -> VendorPlan:
    """Apply sanitized OpenAI-style messages to the vendor request body."""
    rb = dict(plan.request_body)
    if plan.vendor_slug == "anthropic":
        from eeg.gateway.providers.anthropic_vendor import (
            _extract_system_blocks,
            _openai_messages_to_anthropic,
        )

        rb["messages"] = _openai_messages_to_anthropic(messages)
        system_blocks = _extract_system_blocks(messages)
        if system_blocks:
            rb["system"] = system_blocks
        else:
            rb.pop("system", None)
    elif plan.transport == "bedrock_sdk":
        from eeg.gateway.providers.bedrock_vendor import _openai_messages_to_bedrock

        converse_messages, system_blocks = _openai_messages_to_bedrock(messages)
        rb["messages"] = converse_messages
        if system_blocks:
            rb["system"] = system_blocks
        else:
            rb.pop("system", None)
    elif plan.vendor_slug == "vertex":
        from eeg.gateway.providers.vertex_vendor import (
            _extract_system_instruction,
            _openai_messages_to_vertex,
        )

        rb["contents"] = _openai_messages_to_vertex(messages)
        system = _extract_system_instruction(messages)
        if system:
            rb["systemInstruction"] = system
        else:
            rb.pop("systemInstruction", None)
    else:
        rb["messages"] = messages
    return replace(plan, request_body=rb)


def _guard_response(
    messages: list[Any],
    assistant_text: str,
    *,
    config: RuntimePolicyConfig,
    session_id: str = "default",
) -> tuple[GuardDecision, dict[str, Any] | None]:
    resp_messages = list(messages)
    resp_messages.append({"role": "assistant", "content": assistant_text})
    return guard_messages(
        resp_messages, phase="response", config=config, session_id=session_id
    )


def proxy_chat_via_plan(
    body: Dict[str, Any],
    plan: VendorPlan,
    *,
    enforcement_enabled: bool = True,
    runtime_protection_enabled: bool = True,
    block_threshold: float = 0.75,
    config: RuntimePolicyConfig | None = None,
    timeout: float = 120.0,
    ingest_callback: Optional[Callable[..., None]] = None,
    session_id: str = "default",
) -> Tuple[int, Dict[str, Any]]:
    cfg = config or RuntimePolicyConfig(
        enforcement_enabled=enforcement_enabled,
        runtime_protection_enabled=runtime_protection_enabled,
        block_threshold=block_threshold,
    )
    messages = body.get("messages") or []
    if not isinstance(messages, list):
        return 400, _openai_error("invalid_request", "messages must be an array")

    req_decision, sanitized_messages = guard_messages(
        messages, phase="request", config=cfg, session_id=session_id
    )
    if req_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=req_decision,
                input_text=_user_text_from_messages(messages),
                output_text="",
                model=str(body.get("model") or plan.bedrock_model_id or ""),
                blocked=True,
            )
        raise GatewayBlockedError(req_decision)

    forward_body = body
    active_plan = plan
    if sanitized_messages is not None:
        forward_body = {**body, "messages": sanitized_messages}
        active_plan = _patch_plan_messages(plan, sanitized_messages)

    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    model = str(forward_body.get("model") or active_plan.bedrock_model_id or "")

    if active_plan.transport == "bedrock_sdk":
        try:
            client = _bedrock_runtime_client(active_plan)
            raw = client.converse(modelId=active_plan.bedrock_model_id, **active_plan.request_body)
        except Exception as exc:
            return 502, _openai_error("upstream_error", f"Bedrock request failed: {exc}")
        data = normalize_vendor_response(active_plan, raw, model=model)
        status = 200
    else:
        try:
            validate_upstream_url(active_plan.request_url)
        except Exception as exc:
            return 400, _openai_error("invalid_upstream_url", str(exc))

        try:
            resp = requests.post(
                active_plan.request_url,
                json=active_plan.request_body,
                headers=active_plan.request_headers,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            return 502, _openai_error("upstream_error", f"Upstream request failed: {exc}")

        status = resp.status_code
        try:
            raw = resp.json()
        except ValueError:
            return status, _openai_error("invalid_upstream_response", "Upstream returned non-JSON")

        if status >= 400:
            if plan.response_shape == "openai_json" and isinstance(raw, dict):
                return status, raw
            return status, _openai_error("upstream_error", str(raw))

        data = normalize_vendor_response(active_plan, raw if isinstance(raw, dict) else {}, model=model)

    assistant_text = _extract_assistant_content(data)
    user_text = _user_text_from_messages(forward_body.get("messages") or [])
    latency_ms = int((time.monotonic() - started) * 1000)

    resp_decision, _ = _guard_response(
        forward_body.get("messages") or [],
        assistant_text,
        config=cfg,
        session_id=session_id,
    )
    if resp_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=resp_decision,
                input_text=user_text,
                output_text=assistant_text,
                model=model,
                blocked=True,
                latency_ms=latency_ms,
                started_at=started_at,
                request_decision=req_decision,
            )
        raise GatewayBlockedError(resp_decision)

    if isinstance(data, dict):
        if resp_decision.policy_action == "sanitize":
            data = apply_response_sanitization(data, resp_decision)
        attach_eeg_metadata(
            data,
            request_decision=req_decision,
            response_decision=resp_decision,
            latency_ms=latency_ms,
            vendor=active_plan.vendor_slug,
        )

    if ingest_callback:
        final_output = _extract_assistant_content(data) if isinstance(data, dict) else assistant_text
        _safe_ingest(
            ingest_callback,
            decision=resp_decision,
            input_text=user_text,
            output_text=final_output,
            model=model,
            blocked=False,
            latency_ms=latency_ms,
            started_at=started_at,
            request_decision=req_decision,
        )

    return status, data


def stream_chat_via_plan(
    body: Dict[str, Any],
    plan: VendorPlan,
    *,
    enforcement_enabled: bool = True,
    runtime_protection_enabled: bool = True,
    block_threshold: float = 0.75,
    config: RuntimePolicyConfig | None = None,
    timeout: float = 120.0,
    ingest_callback: Optional[Callable[..., None]] = None,
    session_id: str = "default",
) -> Generator[str, None, None]:
    cfg = config or RuntimePolicyConfig(
        enforcement_enabled=enforcement_enabled,
        runtime_protection_enabled=runtime_protection_enabled,
        block_threshold=block_threshold,
    )
    messages = body.get("messages") or []
    if not isinstance(messages, list):
        yield _sse_error("messages must be an array")
        return

    req_decision, sanitized_messages = guard_messages(
        messages, phase="request", config=cfg, session_id=session_id
    )
    if req_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=req_decision,
                input_text=_user_text_from_messages(messages),
                output_text="",
                model=str(body.get("model") or plan.bedrock_model_id or ""),
                blocked=True,
            )
        raise GatewayBlockedError(req_decision)

    forward_messages = sanitized_messages if sanitized_messages is not None else messages
    active_plan = _patch_plan_messages(plan, forward_messages) if sanitized_messages is not None else plan
    user_text = _user_text_from_messages(forward_messages)
    accumulated = ""
    prev_redacted = ""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    fallback_id = f"chatcmpl-{uuid4().hex[:12]}"
    model = str(body.get("model") or plan.bedrock_model_id or "")
    last_decision: GuardDecision = req_decision

    if active_plan.transport == "bedrock_sdk":
        try:
            client = _bedrock_runtime_client(active_plan)
            response = client.converse_stream(modelId=active_plan.bedrock_model_id, **active_plan.request_body)
            tool_index = 0
            for event in response.get("stream") or []:
                if "contentBlockStart" in event:
                    start = (event["contentBlockStart"].get("start") or {})
                    tool_use = start.get("toolUse") or {}
                    if tool_use:
                        line = bedrock_stream_event_to_openai(
                            {
                                "tool_start": {
                                    "id": tool_use.get("toolUseId") or "",
                                    "name": tool_use.get("name") or "",
                                    "index": tool_index,
                                }
                            },
                            fallback_id,
                            model,
                        )
                        tool_index += 1
                        if line:
                            yield line
                elif "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"].get("delta") or {}
                    text = delta.get("text") or ""
                    tool_delta = delta.get("toolUse") or {}
                    if text:
                        accumulated, last_decision, text = _stream_chunk_guard(
                            accumulated, text, user_text, cfg, prev_redacted
                        )
                        prev_redacted = last_decision.sanitized_text or accumulated
                        if last_decision.blocked:
                            raise GatewayBlockedError(last_decision)
                        line = bedrock_stream_event_to_openai({"delta": {"text": text}}, fallback_id, model)
                        if line:
                            yield line
                    elif tool_delta.get("input"):
                        # Bedrock streams tool input as a string fragment
                        frag = tool_delta["input"]
                        if not isinstance(frag, str):
                            frag = json.dumps(frag)
                        line = bedrock_stream_event_to_openai(
                            {
                                "tool_delta": {
                                    "index": max(0, tool_index - 1),
                                    "arguments": frag,
                                }
                            },
                            fallback_id,
                            model,
                        )
                        if line:
                            yield line
                elif "messageStop" in event:
                    stop = event["messageStop"].get("stopReason") or "end_turn"
                    line = bedrock_stream_event_to_openai({"stopReason": stop}, fallback_id, model)
                    if line:
                        yield line
        except GatewayBlockedError:
            raise
        except Exception as exc:
            yield _sse_error(str(exc))
            return
    elif active_plan.stream_shape == "anthropic_sse":
        try:
            validate_upstream_url(active_plan.request_url)
            with requests.post(
                active_plan.request_url,
                json=active_plan.request_body,
                headers=active_plan.request_headers,
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
                    converted = anthropic_stream_line_to_openai(line, fallback_id, model)
                    if converted:
                        if '"content"' in converted:
                            try:
                                payload = converted.split("data:", 1)[1].strip()
                                chunk = json.loads(payload)
                                delta = chunk["choices"][0]["delta"].get("content") or ""
                                accumulated, last_decision, delta = _stream_chunk_guard(
                                    accumulated, delta, user_text, cfg, prev_redacted
                                )
                                prev_redacted = last_decision.sanitized_text or accumulated
                                if last_decision.blocked:
                                    raise GatewayBlockedError(last_decision)
                                if delta != chunk["choices"][0]["delta"].get("content"):
                                    chunk["choices"][0]["delta"]["content"] = delta
                                    converted = f"data: {json.dumps(chunk)}\n\n"
                            except (json.JSONDecodeError, KeyError, IndexError):
                                pass
                        yield converted
        except GatewayBlockedError:
            raise
        except requests.RequestException as exc:
            yield _sse_error(str(exc))
            return
    elif active_plan.stream_shape == "vertex_sse":
        try:
            validate_upstream_url(active_plan.request_url)
            with requests.post(
                active_plan.request_url,
                json=active_plan.request_body,
                headers=active_plan.request_headers,
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
                    converted = vertex_stream_line_to_openai(line, fallback_id, model)
                    if not converted:
                        continue
                    if '"content"' in converted:
                        try:
                            payload = converted.split("data:", 1)[1].strip()
                            if payload != "[DONE]":
                                chunk = json.loads(payload)
                                delta = chunk["choices"][0]["delta"].get("content") or ""
                                if delta:
                                    accumulated, last_decision, delta = _stream_chunk_guard(
                                        accumulated, delta, user_text, cfg, prev_redacted
                                    )
                                    prev_redacted = last_decision.sanitized_text or accumulated
                                    if last_decision.blocked:
                                        raise GatewayBlockedError(last_decision)
                                    if delta != chunk["choices"][0]["delta"].get("content"):
                                        chunk["choices"][0]["delta"]["content"] = delta
                                        converted = f"data: {json.dumps(chunk)}\n\n"
                        except (json.JSONDecodeError, KeyError, IndexError):
                            pass
                    yield converted
        except GatewayBlockedError:
            raise
        except requests.RequestException as exc:
            yield _sse_error(str(exc))
            return
    else:
        try:
            validate_upstream_url(active_plan.request_url)
            with requests.post(
                active_plan.request_url,
                json=active_plan.request_body,
                headers=active_plan.request_headers,
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
                        accumulated, last_decision, delta_text = _stream_chunk_guard(
                            accumulated, delta_text, user_text, cfg, prev_redacted
                        )
                        prev_redacted = last_decision.sanitized_text or accumulated
                        if last_decision.blocked:
                            raise GatewayBlockedError(last_decision)
                        if delta_text != _extract_stream_delta(payload):
                            payload = _replace_stream_delta(payload, delta_text)
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
            model=model,
            blocked=False,
            latency_ms=int((time.monotonic() - started) * 1000),
            started_at=started_at,
            request_decision=req_decision,
        )


def _stream_chunk_guard(
    accumulated: str,
    delta: str,
    user_text: str,
    config: RuntimePolicyConfig,
    prev_redacted: str,
) -> tuple[str, GuardDecision, str]:
    accumulated = accumulated + delta
    decision = guard_text(accumulated, phase="response", prior_prompt=user_text, config=config)
    if decision.policy_action == "sanitize" and decision.sanitized_text is not None:
        redacted = decision.sanitized_text
        new_delta = redacted[len(prev_redacted) :]
        return redacted, decision, new_delta
    return accumulated, decision, delta


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


def execute_bedrock_invoke_capability(
    plan: VendorPlan,
    body: dict[str, Any],
    *,
    capability: str,
    config: RuntimePolicyConfig,
    timeout: float = 120.0,
    ingest_callback: Optional[Callable[..., None]] = None,
    request_decision: GuardDecision | None = None,
) -> Tuple[int, Dict[str, Any]]:
    """Run Bedrock InvokeModel / Polly for embeddings, image, speech and normalize to OpenAI shapes."""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    model = str(body.get("model") or plan.bedrock_model_id or "")

    try:
        if plan.response_shape == "bedrock_speech_json" or (plan.request_body or {}).get("_eeg_service") == "polly":
            data = _execute_polly_speech(plan)
        else:
            client = _bedrock_runtime_client(plan)
            if plan.response_shape == "bedrock_embed_json":
                vectors: list[list[float]] = []
                for item in (plan.request_body or {}).get("inputs") or []:
                    resp = client.invoke_model(
                        modelId=plan.bedrock_model_id,
                        body=json.dumps(item),
                        contentType="application/json",
                        accept="application/json",
                    )
                    payload = json.loads(resp["body"].read())
                    embedding = payload.get("embedding") or []
                    vectors.append([float(v) for v in embedding])
                data = normalize_vendor_response(plan, {"vectors": vectors}, model=model)
            elif plan.response_shape == "bedrock_image_json":
                resp = client.invoke_model(
                    modelId=plan.bedrock_model_id,
                    body=json.dumps(plan.request_body),
                    contentType="application/json",
                    accept="application/json",
                )
                payload = json.loads(resp["body"].read())
                images = payload.get("images") or []
                data = normalize_vendor_response(plan, {"images": images}, model=model)
            else:
                return 500, _openai_error("internal_error", f"Unsupported Bedrock invoke shape {plan.response_shape}")
    except Exception as exc:
        return 502, _openai_error("upstream_error", f"Bedrock invoke failed: {exc}")

    response_text = json.dumps(data, ensure_ascii=False)[:4000]
    from eeg.runtime.guard import guard_text

    if capability == "embed":
        inp = body.get("input")
        prior = " ".join(str(x) for x in inp) if isinstance(inp, list) else str(inp or "")
    else:
        prior = str(body.get("prompt") or body.get("input") or "")
    resp_decision = guard_text(response_text, phase="response", prior_prompt=prior, config=config)
    if resp_decision.blocked:
        if ingest_callback:
            _safe_ingest(
                ingest_callback,
                decision=resp_decision,
                input_text=prior,
                output_text=response_text,
                model=model,
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
            input_text=prior,
            output_text=response_text,
            model=model,
            blocked=False,
            latency_ms=int((time.monotonic() - started) * 1000),
            started_at=started_at,
            request_decision=request_decision,
        )
    return 200, data


def _execute_polly_speech(plan: VendorPlan) -> dict[str, Any]:
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required for Bedrock/Polly speech") from exc
    from eeg.gateway.multimodal import b64_audio_response

    creds = plan.bedrock_credentials
    session = boto3.Session(
        aws_access_key_id=creds.get("access_key_id"),
        aws_secret_access_key=creds.get("secret_access_key"),
        aws_session_token=creds.get("session_token"),
        region_name=plan.bedrock_region,
    )
    client = session.client("polly")
    body = dict(plan.request_body or {})
    body.pop("_eeg_service", None)
    resp = client.synthesize_speech(**body)
    audio = resp["AudioStream"].read()
    content_type = {
        "mp3": "audio/mpeg",
        "ogg_vorbis": "audio/ogg",
        "pcm": "audio/pcm",
    }.get(str(body.get("OutputFormat") or "mp3"), "audio/mpeg")
    out = b64_audio_response(audio_bytes=audio, content_type=content_type)
    out["model"] = plan.bedrock_model_id
    out["voice"] = body.get("VoiceId")
    return out
