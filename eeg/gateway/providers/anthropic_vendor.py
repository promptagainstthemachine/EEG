"""Anthropic Messages API vendor with OpenAI chat completion normalization."""
from __future__ import annotations

import json
import time
from typing import Any

from eeg.gateway.providers.types import VendorPlan

DEFAULT_ANTHROPIC_BASE = "https://api.anthropic.com/v1"
SYSTEM_ROLES = frozenset({"system", "developer"})


def _extract_system_blocks(messages: list[Any]) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") not in SYSTEM_ROLES:
            continue
        content = msg.get("content")
        if isinstance(content, str) and content.strip():
            blocks.append({"type": "text", "text": content})
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                    blocks.append({"type": "text", "text": str(item["text"])})
    return blocks


def _openai_messages_to_anthropic(messages: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role in SYSTEM_ROLES:
            continue
        if role == "tool":
            out.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id") or "",
                            "content": msg.get("content") or "",
                        }
                    ],
                }
            )
            continue
        if role == "assistant" and msg.get("tool_calls"):
            content_blocks: list[dict[str, Any]] = []
            text = msg.get("content")
            if isinstance(text, str) and text:
                content_blocks.append({"type": "text", "text": text})
            for tc in msg.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") or {}
                args_raw = fn.get("arguments") or "{}"
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except json.JSONDecodeError:
                    args = {}
                content_blocks.append(
                    {
                        "type": "tool_use",
                        "id": tc.get("id") or "",
                        "name": fn.get("name") or "",
                        "input": args if isinstance(args, dict) else {},
                    }
                )
            out.append({"role": "assistant", "content": content_blocks})
            continue

        content = msg.get("content")
        if isinstance(content, str):
            out.append({"role": role, "content": content})
        elif isinstance(content, list):
            anthropic_content: list[dict[str, Any]] = []
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "text":
                    anthropic_content.append({"type": "text", "text": item.get("text") or ""})
                elif item.get("type") == "image_url" and isinstance(item.get("image_url"), dict):
                    url = item["image_url"].get("url") or ""
                    if url.startswith("data:"):
                        parts = url.split(",", 1)
                        meta = parts[0]
                        data = parts[1] if len(parts) > 1 else ""
                        media = meta.split(";")[0].replace("data:", "")
                        anthropic_content.append(
                            {
                                "type": "image",
                                "source": {"type": "base64", "media_type": media, "data": data},
                            }
                        )
                    else:
                        anthropic_content.append(
                            {"type": "image", "source": {"type": "url", "url": url}}
                        )
            out.append({"role": role, "content": anthropic_content or ""})
        else:
            out.append({"role": role, "content": str(content or "")})
    return out


def _map_tool_choice(tool_choice: Any) -> dict[str, Any] | None:
    if tool_choice is None:
        return None
    if isinstance(tool_choice, str):
        if tool_choice == "required":
            return {"type": "any"}
        if tool_choice == "auto":
            return {"type": "auto"}
        if tool_choice == "none":
            return {"type": "none"}
        return None
    if isinstance(tool_choice, dict):
        fn = tool_choice.get("function") or {}
        name = fn.get("name")
        if name:
            return {"type": "tool", "name": name}
    return None


def compose_anthropic_plan(
    body: dict[str, Any],
    config: dict[str, Any],
    *,
    stream: bool,
) -> VendorPlan:
    api_key = (config.get("api_key") or "").strip()
    base_url = (config.get("base_url") or DEFAULT_ANTHROPIC_BASE).rstrip("/")
    messages = body.get("messages") or []
    model = body.get("model") or config.get("default_model") or "claude-sonnet-4-20250514"
    max_tokens = body.get("max_tokens") or body.get("max_completion_tokens") or config.get("max_tokens") or 4096

    anthropic_body: dict[str, Any] = {
        "model": model,
        "max_tokens": int(max_tokens),
        "messages": _openai_messages_to_anthropic(messages),
    }
    system_blocks = _extract_system_blocks(messages)
    if system_blocks:
        anthropic_body["system"] = system_blocks

    for field in ("temperature", "top_p", "stop"):
        if body.get(field) is not None:
            if field == "stop":
                anthropic_body["stop_sequences"] = body[field]
            else:
                anthropic_body[field] = body[field]

    if body.get("tools"):
        tools = []
        for tool in body["tools"]:
            if not isinstance(tool, dict):
                continue
            fn = tool.get("function") or {}
            tools.append(
                {
                    "name": fn.get("name") or "",
                    "description": fn.get("description") or "",
                    "input_schema": {
                        "type": (fn.get("parameters") or {}).get("type") or "object",
                        "properties": (fn.get("parameters") or {}).get("properties") or {},
                        "required": (fn.get("parameters") or {}).get("required") or [],
                    },
                }
            )
        if tools:
            anthropic_body["tools"] = tools
            mapped = _map_tool_choice(body.get("tool_choice"))
            if mapped:
                anthropic_body["tool_choice"] = mapped

    if stream:
        anthropic_body["stream"] = True

    headers = {
        "x-api-key": api_key,
        "anthropic-version": (config.get("anthropic_version") or "2023-06-01"),
        "content-type": "application/json",
    }
    beta = (config.get("anthropic_beta") or "messages-2023-12-15").strip()
    if beta:
        headers["anthropic-beta"] = beta

    return VendorPlan(
        vendor_slug="anthropic",
        transport="http",
        request_url=f"{base_url}/messages",
        request_headers=headers,
        request_body=anthropic_body,
        response_shape="anthropic_json",
        stream_shape="anthropic_sse" if stream else "none",
    )


def normalize_anthropic_response(data: dict[str, Any]) -> dict[str, Any]:
    content_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in data.get("content") or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            content_parts.append(block.get("text") or "")
        elif block.get("type") == "tool_use":
            tool_calls.append(
                {
                    "id": block.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": block.get("name") or "",
                        "arguments": json.dumps(block.get("input") or {}),
                    },
                }
            )

    usage = data.get("usage") or {}
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    stop_reason = data.get("stop_reason") or "stop"
    finish = "tool_calls" if tool_calls else ("length" if stop_reason == "max_tokens" else "stop")

    message: dict[str, Any] = {"role": "assistant", "content": "".join(content_parts)}
    if tool_calls:
        message["tool_calls"] = tool_calls

    return {
        "id": data.get("id") or f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": data.get("model") or "",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish,
            }
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
    }


def anthropic_stream_line_to_openai(line: str, fallback_id: str, model: str) -> str | None:
    raw = line.strip()
    if raw.startswith("event:"):
        return None
    if not raw.startswith("data:"):
        return None
    payload = raw[5:].strip()
    if not payload:
        return None
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return None

    event_type = event.get("type")
    if event_type == "message_stop":
        return "data: [DONE]\n\n"

    delta: dict[str, Any] = {}
    if event_type == "content_block_delta":
        text = (event.get("delta") or {}).get("text")
        if text:
            delta["content"] = text
    elif event_type == "content_block_start":
        block = event.get("content_block") or {}
        if block.get("type") == "tool_use":
            delta["tool_calls"] = [
                {
                    "index": 0,
                    "id": block.get("id"),
                    "type": "function",
                    "function": {"name": block.get("name"), "arguments": ""},
                }
            ]

    if not delta and event_type not in ("message_start", "message_delta"):
        return None

    chunk = {
        "id": fallback_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
    }
    if event_type == "message_delta":
        chunk["choices"][0]["finish_reason"] = "stop"
    return f"data: {json.dumps(chunk)}\n\n"
