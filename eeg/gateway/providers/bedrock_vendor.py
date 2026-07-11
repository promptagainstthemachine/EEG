"""Amazon Bedrock vendor: Converse chat, Titan embeddings/image, Polly speech."""
from __future__ import annotations

import json
import time
from typing import Any

from eeg.gateway.cloud_safety import apply_bedrock_guardrail
from eeg.gateway.multimodal import image_url_to_bedrock_block
from eeg.gateway.providers.types import VendorPlan

SYSTEM_ROLES = frozenset({"system", "developer"})
DEFAULT_EMBED_MODEL = "amazon.titan-embed-text-v2:0"
DEFAULT_IMAGE_MODEL = "amazon.titan-image-generator-v2:0"
DEFAULT_SPEECH_VOICE = "Joanna"


def _bedrock_credentials(config: dict[str, Any]) -> dict[str, str]:
    region = (config.get("region") or config.get("aws_region") or "us-east-1").strip()
    role_arn = (config.get("role_arn") or "").strip()
    if role_arn:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required for Bedrock connectors") from exc
        sts = boto3.client("sts", region_name=region)
        kwargs: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "eeg-ai-gateway"}
        if config.get("external_id"):
            kwargs["ExternalId"] = str(config["external_id"])
        creds = sts.assume_role(**kwargs)["Credentials"]
        return {
            "region": region,
            "access_key_id": creds["AccessKeyId"],
            "secret_access_key": creds["SecretAccessKey"],
            "session_token": creds["SessionToken"],
        }

    access_key = str(config.get("access_key_id") or config.get("api_key") or "").strip()
    secret_key = str(config.get("secret_access_key") or config.get("api_secret") or "").strip()
    # Pass-through may encode "ACCESS_KEY:SECRET_KEY"
    if access_key and not secret_key and ":" in access_key:
        access_key, secret_key = access_key.split(":", 1)
        access_key, secret_key = access_key.strip(), secret_key.strip()
    out = {"region": region, "access_key_id": access_key, "secret_access_key": secret_key}
    if config.get("session_token"):
        out["session_token"] = str(config["session_token"])
    return out


def _message_content_blocks(msg: dict[str, Any]) -> list[dict[str, Any]]:
    if msg.get("role") == "tool":
        return [
            {
                "toolResult": {
                    "toolUseId": msg.get("tool_call_id") or "",
                    "content": [{"text": str(msg.get("content") or "")}],
                }
            }
        ]

    blocks: list[dict[str, Any]] = []
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        blocks.append({"text": content})
    elif isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                blocks.append({"text": item.get("text") or ""})
            elif item.get("type") == "image_url":
                image_block = image_url_to_bedrock_block(item)
                if image_block:
                    blocks.append(image_block)

    for tc in msg.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        args_raw = fn.get("arguments") or "{}"
        try:
            args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
        except json.JSONDecodeError:
            args = {}
        blocks.append(
            {
                "toolUse": {
                    "toolUseId": tc.get("id") or "",
                    "name": fn.get("name") or "",
                    "input": args if isinstance(args, dict) else {},
                }
            }
        )
    return blocks or [{"text": ""}]


def _openai_messages_to_bedrock(messages: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    system_blocks: list[dict[str, str]] = []
    converse_messages: list[dict[str, Any]] = []

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role in SYSTEM_ROLES:
            text = msg.get("content")
            if isinstance(text, str) and text.strip():
                system_blocks.append({"text": text})
            elif isinstance(text, list):
                for item in text:
                    if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                        system_blocks.append({"text": str(item["text"])})
            continue
        bedrock_role = "assistant" if role == "assistant" else "user"
        converse_messages.append({"role": bedrock_role, "content": _message_content_blocks(msg)})

    merged: list[dict[str, Any]] = []
    prev_role = ""
    for item in converse_messages:
        if item["role"] == "user" and prev_role == "user" and merged:
            merged[-1]["content"].extend(item["content"])
        else:
            merged.append(item)
        prev_role = item["role"]
    return merged, system_blocks


def _tool_choice(body: dict[str, Any]) -> dict[str, Any] | None:
    choice = body.get("tool_choice")
    if choice is None:
        return None
    if choice == "auto":
        return {"auto": {}}
    if choice == "none":
        return {"any": {}}  # Bedrock has no exact "none"; omit tools instead at call site
    if choice == "required":
        return {"any": {}}
    if isinstance(choice, dict) and choice.get("type") == "function":
        name = (choice.get("function") or {}).get("name") or ""
        if name:
            return {"tool": {"name": name}}
    return None


def _compose_chat_plan(body: dict[str, Any], config: dict[str, Any], *, stream: bool) -> VendorPlan:
    model_id = (
        body.get("model") or config.get("model_id") or config.get("default_model") or ""
    ).strip()
    if not model_id:
        raise ValueError("Bedrock connector requires model in request body or default_model in config")

    creds = _bedrock_credentials(config)
    if not creds.get("access_key_id") or not creds.get("secret_access_key"):
        raise ValueError("Bedrock requires role_arn or access_key_id + secret_access_key")

    messages = body.get("messages") or []
    converse_messages, system_blocks = _openai_messages_to_bedrock(messages)

    converse_body: dict[str, Any] = {"messages": converse_messages}
    if system_blocks:
        converse_body["system"] = system_blocks

    inference: dict[str, Any] = {}
    if body.get("max_tokens") or body.get("max_completion_tokens"):
        inference["maxTokens"] = int(body.get("max_tokens") or body.get("max_completion_tokens"))
    if body.get("temperature") is not None:
        inference["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        inference["topP"] = body["top_p"]
    if body.get("stop"):
        inference["stopSequences"] = body["stop"] if isinstance(body["stop"], list) else [body["stop"]]
    if inference:
        converse_body["inferenceConfig"] = inference

    tools = body.get("tools")
    if tools and body.get("tool_choice") != "none":
        tool_specs = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            fn = tool.get("function") or {}
            tool_specs.append(
                {
                    "toolSpec": {
                        "name": fn.get("name") or "",
                        "description": fn.get("description") or "",
                        "inputSchema": {
                            "json": fn.get("parameters") or {"type": "object", "properties": {}}
                        },
                    }
                }
            )
        if tool_specs:
            tool_config: dict[str, Any] = {"tools": tool_specs}
            mapped = _tool_choice(body)
            if mapped and body.get("tool_choice") != "none":
                tool_config["toolChoice"] = mapped
            converse_body["toolConfig"] = tool_config

    converse_body = apply_bedrock_guardrail(converse_body, config)

    return VendorPlan(
        vendor_slug="bedrock",
        transport="bedrock_sdk",
        request_url="",
        request_headers={},
        request_body=converse_body,
        response_shape="bedrock_json",
        stream_shape="bedrock_eventstream" if stream else "none",
        capability="chat",
        bedrock_model_id=model_id,
        bedrock_region=creds["region"],
        bedrock_credentials=creds,
    )


def _compose_embed_plan(body: dict[str, Any], config: dict[str, Any]) -> VendorPlan:
    model_id = (
        body.get("model")
        or config.get("embed_model_id")
        or config.get("default_embed_model")
        or config.get("default_model")
        or DEFAULT_EMBED_MODEL
    ).strip()
    creds = _bedrock_credentials(config)
    if not creds.get("access_key_id") or not creds.get("secret_access_key"):
        raise ValueError("Bedrock requires role_arn or access_key_id + secret_access_key")

    raw_input = body.get("input")
    if isinstance(raw_input, list):
        texts = [str(x) for x in raw_input]
    elif raw_input is None:
        texts = []
    else:
        texts = [str(raw_input)]
    if not texts:
        raise ValueError("embeddings input is required")

    dimensions = body.get("dimensions")
    normalize = body.get("normalize")
    payloads = []
    for text in texts:
        item: dict[str, Any] = {"inputText": text}
        if dimensions is not None:
            item["dimensions"] = int(dimensions)
        if normalize is not None:
            item["normalize"] = bool(normalize)
        payloads.append(item)

    return VendorPlan(
        vendor_slug="bedrock",
        transport="bedrock_invoke",
        request_url="",
        request_headers={},
        request_body={"inputs": payloads},
        response_shape="bedrock_embed_json",
        stream_shape="none",
        capability="embed",
        bedrock_model_id=model_id,
        bedrock_region=creds["region"],
        bedrock_credentials=creds,
    )


def _compose_image_plan(body: dict[str, Any], config: dict[str, Any]) -> VendorPlan:
    model_id = (
        body.get("model")
        or config.get("image_model_id")
        or config.get("default_image_model")
        or DEFAULT_IMAGE_MODEL
    ).strip()
    creds = _bedrock_credentials(config)
    if not creds.get("access_key_id") or not creds.get("secret_access_key"):
        raise ValueError("Bedrock requires role_arn or access_key_id + secret_access_key")

    prompt = str(body.get("prompt") or "").strip()
    if not prompt:
        raise ValueError("image prompt is required")

    n = int(body.get("n") or 1)
    size = str(body.get("size") or "1024x1024")
    try:
        width_s, height_s = size.lower().split("x", 1)
        width, height = int(width_s), int(height_s)
    except ValueError:
        width, height = 1024, 1024

    native: dict[str, Any] = {
        "taskType": "TEXT_IMAGE",
        "textToImageParams": {"text": prompt[:512]},
        "imageGenerationConfig": {
            "numberOfImages": max(1, min(n, 5)),
            "height": height,
            "width": width,
            "quality": "standard",
        },
    }
    if body.get("negative_prompt"):
        native["textToImageParams"]["negativeText"] = str(body["negative_prompt"])[:512]
    if body.get("seed") is not None:
        native["imageGenerationConfig"]["seed"] = int(body["seed"])

    return VendorPlan(
        vendor_slug="bedrock",
        transport="bedrock_invoke",
        request_url="",
        request_headers={},
        request_body=native,
        response_shape="bedrock_image_json",
        stream_shape="none",
        capability="image",
        bedrock_model_id=model_id,
        bedrock_region=creds["region"],
        bedrock_credentials=creds,
    )


def _compose_speech_plan(body: dict[str, Any], config: dict[str, Any]) -> VendorPlan:
    """Amazon Polly TTS mapped to OpenAI /audio/speech shape (JSON envelope)."""
    creds = _bedrock_credentials(config)
    if not creds.get("access_key_id") or not creds.get("secret_access_key"):
        raise ValueError("Bedrock speech requires role_arn or access_key_id + secret_access_key")

    text = str(body.get("input") or body.get("prompt") or "").strip()
    if not text:
        raise ValueError("speech input is required")

    voice = str(body.get("voice") or config.get("polly_voice") or DEFAULT_SPEECH_VOICE).strip()
    fmt = str(body.get("response_format") or body.get("format") or "mp3").strip().lower()
    if fmt not in {"mp3", "ogg_vorbis", "pcm"}:
        fmt = "mp3"
    engine = str(config.get("polly_engine") or body.get("engine") or "neural").strip()

    return VendorPlan(
        vendor_slug="bedrock",
        transport="bedrock_invoke",
        request_url="",
        request_headers={},
        request_body={
            "Text": text[:3000],
            "OutputFormat": fmt,
            "VoiceId": voice,
            "Engine": engine,
            "_eeg_service": "polly",
        },
        response_shape="bedrock_speech_json",
        stream_shape="none",
        capability="speech",
        bedrock_model_id=f"polly:{voice}",
        bedrock_region=creds["region"],
        bedrock_credentials=creds,
    )


def compose_bedrock_plan(
    body: dict[str, Any],
    config: dict[str, Any],
    *,
    stream: bool,
    capability: str = "chat",
) -> VendorPlan:
    cap = (capability or "chat").strip().lower()
    if cap in {"chat", "mcp_toolsets"}:
        return _compose_chat_plan(body, config, stream=stream)
    if cap == "embed":
        return _compose_embed_plan(body, config)
    if cap == "image":
        return _compose_image_plan(body, config)
    if cap == "speech":
        return _compose_speech_plan(body, config)
    raise ValueError(f"Bedrock does not support capability '{capability}'")


def normalize_bedrock_response(data: dict[str, Any], model: str) -> dict[str, Any]:
    output = data.get("output") or {}
    message = output.get("message") or {}
    content_blocks = message.get("content") or []

    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in content_blocks:
        if not isinstance(block, dict):
            continue
        if block.get("text"):
            text_parts.append(block["text"])
        elif block.get("toolUse"):
            tu = block["toolUse"]
            tool_calls.append(
                {
                    "id": tu.get("toolUseId") or "",
                    "type": "function",
                    "function": {
                        "name": tu.get("name") or "",
                        "arguments": json.dumps(tu.get("input") or {}),
                    },
                }
            )

    usage = data.get("usage") or {}
    input_tokens = int(usage.get("inputTokens") or 0)
    output_tokens = int(usage.get("outputTokens") or 0)
    stop_reason = data.get("stopReason") or "end_turn"
    finish = "tool_calls" if tool_calls else ("length" if stop_reason == "max_tokens" else "stop")

    message_out: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts)}
    if tool_calls:
        message_out["tool_calls"] = tool_calls

    return {
        "id": f"chatcmpl-bedrock-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message_out, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": int(usage.get("totalTokens") or input_tokens + output_tokens),
        },
    }


def normalize_bedrock_embed_response(
    vectors: list[list[float]],
    *,
    model: str,
) -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {"object": "embedding", "index": idx, "embedding": vec}
            for idx, vec in enumerate(vectors)
        ],
        "model": model,
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
    }


def normalize_bedrock_image_response(
    images_b64: list[str],
    *,
    model: str,
) -> dict[str, Any]:
    return {
        "created": int(time.time()),
        "data": [{"b64_json": img, "revised_prompt": None} for img in images_b64],
        "model": model,
    }


def bedrock_stream_event_to_openai(event: dict[str, Any], fallback_id: str, model: str) -> str | None:
    """
    Convert a normalized Bedrock stream fragment to OpenAI SSE.

    Accepted keys (set by vendor_executor):
      - delta.text
      - tool_start: {id, name, index}
      - tool_delta: {index, arguments}
      - stopReason
    """
    if event.get("message"):
        return None

    created = int(time.time())
    if event.get("tool_start"):
        ts = event["tool_start"]
        chunk = {
            "id": fallback_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": int(ts.get("index") or 0),
                                "id": ts.get("id") or "",
                                "type": "function",
                                "function": {"name": ts.get("name") or "", "arguments": ""},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ],
        }
        return f"data: {json.dumps(chunk)}\n\n"

    if event.get("tool_delta"):
        td = event["tool_delta"]
        args = td.get("arguments") or ""
        if not args:
            return None
        chunk = {
            "id": fallback_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": int(td.get("index") or 0),
                                "function": {"arguments": args},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ],
        }
        return f"data: {json.dumps(chunk)}\n\n"

    delta_text = (event.get("delta") or {}).get("text")
    if event.get("stopReason"):
        finish = "tool_calls" if event.get("stopReason") == "tool_use" else "stop"
        if event.get("stopReason") == "max_tokens":
            finish = "length"
        chunk = {
            "id": fallback_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
        }
        return f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"

    if not delta_text:
        return None
    chunk = {
        "id": fallback_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {"content": delta_text}, "finish_reason": None}],
    }
    return f"data: {json.dumps(chunk)}\n\n"
