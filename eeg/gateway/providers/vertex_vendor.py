"""Google Vertex AI (Gemini) vendor: chat with tools/system/images, embeddings, Imagen, streaming."""
from __future__ import annotations

import json
import time
from typing import Any
from uuid import uuid4

from eeg.gateway.cloud_safety import apply_vertex_model_armor
from eeg.gateway.multimodal import image_url_to_vertex_part
from eeg.gateway.providers.types import VendorPlan

DEFAULT_LOCATION = "us-central1"
DEFAULT_CHAT_MODEL = "gemini-2.0-flash"
DEFAULT_EMBED_MODEL = "gemini-embedding-001"
DEFAULT_IMAGE_MODEL = "imagen-3.0-generate-001"
SYSTEM_ROLES = frozenset({"system", "developer"})


def _vertex_access_token(config: dict[str, Any]) -> str:
    token = str(config.get("access_token") or config.get("api_key") or "").strip()
    if token and not token.startswith("{"):
        # Service-account JSON pasted into api_key should not be treated as a bearer token.
        if "private_key" not in token:
            return token

    # Inline service-account JSON
    sa_json = config.get("service_account_json") or config.get("credentials_json")
    if isinstance(sa_json, dict):
        return _token_from_service_account_info(sa_json)
    if isinstance(sa_json, str) and sa_json.strip().startswith("{"):
        return _token_from_service_account_info(json.loads(sa_json))
    if token.startswith("{") and "private_key" in token:
        return _token_from_service_account_info(json.loads(token))

    creds_path = (config.get("credentials_path") or "").strip()
    if creds_path:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request

        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        creds = service_account.Credentials.from_service_account_file(creds_path, scopes=scopes)
        creds.refresh(Request())
        return creds.token or ""
    return ""


def _token_from_service_account_info(info: dict[str, Any]) -> str:
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request

    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    creds = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    creds.refresh(Request())
    return creds.token or ""


def _extract_system_instruction(messages: list[Any]) -> dict[str, Any] | None:
    parts: list[dict[str, str]] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") not in SYSTEM_ROLES:
            continue
        content = msg.get("content")
        if isinstance(content, str) and content.strip():
            parts.append({"text": content})
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                    parts.append({"text": str(block["text"])})
    if not parts:
        return None
    return {"parts": parts}


def _openai_messages_to_vertex(messages: list[Any]) -> list[dict[str, Any]]:
    contents: list[dict[str, Any]] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role in SYSTEM_ROLES:
            continue

        if role == "tool":
            name = str(msg.get("name") or "")
            raw = msg.get("content")
            try:
                response_obj = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except json.JSONDecodeError:
                response_obj = {"result": str(raw or "")}
            if not isinstance(response_obj, dict):
                response_obj = {"result": response_obj}
            contents.append(
                {
                    "role": "user",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": name,
                                "response": response_obj,
                            }
                        }
                    ],
                }
            )
            continue

        vertex_role = "model" if role == "assistant" else "user"
        parts: list[dict[str, Any]] = []

        content = msg.get("content")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("text"):
                    parts.append({"text": block["text"]})
                elif block.get("type") == "text" and block.get("text"):
                    parts.append({"text": block["text"]})
                elif block.get("type") == "image_url":
                    image_part = image_url_to_vertex_part(block)
                    if image_part:
                        parts.append(image_part)
        elif isinstance(content, str) and content.strip():
            parts.append({"text": content})

        for tc in msg.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") or {}
            args_raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except json.JSONDecodeError:
                args = {}
            parts.append(
                {
                    "functionCall": {
                        "name": fn.get("name") or "",
                        "args": args if isinstance(args, dict) else {},
                    }
                }
            )

        if not parts:
            continue
        contents.append({"role": vertex_role, "parts": parts})
    return contents


def _openai_tools_to_vertex(tools: Any) -> list[dict[str, Any]] | None:
    if not isinstance(tools, list) or not tools:
        return None
    declarations = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") or {}
        name = fn.get("name")
        if not name:
            continue
        decl: dict[str, Any] = {
            "name": name,
            "description": fn.get("description") or "",
        }
        params = fn.get("parameters")
        if isinstance(params, dict):
            decl["parameters"] = params
        declarations.append(decl)
    if not declarations:
        return None
    return [{"functionDeclarations": declarations}]


def _tool_config(body: dict[str, Any]) -> dict[str, Any] | None:
    choice = body.get("tool_choice")
    if choice is None:
        return None
    if choice == "none":
        return {"functionCallingConfig": {"mode": "NONE"}}
    if choice == "auto":
        return {"functionCallingConfig": {"mode": "AUTO"}}
    if choice == "required":
        return {"functionCallingConfig": {"mode": "ANY"}}
    if isinstance(choice, dict) and choice.get("type") == "function":
        name = (choice.get("function") or {}).get("name")
        if name:
            return {
                "functionCallingConfig": {
                    "mode": "ANY",
                    "allowedFunctionNames": [name],
                }
            }
    return None


def _compose_chat_plan(body: dict[str, Any], config: dict[str, Any], *, stream: bool) -> VendorPlan:
    project = (config.get("project_id") or config.get("project") or "").strip()
    location = (config.get("location") or config.get("region") or DEFAULT_LOCATION).strip()
    model = (
        body.get("model") or config.get("model_id") or config.get("default_model") or DEFAULT_CHAT_MODEL
    ).strip()
    if not project:
        raise ValueError("Vertex connector requires project_id in config")

    token = _vertex_access_token(config)
    if not token:
        raise ValueError(
            "Vertex requires access_token, credentials_path, or service_account_json"
        )

    action = "streamGenerateContent" if stream else "generateContent"
    url = (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project}/locations/{location}/publishers/google/models/{model}:{action}"
    )
    if stream:
        url = f"{url}?alt=sse"

    messages = body.get("messages") or []
    contents = _openai_messages_to_vertex(messages)
    payload: dict[str, Any] = {"contents": contents}

    system = _extract_system_instruction(messages)
    if system:
        payload["systemInstruction"] = system

    gen: dict[str, Any] = {}
    if body.get("max_tokens") or body.get("max_completion_tokens"):
        gen["maxOutputTokens"] = int(body.get("max_tokens") or body.get("max_completion_tokens"))
    if body.get("temperature") is not None:
        gen["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        gen["topP"] = body["top_p"]
    if body.get("stop"):
        stops = body["stop"] if isinstance(body["stop"], list) else [body["stop"]]
        gen["stopSequences"] = stops
    if gen:
        payload["generationConfig"] = gen

    tools = _openai_tools_to_vertex(body.get("tools"))
    if tools and body.get("tool_choice") != "none":
        payload["tools"] = tools
        tool_cfg = _tool_config(body)
        if tool_cfg:
            payload["toolConfig"] = tool_cfg

    payload = apply_vertex_model_armor(payload, config)

    return VendorPlan(
        vendor_slug="vertex",
        transport="http",
        request_url=url,
        request_headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        request_body=payload,
        response_shape="vertex_json",
        stream_shape="vertex_sse" if stream else "none",
        capability="chat",
        vertex_model=model,
        vertex_project=project,
        vertex_location=location,
    )


def _compose_embed_plan(body: dict[str, Any], config: dict[str, Any]) -> VendorPlan:
    project = (config.get("project_id") or config.get("project") or "").strip()
    location = (config.get("location") or config.get("region") or DEFAULT_LOCATION).strip()
    model = (
        body.get("model")
        or config.get("embed_model_id")
        or config.get("default_embed_model")
        or DEFAULT_EMBED_MODEL
    ).strip()
    if not project:
        raise ValueError("Vertex connector requires project_id in config")
    token = _vertex_access_token(config)
    if not token:
        raise ValueError(
            "Vertex requires access_token, credentials_path, or service_account_json"
        )

    raw_input = body.get("input")
    if isinstance(raw_input, list):
        texts = [str(x) for x in raw_input]
    elif raw_input is None:
        texts = []
    else:
        texts = [str(raw_input)]
    if not texts:
        raise ValueError("embeddings input is required")

    # gemini-embedding-001 accepts one input per request; batch via repeated predict.
    instances = [{"content": t} for t in texts]
    parameters: dict[str, Any] = {"autoTruncate": True}
    if body.get("dimensions") is not None:
        parameters["outputDimensionality"] = int(body["dimensions"])
    if body.get("task_type"):
        for inst in instances:
            inst["task_type"] = str(body["task_type"])

    url = (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project}/locations/{location}/publishers/google/models/{model}:predict"
    )
    return VendorPlan(
        vendor_slug="vertex",
        transport="http",
        request_url=url,
        request_headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        request_body={"instances": instances, "parameters": parameters, "_eeg_batch": True},
        response_shape="vertex_embed_json",
        stream_shape="none",
        capability="embed",
        vertex_model=model,
        vertex_project=project,
        vertex_location=location,
    )


def _compose_image_plan(body: dict[str, Any], config: dict[str, Any]) -> VendorPlan:
    project = (config.get("project_id") or config.get("project") or "").strip()
    location = (config.get("location") or config.get("region") or DEFAULT_LOCATION).strip()
    model = (
        body.get("model")
        or config.get("image_model_id")
        or config.get("default_image_model")
        or DEFAULT_IMAGE_MODEL
    ).strip()
    if not project:
        raise ValueError("Vertex connector requires project_id in config")
    token = _vertex_access_token(config)
    if not token:
        raise ValueError(
            "Vertex requires access_token, credentials_path, or service_account_json"
        )

    prompt = str(body.get("prompt") or "").strip()
    if not prompt:
        raise ValueError("image prompt is required")

    n = max(1, min(int(body.get("n") or 1), 4))
    parameters: dict[str, Any] = {"sampleCount": n}
    if body.get("size"):
        # Map OpenAI size strings to Imagen aspectRatio when possible
        size = str(body["size"]).lower()
        if size in {"1792x1024", "1536x1024"}:
            parameters["aspectRatio"] = "16:9"
        elif size in {"1024x1792", "1024x1536"}:
            parameters["aspectRatio"] = "9:16"
        else:
            parameters["aspectRatio"] = "1:1"
    if body.get("negative_prompt"):
        parameters["negativePrompt"] = str(body["negative_prompt"])[:512]

    url = (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project}/locations/{location}/publishers/google/models/{model}:predict"
    )
    return VendorPlan(
        vendor_slug="vertex",
        transport="http",
        request_url=url,
        request_headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        request_body={
            "instances": [{"prompt": prompt}],
            "parameters": parameters,
        },
        response_shape="vertex_image_json",
        stream_shape="none",
        capability="image",
        vertex_model=model,
        vertex_project=project,
        vertex_location=location,
    )


def compose_vertex_plan(
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
    raise ValueError(f"Vertex does not support capability '{capability}'")


def normalize_vertex_response(data: dict[str, Any], model: str) -> dict[str, Any]:
    candidates = data.get("candidates") or []
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    finish = "stop"

    if candidates:
        parts = (candidates[0].get("content") or {}).get("parts") or []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if part.get("text"):
                text_parts.append(part["text"])
            elif part.get("functionCall"):
                fc = part["functionCall"]
                tool_calls.append(
                    {
                        "id": f"call_{uuid4().hex[:12]}",
                        "type": "function",
                        "function": {
                            "name": fc.get("name") or "",
                            "arguments": json.dumps(fc.get("args") or {}),
                        },
                    }
                )
        finish_reason = candidates[0].get("finishReason") or ""
        if tool_calls:
            finish = "tool_calls"
        elif finish_reason in {"MAX_TOKENS", "LENGTH"}:
            finish = "length"

    usage_meta = data.get("usageMetadata") or {}
    input_tokens = int(usage_meta.get("promptTokenCount") or 0)
    output_tokens = int(usage_meta.get("candidatesTokenCount") or 0)

    message: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls
        if message["content"] is None:
            message["content"] = ""

    return {
        "id": f"chatcmpl-vertex-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
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
            "total_tokens": int(usage_meta.get("totalTokenCount") or input_tokens + output_tokens),
        },
    }


def normalize_vertex_embed_response(data: dict[str, Any], *, model: str) -> dict[str, Any]:
    predictions = data.get("predictions") or []
    vectors: list[list[float]] = []
    for pred in predictions:
        if not isinstance(pred, dict):
            continue
        emb = pred.get("embeddings") or pred.get("values")
        if isinstance(emb, dict):
            values = emb.get("values") or []
        else:
            values = emb or []
        vectors.append([float(v) for v in values])
    return {
        "object": "list",
        "data": [
            {"object": "embedding", "index": idx, "embedding": vec}
            for idx, vec in enumerate(vectors)
        ],
        "model": model,
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
    }


def normalize_vertex_image_response(data: dict[str, Any], *, model: str) -> dict[str, Any]:
    predictions = data.get("predictions") or []
    images: list[str] = []
    for pred in predictions:
        if not isinstance(pred, dict):
            continue
        # Imagen returns bytesBase64Encoded or similar keys depending on model version
        b64 = (
            pred.get("bytesBase64Encoded")
            or pred.get("image")
            or (pred.get("images") or [None])[0]
        )
        if isinstance(b64, dict):
            b64 = b64.get("bytesBase64Encoded") or b64.get("b64_json")
        if isinstance(b64, str) and b64:
            images.append(b64)
        # Some responses nest under "predictions[].mimeType" + bytes
        nested = pred.get("bytesBase64Encoded")
        if not images and isinstance(nested, str):
            images.append(nested)
    return {
        "created": int(time.time()),
        "data": [{"b64_json": img, "revised_prompt": None} for img in images],
        "model": model,
    }


def vertex_stream_line_to_openai(line: str, fallback_id: str, model: str) -> str | None:
    raw = line.strip()
    if not raw.startswith("data:"):
        return None
    payload = raw[5:].strip()
    if not payload or payload == "[DONE]":
        return "data: [DONE]\n\n"
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return None

    candidates = event.get("candidates") or []
    if not candidates:
        return None
    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(
        str(p.get("text") or "") for p in parts if isinstance(p, dict) and p.get("text")
    )
    tool_calls: list[dict[str, Any]] = []
    for p in parts:
        if not isinstance(p, dict) or not p.get("functionCall"):
            continue
        fc = p["functionCall"]
        tool_calls.append(
            {
                "index": len(tool_calls),
                "id": f"call_{uuid4().hex[:12]}",
                "type": "function",
                "function": {
                    "name": fc.get("name") or "",
                    "arguments": json.dumps(fc.get("args") or {}),
                },
            }
        )

    finish_reason = candidates[0].get("finishReason")
    delta: dict[str, Any] = {}
    if text:
        delta["content"] = text
    if tool_calls:
        delta["tool_calls"] = tool_calls
    finish = None
    if finish_reason:
        if tool_calls:
            finish = "tool_calls"
        elif finish_reason in {"MAX_TOKENS", "LENGTH"}:
            finish = "length"
        else:
            finish = "stop"
    if not delta and not finish:
        return None
    chunk = {
        "id": fallback_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    out = f"data: {json.dumps(chunk)}\n\n"
    if finish:
        out += "data: [DONE]\n\n"
    return out
