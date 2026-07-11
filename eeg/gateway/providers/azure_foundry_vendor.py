"""Azure OpenAI / AI Foundry vendor routing (classic deployment + v1 OpenAI-compat)."""
from __future__ import annotations

from typing import Any

from eeg.gateway.cloud_safety import apply_azure_prompt_shield
from eeg.gateway.providers.types import VendorPlan

DEFAULT_API_VERSION = "2024-08-01-preview"
SUPPORTED_CAPS = frozenset(
    {"chat", "mcp_toolsets", "embed", "image", "speech", "transcription"}
)
_MULTIPART_CAPS = frozenset({"transcription", "files"})


def _resolve_root(config: dict[str, Any]) -> str:
    resource = (
        config.get("resource_name")
        or config.get("endpoint")
        or config.get("base_url")
        or ""
    ).strip()
    if not resource:
        raise ValueError("Azure Foundry requires resource_name or endpoint")

    if resource.startswith("https://"):
        base = resource.rstrip("/")
        if base.endswith("/openai/v1"):
            return base[: -len("/openai/v1")]
        if "/openai" in base:
            return base.split("/openai")[0]
        return base
    if ".services.ai.azure.com" in resource or ".openai.azure.com" in resource:
        return f"https://{resource}"
    return f"https://{resource}.openai.azure.com"


def _api_style(config: dict[str, Any], root: str) -> str:
    explicit = (config.get("api_style") or "").strip().lower()
    if explicit in {"v1", "deployment", "classic"}:
        return "v1" if explicit == "v1" else "deployment"
    if "services.ai.azure.com" in root:
        return "v1"
    if (config.get("base_url") or "").rstrip("/").endswith("/openai/v1"):
        return "v1"
    return "deployment"


def _auth_headers(config: dict[str, Any], *, stream: bool, multipart: bool = False) -> dict[str, str]:
    api_key = (config.get("api_key") or "").strip()
    if not api_key:
        raise ValueError("Azure Foundry requires api_key")
    headers: dict[str, str] = {}
    if not multipart:
        headers["Content-Type"] = "application/json"
    if str(config.get("auth_mode") or "").lower() == "bearer":
        headers["Authorization"] = f"Bearer {api_key}"
    else:
        headers["api-key"] = api_key
    if stream:
        headers["Accept"] = "text/event-stream"
    return headers


def _deployment_id(body: dict[str, Any], config: dict[str, Any], *, capability: str) -> str:
    if capability == "embed":
        deployment = (
            config.get("embed_deployment_id")
            or config.get("deployment_id")
            or config.get("deployment")
            or body.get("model")
            or config.get("default_embed_model")
            or config.get("default_model")
            or ""
        ).strip()
    elif capability == "image":
        deployment = (
            config.get("image_deployment_id")
            or config.get("deployment_id")
            or config.get("deployment")
            or body.get("model")
            or config.get("default_image_model")
            or "dall-e-3"
        ).strip()
    elif capability == "speech":
        deployment = (
            config.get("speech_deployment_id")
            or config.get("deployment_id")
            or body.get("model")
            or config.get("default_speech_model")
            or "tts-1"
        ).strip()
    elif capability == "transcription":
        deployment = (
            config.get("transcription_deployment_id")
            or config.get("deployment_id")
            or body.get("model")
            or config.get("default_transcription_model")
            or "whisper-1"
        ).strip()
    else:
        deployment = (
            config.get("deployment_id")
            or config.get("deployment")
            or body.get("model")
            or config.get("default_model")
            or ""
        ).strip()
    if not deployment:
        raise ValueError("Azure Foundry requires deployment_id (or model) in config/request")
    return deployment


def _capability_path(capability: str) -> str:
    mapping = {
        "chat": "chat/completions",
        "mcp_toolsets": "chat/completions",
        "embed": "embeddings",
        "image": "images/generations",
        "speech": "audio/speech",
        "transcription": "audio/transcriptions",
    }
    return mapping[capability]


def compose_azure_foundry_plan(
    body: dict[str, Any],
    config: dict[str, Any],
    *,
    stream: bool,
    capability: str = "chat",
) -> VendorPlan:
    cap = (capability or "chat").strip().lower()
    if cap not in SUPPORTED_CAPS:
        raise ValueError(f"Azure Foundry does not support capability '{capability}'")

    root = _resolve_root(config)
    style = _api_style(config, root)
    api_version = (config.get("api_version") or DEFAULT_API_VERSION).strip()
    deployment = _deployment_id(body, config, capability=cap)
    multipart = cap in _MULTIPART_CAPS
    headers = _auth_headers(
        config,
        stream=stream and cap in {"chat", "mcp_toolsets"},
        multipart=multipart,
    )

    payload = dict(body) if body else {}
    if stream and cap in {"chat", "mcp_toolsets"}:
        payload["stream"] = True

    path = _capability_path(cap)
    if style == "v1":
        base = f"{root}/openai/v1"
        url = f"{base}/{path}"
        payload["model"] = deployment
    else:
        url = f"{root}/openai/deployments/{deployment}/{path}?api-version={api_version}"
        payload["model"] = deployment

    if cap in {"chat", "mcp_toolsets"}:
        payload = apply_azure_prompt_shield(payload, config)

    return VendorPlan(
        vendor_slug="azure_foundry",
        transport="http",
        request_url=url,
        request_headers=headers,
        request_body=payload,
        response_shape="openai_json",
        stream_shape="openai_sse" if stream and cap in {"chat", "mcp_toolsets"} else "none",
        capability=cap if cap != "mcp_toolsets" else "chat",
        multipart=multipart,
    )


def normalize_azure_foundry_response(data: dict[str, Any]) -> dict[str, Any]:
    return data
