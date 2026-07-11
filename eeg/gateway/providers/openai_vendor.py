"""OpenAI-compatible vendor passthrough."""
from __future__ import annotations

from typing import Any

from eeg.gateway.providers.types import VendorPlan

DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"


def compose_openai_plan(
    body: dict[str, Any],
    config: dict[str, Any],
    *,
    stream: bool,
) -> VendorPlan:
    api_key = (config.get("api_key") or "").strip()
    base_url = (config.get("base_url") or DEFAULT_OPENAI_BASE).rstrip("/")
    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    org = (config.get("organization") or "").strip()
    if org:
        headers["OpenAI-Organization"] = org
    project = (config.get("project") or "").strip()
    if project:
        headers["OpenAI-Project"] = project

    payload = dict(body)
    if stream:
        payload["stream"] = True
        headers["Accept"] = "text/event-stream"

    return VendorPlan(
        vendor_slug="openai",
        transport="http",
        request_url=f"{base_url}/chat/completions",
        request_headers=headers,
        request_body=payload,
        response_shape="openai_json",
        stream_shape="openai_sse" if stream else "none",
    )


def normalize_openai_response(data: dict[str, Any]) -> dict[str, Any]:
    return data
