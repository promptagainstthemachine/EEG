"""Vendor plan composition and response normalization."""
from __future__ import annotations

from typing import Any

from eeg.gateway.providers.anthropic_vendor import (
    compose_anthropic_plan,
    normalize_anthropic_response,
)
from eeg.gateway.providers.azure_foundry_vendor import (
    compose_azure_foundry_plan,
    normalize_azure_foundry_response,
)
from eeg.gateway.providers.bedrock_vendor import (
    compose_bedrock_plan,
    normalize_bedrock_embed_response,
    normalize_bedrock_image_response,
    normalize_bedrock_response,
)
from eeg.gateway.providers.catalog import compose_catalog_plan, provider_count
from eeg.gateway.providers.openai_vendor import (
    compose_openai_plan,
    normalize_openai_response,
)
from eeg.gateway.providers.vertex_vendor import (
    compose_vertex_plan,
    normalize_vertex_embed_response,
    normalize_vertex_image_response,
    normalize_vertex_response,
)
from eeg.gateway.providers.types import VendorPlan

SUPPORTED_BACKENDS = frozenset({"openai", "anthropic", "bedrock", "azure_foundry", "vertex"})


def compose_vendor_plan(
    config: dict[str, Any],
    body: dict[str, Any],
    *,
    stream: bool,
    capability: str = "chat",
    method: str = "POST",
    path_suffix: str = "",
) -> VendorPlan:
    """Compose an upstream dispatch plan from connector config and catalog metadata."""
    return compose_catalog_plan(
        config,
        body,
        capability=capability,
        stream=stream,
        method=method,
        path_suffix=path_suffix,
    )


def list_supported_providers(*, capability: str | None = None) -> list[dict[str, Any]]:
    from eeg.gateway.providers.catalog.registry import list_providers

    return list_providers(capability=capability)


def total_provider_count() -> int:
    return provider_count()


def normalize_vendor_response(plan: VendorPlan, raw: dict[str, Any], *, model: str = "") -> dict[str, Any]:
    if plan.response_shape == "anthropic_json":
        return normalize_anthropic_response(raw)
    if plan.response_shape == "bedrock_json":
        return normalize_bedrock_response(raw, model or plan.bedrock_model_id)
    if plan.response_shape == "bedrock_embed_json":
        vectors = raw.get("vectors") if isinstance(raw.get("vectors"), list) else []
        return normalize_bedrock_embed_response(vectors, model=model or plan.bedrock_model_id)
    if plan.response_shape == "bedrock_image_json":
        images = raw.get("images") if isinstance(raw.get("images"), list) else []
        return normalize_bedrock_image_response(images, model=model or plan.bedrock_model_id)
    if plan.response_shape == "vertex_json":
        return normalize_vertex_response(raw, model or plan.vertex_model)
    if plan.response_shape == "vertex_embed_json":
        return normalize_vertex_embed_response(raw, model=model or plan.vertex_model)
    if plan.response_shape == "vertex_image_json":
        return normalize_vertex_image_response(raw, model=model or plan.vertex_model)
    if plan.vendor_slug == "azure_foundry":
        return normalize_azure_foundry_response(raw)
    return normalize_openai_response(raw)
