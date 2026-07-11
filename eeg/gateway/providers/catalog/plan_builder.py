"""Build upstream dispatch plans from catalog providers."""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from eeg.gateway.providers.anthropic_vendor import compose_anthropic_plan
from eeg.gateway.providers.azure_foundry_vendor import compose_azure_foundry_plan
from eeg.gateway.providers.bedrock_vendor import compose_bedrock_plan
from eeg.gateway.providers.catalog.registry import get_provider, is_enterprise_provider, resolve_provider_id
from eeg.gateway.providers.catalog.types import CAPABILITY_PATHS, MULTIPART_CAPABILITIES, ProviderDefinition
from eeg.gateway.providers.openai_vendor import compose_openai_plan
from eeg.gateway.providers.types import VendorPlan
from eeg.gateway.providers.vertex_vendor import compose_vertex_plan


def _auth_headers(defn: ProviderDefinition, config: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    api_key = (config.get("api_key") or "").strip()
    if defn.auth_style == "none" or not api_key:
        return headers
    if defn.auth_style == "x-api-key":
        headers["x-api-key"] = api_key
        version = (config.get("anthropic_version") or "2023-06-01").strip()
        if defn.family == "anthropic":
            headers["anthropic-version"] = version
        return headers
    headers["Authorization"] = f"Bearer {api_key}"
    org = (config.get("organization") or "").strip()
    if org:
        headers["OpenAI-Organization"] = org
    project = (config.get("project") or "").strip()
    if project:
        headers["OpenAI-Project"] = project
    extra = config.get("extra_headers")
    if isinstance(extra, dict):
        for key, value in extra.items():
            if value is not None:
                headers[str(key)] = str(value)
    return headers


def _resolve_base_url(defn: ProviderDefinition, config: dict[str, Any]) -> str:
    override = (config.get("base_url") or "").strip()
    if override:
        return override.rstrip("/")
    template = defn.base_url
    if "{" in template:
        subs = {
            "resource": config.get("resource_name") or config.get("resource") or "",
            "deployment": config.get("deployment_id") or config.get("deployment") or "",
            "region": config.get("region") or "us-east-1",
            "endpoint": config.get("endpoint") or "",
            "account_id": config.get("account_id") or "",
            "cluster": config.get("cluster") or "",
            "model_id": config.get("model_id") or "",
        }
        try:
            return template.format(**subs).rstrip("/")
        except KeyError:
            return template.rstrip("/")
    return template.rstrip("/")


def _capability_path(capability: str, *, path_suffix: str = "") -> str:
    if path_suffix:
        return path_suffix if path_suffix.startswith("/") else f"/{path_suffix}"
    if capability == "mcp_toolsets":
        return CAPABILITY_PATHS["chat"]
    return CAPABILITY_PATHS.get(capability, f"/{capability}")


def compose_catalog_plan(
    config: dict[str, Any],
    body: dict[str, Any],
    *,
    capability: str = "chat",
    stream: bool = False,
    method: str = "POST",
    path_suffix: str = "",
) -> VendorPlan:
    explicit_provider = (config.get("provider") or "").strip().lower()
    backend = (config.get("backend") or "").strip().lower()

    provider_id = explicit_provider or resolve_provider_id(config)
    if (
        is_enterprise_provider(provider_id)
        or (not explicit_provider and backend in {"anthropic", "bedrock", "vertex", "azure_foundry"})
    ):
        return _compose_enterprise_plan(config, body, capability=capability, stream=stream)

    defn = get_provider(provider_id)
    if not defn:
        raise ValueError(f"Unknown gateway provider: {provider_id}")
    if not defn.supports(capability):
        raise ValueError(f"Provider '{provider_id}' does not support capability '{capability}'")

    if defn.family == "openai":
        return _compose_openai_family_plan(defn, config, body, capability=capability, stream=stream, method=method, path_suffix=path_suffix)
    if defn.family == "anthropic" and capability in {"chat", "mcp_toolsets"}:
        return compose_anthropic_plan(body, config, stream=stream)
    if defn.family == "cohere" and capability in {"chat", "embed", "mcp_toolsets"}:
        return _compose_cohere_plan(defn, config, body, capability=capability, stream=stream)

    raise ValueError(f"Capability '{capability}' is not implemented for provider family '{defn.family}'")


def _compose_enterprise_plan(
    config: dict[str, Any],
    body: dict[str, Any],
    *,
    capability: str,
    stream: bool,
) -> VendorPlan:
    backend = (config.get("backend") or resolve_provider_id(config)).strip().lower()
    if backend == "vertex-ai":
        backend = "vertex"
    if backend == "anthropic":
        if capability not in {"chat", "mcp_toolsets"}:
            raise ValueError(
                f"Enterprise backend 'anthropic' currently supports chat only "
                f"(got capability '{capability}')"
            )
        return compose_anthropic_plan(body, config, stream=stream)
    if backend == "bedrock":
        return compose_bedrock_plan(body, config, stream=stream, capability=capability)
    if backend == "vertex":
        return compose_vertex_plan(body, config, stream=stream, capability=capability)
    if backend == "azure_foundry":
        return compose_azure_foundry_plan(body, config, stream=stream, capability=capability)
    return compose_openai_plan(body, config, stream=stream)


def _compose_openai_family_plan(
    defn: ProviderDefinition,
    config: dict[str, Any],
    body: dict[str, Any],
    *,
    capability: str,
    stream: bool,
    method: str,
    path_suffix: str,
) -> VendorPlan:
    base = _resolve_base_url(defn, config)
    path = _capability_path(capability, path_suffix=path_suffix)
    url = urljoin(f"{base}/", path.lstrip("/"))
    headers = _auth_headers(defn, config)
    payload = dict(body) if body else {}
    stream_shape = "none"
    if capability in {"chat", "mcp_toolsets"} and stream:
        payload["stream"] = True
        headers["Accept"] = "text/event-stream"
        stream_shape = "openai_sse"
    if capability in MULTIPART_CAPABILITIES:
        headers.pop("Content-Type", None)
    return VendorPlan(
        vendor_slug=defn.id,
        transport="http",
        request_url=url,
        request_headers=headers,
        request_body=payload,
        response_shape="openai_json",
        stream_shape=stream_shape,
        capability=capability,
        http_method=method.upper(),
        multipart=capability in MULTIPART_CAPABILITIES,
    )


def _compose_cohere_plan(
    defn: ProviderDefinition,
    config: dict[str, Any],
    body: dict[str, Any],
    *,
    capability: str,
    stream: bool,
) -> VendorPlan:
    base = _resolve_base_url(defn, config)
    if capability == "embed":
        path = "/embed"
        payload = {
            "texts": body.get("input") if isinstance(body.get("input"), list) else [body.get("input", "")],
            "model": body.get("model", "embed-english-v3.0"),
        }
    else:
        path = "/chat"
        payload = {
            "model": body.get("model", "command-r"),
            "messages": body.get("messages") or [],
            "stream": bool(stream),
        }
    headers = _auth_headers(defn, config)
    if stream:
        headers["Accept"] = "text/event-stream"
    return VendorPlan(
        vendor_slug=defn.id,
        transport="http",
        request_url=f"{base}{path}",
        request_headers=headers,
        request_body=payload,
        response_shape="openai_json",
        stream_shape="openai_sse" if stream else "none",
        capability=capability,
        http_method="POST",
    )
