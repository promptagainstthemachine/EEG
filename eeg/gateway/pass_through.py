"""Pass-through provider selection for BYOK-style gateway calls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from eeg.gateway.providers.catalog.registry import get_provider, is_enterprise_provider
from eeg.gateway.providers.types import VendorPlan


@dataclass(frozen=True)
class PassThroughAuth:
    provider_id: str
    api_key: str
    base_url: str | None = None
    extra_config: dict[str, Any] | None = None


def parse_pass_through(
    *,
    provider_header: str | None,
    api_key_header: str | None,
    upstream_url: str | None = None,
    upstream_authorization: str | None = None,
    provider_config_header: str | None = None,
) -> PassThroughAuth | None:
    """
    Resolve optional per-request provider credentials.

    Preferred: X-EEG-Provider + X-EEG-Provider-Key
    Also accepts X-EEG-Upstream-Authorization as Bearer token when provider is set.
    Optional X-EEG-Provider-Config: JSON object with enterprise fields
    (region, project_id, deployment_id, role_arn, credentials_path, ...).
    """
    provider = (provider_header or "").strip().lower()
    if not provider:
        return None
    if get_provider(provider) is None:
        raise ValueError(f"Unknown pass-through provider: {provider}")

    key = (api_key_header or "").strip()
    if not key and upstream_authorization:
        auth = upstream_authorization.strip()
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
        else:
            key = auth
    if not key and not is_enterprise_provider(provider):
        raise ValueError(
            "Pass-through provider requires X-EEG-Provider-Key "
            "(or X-EEG-Upstream-Authorization)."
        )

    extra: dict[str, Any] = {}
    raw_cfg = (provider_config_header or "").strip()
    if raw_cfg:
        try:
            parsed = json.loads(raw_cfg)
        except json.JSONDecodeError as exc:
            raise ValueError("X-EEG-Provider-Config must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("X-EEG-Provider-Config must be a JSON object")
        extra = parsed

    return PassThroughAuth(
        provider_id=provider,
        api_key=key,
        base_url=(upstream_url or "").strip() or None,
        extra_config=extra or None,
    )


def build_pass_through_config(auth: PassThroughAuth) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "provider": auth.provider_id,
        "backend": auth.provider_id if is_enterprise_provider(auth.provider_id) else auth.provider_id,
        "api_key": auth.api_key,
        "pass_through": True,
    }
    if auth.base_url:
        cfg["base_url"] = auth.base_url.rstrip("/")
        cfg["endpoint"] = auth.base_url.rstrip("/")

    if auth.extra_config:
        for key, value in auth.extra_config.items():
            if value is not None and key not in {"api_key", "pass_through"}:
                cfg[key] = value

    # Enterprise credential mapping from the single Provider-Key header.
    if auth.provider_id == "bedrock" and auth.api_key:
        if ":" in auth.api_key and not cfg.get("access_key_id"):
            access, secret = auth.api_key.split(":", 1)
            cfg["access_key_id"] = access.strip()
            cfg["secret_access_key"] = secret.strip()
        elif not cfg.get("access_key_id") and not cfg.get("role_arn"):
            cfg["access_key_id"] = auth.api_key
    if auth.provider_id in {"vertex", "vertex-ai"} and auth.api_key:
        if auth.api_key.strip().startswith("{"):
            cfg["service_account_json"] = auth.api_key
        else:
            cfg["access_token"] = auth.api_key
    if auth.provider_id == "azure_foundry":
        if auth.api_key:
            cfg["api_key"] = auth.api_key
        if auth.base_url and not cfg.get("resource_name"):
            cfg["endpoint"] = auth.base_url.rstrip("/")

    return cfg


def build_pass_through_plan(
    auth: PassThroughAuth,
    body: dict[str, Any],
    *,
    capability: str = "chat",
    stream: bool = False,
) -> VendorPlan:
    """Compose a VendorPlan from pass-through credentials (no org connector)."""
    from eeg.gateway.providers.catalog.plan_builder import compose_catalog_plan

    config = build_pass_through_config(auth)
    return compose_catalog_plan(
        config,
        body,
        capability=capability,
        stream=stream,
    )
