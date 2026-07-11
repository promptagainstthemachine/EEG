"""Provider catalog registry."""
from __future__ import annotations

from eeg.gateway.providers.catalog.definitions import (
    BACKEND_TO_PROVIDER,
    ENTERPRISE_PROVIDER_IDS,
    PROVIDER_BY_ID,
    PROVIDER_DEFINITIONS,
)
from eeg.gateway.providers.catalog.types import ProviderDefinition


def list_providers(*, capability: str | None = None) -> list[dict]:
    rows: list[dict] = []
    for item in PROVIDER_DEFINITIONS:
        if capability and not item.supports(capability):
            continue
        rows.append(provider_to_dict(item))
    return rows


def provider_to_dict(defn: ProviderDefinition) -> dict:
    return {
        "id": defn.id,
        "name": defn.name,
        "family": defn.family,
        "base_url": defn.base_url,
        "capabilities": sorted(defn.capabilities),
        "auth_style": defn.auth_style,
    }


def get_provider(provider_id: str) -> ProviderDefinition | None:
    return PROVIDER_BY_ID.get((provider_id or "").strip().lower())


def resolve_provider_id(config: dict) -> str:
    explicit = (config.get("provider") or "").strip().lower()
    if explicit:
        return explicit
    backend = (config.get("backend") or "openai").strip().lower()
    return BACKEND_TO_PROVIDER.get(backend, backend)


def is_enterprise_provider(provider_id: str) -> bool:
    return provider_id in ENTERPRISE_PROVIDER_IDS


def provider_count() -> int:
    return len(PROVIDER_DEFINITIONS)
