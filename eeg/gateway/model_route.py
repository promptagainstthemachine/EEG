"""Resolve provider and model from the OpenAI-compatible ``model`` field.

Supports:
  - ``provider/model-name``  → explicit per-request provider
  - bare ``model-name``      → connector/default provider, model unchanged
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eeg.gateway.providers.catalog.registry import get_provider


@dataclass(frozen=True)
class ModelRoute:
    provider_id: str | None
    model_name: str
    raw: str
    explicit_provider: bool

    def apply_to_body(self, body: dict[str, Any]) -> dict[str, Any]:
        out = dict(body)
        out["model"] = self.model_name
        return out

    def apply_to_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if not self.explicit_provider or not self.provider_id:
            return config
        out = dict(config)
        out["provider"] = self.provider_id
        return out


def parse_model_route(raw: str | None) -> ModelRoute:
    """Parse ``model`` into an optional provider id and upstream model name."""
    text = (raw or "").strip()
    if not text:
        return ModelRoute(provider_id=None, model_name="", raw="", explicit_provider=False)

    if "/" not in text:
        return ModelRoute(provider_id=None, model_name=text, raw=text, explicit_provider=False)

    provider, model_name = text.split("/", 1)
    provider = provider.strip().lower()
    model_name = model_name.strip()
    if not provider or not model_name:
        raise ValueError(
            "Model must be 'provider/model' or a bare model name. "
            f"Got: {text!r}"
        )
    if get_provider(provider) is None:
        raise ValueError(
            f"Unknown gateway provider {provider!r} in model string. "
            "Use a catalog provider id or a bare model name."
        )
    return ModelRoute(
        provider_id=provider,
        model_name=model_name,
        raw=text,
        explicit_provider=True,
    )


def resolve_model_route(body: dict[str, Any]) -> tuple[dict[str, Any], ModelRoute]:
    """Return (body_with_bare_model, route). Raises ValueError on bad format."""
    route = parse_model_route(str(body.get("model") or ""))
    return route.apply_to_body(body), route
