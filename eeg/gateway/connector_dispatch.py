"""Load AI gateway connector config and build vendor dispatch plans (OSS Django)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from eeg.gateway.model_route import ModelRoute, parse_model_route
from eeg.gateway.providers.types import VendorPlan
from eeg.gateway.providers.vendor_router import compose_vendor_plan


@dataclass
class ConnectorRecord:
    """Lightweight connector row compatible with gateway call sites."""

    id: int
    organization_id: int
    label: str
    status: str
    config: dict[str, Any]


def _env_connectors(organization_id: int) -> list[ConnectorRecord]:
    """Optional EEG_GATEWAY_CONNECTORS JSON list for headless / local use."""
    raw = (os.environ.get("EEG_GATEWAY_CONNECTORS") or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: list[ConnectorRecord] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        org = item.get("organization_id")
        if org is not None and int(org) != int(organization_id):
            continue
        cfg = item.get("config") if isinstance(item.get("config"), dict) else item
        out.append(
            ConnectorRecord(
                id=int(item.get("id") or idx + 1),
                organization_id=int(organization_id),
                label=str(item.get("label") or cfg.get("label") or f"connector-{idx + 1}"),
                status=str(item.get("status") or "active"),
                config=dict(cfg),
            )
        )
    return [c for c in out if c.status == "active"]


def _django_connectors(organization_id: int) -> list[ConnectorRecord]:
    try:
        from apps.accounts.models import GatewayConnector
    except Exception:
        return []
    rows = (
        GatewayConnector.objects.filter(
            organization_id=organization_id,
            status="active",
        )
        .order_by("-updated_at", "-id")
    )
    return [
        ConnectorRecord(
            id=row.id,
            organization_id=row.organization_id,
            label=row.label,
            status=row.status,
            config=dict(row.config or {}),
        )
        for row in rows
    ]


def get_org_ai_gateway_connectors(_db: Any, organization_id: int) -> list[ConnectorRecord]:
    django_rows = _django_connectors(organization_id)
    if django_rows:
        return django_rows
    return _env_connectors(organization_id)


def pick_ai_gateway_connector(
    db: Any,
    organization_id: int,
    *,
    label: str | None = None,
    preferred_provider: str | None = None,
) -> ConnectorRecord | None:
    rows = get_org_ai_gateway_connectors(db, organization_id)
    if not rows:
        return None
    if label:
        label = label.strip()
        for row in rows:
            if row.label == label:
                return row
        return None
    if preferred_provider:
        pref = preferred_provider.strip().lower()
        for row in rows:
            cfg = row.config
            row_provider = str(cfg.get("provider") or cfg.get("backend") or "").strip().lower()
            if row_provider == pref:
                return row
    for row in rows:
        if row.config.get("is_default"):
            return row
    return rows[0]


def load_ai_gateway_connector(
    db: Any,
    organization_id: int,
    connector_id: int,
) -> tuple[ConnectorRecord, dict[str, Any]]:
    rows = get_org_ai_gateway_connectors(db, organization_id)
    for row in rows:
        if row.id == int(connector_id):
            if row.status != "active":
                raise ValueError(f"AI gateway connector is not active ({row.status})")
            return row, dict(row.config)
    raise ValueError("AI gateway connector not found")


def resolve_ai_gateway_connector(
    db: Any,
    organization_id: int,
    *,
    connector_id: int | None = None,
    gateway_label: str | None = None,
    preferred_provider: str | None = None,
) -> tuple[ConnectorRecord, dict[str, Any]]:
    if connector_id is not None:
        return load_ai_gateway_connector(db, organization_id, connector_id)
    row = pick_ai_gateway_connector(
        db,
        organization_id,
        label=gateway_label,
        preferred_provider=preferred_provider,
    )
    if not row:
        raise ValueError(
            "No active AI gateway connector for this organization. "
            "Create a GatewayConnector or set EEG_GATEWAY_CONNECTORS, "
            "or use X-EEG-Provider / X-EEG-Provider-Key pass-through."
        )
    return row, dict(row.config)


def build_connector_vendor_plan(
    db: Any,
    organization_id: int,
    body: dict[str, Any],
    *,
    stream: bool,
    connector_id: int | None = None,
    gateway_label: str | None = None,
    capability: str = "chat",
    method: str = "POST",
    path_suffix: str = "",
    config_override: dict[str, Any] | None = None,
    model_route: ModelRoute | None = None,
) -> tuple[ConnectorRecord | None, VendorPlan, dict[str, Any], ModelRoute]:
    """
    Build a vendor plan.

    Returns (connector_row_or_none, plan, effective_config, model_route).
    ``config_override`` is used for pass-through BYOK (no connector row).
    """
    route = model_route or parse_model_route(str(body.get("model") or ""))
    routed_body = route.apply_to_body(body)

    if config_override is not None:
        config = route.apply_to_config(dict(config_override))
        plan = compose_vendor_plan(
            config,
            routed_body,
            stream=stream,
            capability=capability,
            method=method,
            path_suffix=path_suffix,
        )
        return None, plan, config, route

    row, config = resolve_ai_gateway_connector(
        db,
        organization_id,
        connector_id=connector_id,
        gateway_label=gateway_label,
        preferred_provider=route.provider_id,
    )
    config = route.apply_to_config(config)
    plan = compose_vendor_plan(
        config,
        routed_body,
        stream=stream,
        capability=capability,
        method=method,
        path_suffix=path_suffix,
    )
    return row, plan, config, route
