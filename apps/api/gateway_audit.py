"""Audit log entries for runtime gateway blocks."""

from __future__ import annotations

from typing import Any, Dict, Optional

from django.http import HttpRequest

from apps.accounts.activity_log import record_user_activity
from apps.accounts.models import Organization


def record_gateway_block(
    *,
    organization: Organization,
    request: HttpRequest,
    phase: str,
    reason: str,
    risk_score: float,
    risk_signals: list,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist a gateway policy block for the organization owner (audit trail)."""
    owner = getattr(organization, "owner", None)
    if not owner:
        return
    meta: Dict[str, Any] = {
        "phase": phase,
        "reason": reason[:500],
        "risk_score": risk_score,
        "signal_count": len(risk_signals or []),
        "path": request.path,
    }
    if extra:
        meta.update(extra)
    record_user_activity(
        user=owner,
        organization=organization,
        event_type="gateway_blocked",
        metadata=meta,
        request=request,
    )
