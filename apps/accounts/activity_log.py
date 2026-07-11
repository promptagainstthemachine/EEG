"""Record user-scoped activity for the Logs tab (audit trail)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from django.conf import settings
from django.http import HttpRequest

from apps.accounts.models import Organization, UserActivityLog


def _client_ip(request: Optional[HttpRequest]) -> Optional[str]:
    if not request:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()[:45] or None
    ip = request.META.get("REMOTE_ADDR")
    return ip[:45] if ip else None


def record_user_activity(
    *,
    user,
    organization: Optional[Organization] = None,
    event_type: str,
    metadata: Optional[Dict[str, Any]] = None,
    request: Optional[HttpRequest] = None,
) -> Optional[UserActivityLog]:
    """Persist one log row for the given user (log owner)."""
    if not user or not getattr(user, "pk", None):
        return None
    org = organization if organization is not None else getattr(user, "organization", None)
    meta = dict(metadata or {})
    return UserActivityLog.objects.create(
        user=user,
        organization=org if org and getattr(org, "pk", None) else None,
        event_type=event_type,
        actor_username=(getattr(user, "username", "") or "")[:150],
        metadata=meta,
        ip_address=_client_ip(request),
    )
