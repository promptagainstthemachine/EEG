"""
EEG OSS Account Models.

Simplified model:
- 1 User = 1 Organization (single-tenant per user)
- Unlimited projects per organization
- User manages their own organization settings
"""
import hashlib
import secrets
from typing import Optional

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class Organization(models.Model):
    """
    Organization for EEG OSS - each user owns exactly one organization.
    All security scans, projects, and findings are scoped to an organization.
    """

    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, max_length=80)
    created_at = models.DateTimeField(auto_now_add=True)

    auto_redteam_enabled = models.BooleanField(
        default=False,
        help_text="Enable automatic adversarial probes against your endpoints.",
    )
    model_scanning_enabled = models.BooleanField(
        default=True,
        help_text="Enable model artifact serialization scanning.",
    )
    realtime_telemetry_enabled = models.BooleanField(
        default=True,
        help_text="Enable real-time AI trace telemetry ingestion.",
    )
    realtime_monitoring_enabled = models.BooleanField(
        default=True,
        help_text="Enable real-time security monitoring.",
    )
    policy_enforcement_enabled = models.BooleanField(
        default=False,
        help_text="Enable automated policy enforcement and blocking.",
    )
    runtime_protection_enabled = models.BooleanField(
        default=False,
        help_text="Enable in-path EEG Gateway blocking and server-side trace scoring enforcement.",
    )
    runtime_policy_config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Workspace runtime policy (e.g. blocked_agent_keys).",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def project_count(self) -> int:
        return self.projects.count()

    def can_add_project(self) -> bool:
        """True when under the org project cap. EEG_MAX_PROJECTS_PER_ORG <= 0 means unlimited."""
        max_projects = int(getattr(settings, "EEG_MAX_PROJECTS_PER_ORG", 0) or 0)
        if max_projects <= 0:
            return True
        return self.project_count() < max_projects


class User(AbstractUser):
    """
    Custom user model for EEG OSS.
    Each user owns exactly one organization.
    """

    organization = models.OneToOneField(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owner",
    )
    dashboard_project = models.ForeignKey(
        "projects.Project",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dashboard_focus_users",
        help_text="Last project selected for the security dashboard.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"

    def __str__(self) -> str:
        return self.email or self.username

    def has_organization(self) -> bool:
        return self.organization is not None

    def get_organization(self) -> Optional[Organization]:
        return self.organization


def _hash_key(raw: str) -> str:
    pepper = settings.SECRET_KEY.encode("utf-8", errors="ignore")
    return hashlib.sha256(pepper + b"|" + raw.encode("utf-8")).hexdigest()


class ApiKey(models.Model):
    """
    API key for programmatic access to EEG OSS.
    Keys are scoped to an organization.
    """

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="api_keys"
    )
    label = models.CharField(max_length=120)
    prefix = models.CharField(max_length=16, editable=False)
    key_hash = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"

    def __str__(self) -> str:
        return f"{self.label} ({self.prefix}...)"

    @classmethod
    def create_key(cls, organization: Organization, label: str) -> tuple["ApiKey", str]:
        """Create a new API key. Returns (ApiKey, raw_key). Raw key is shown only once."""
        raw = f"eeg_oss_{secrets.token_urlsafe(32)}"
        prefix = raw[:14]
        obj = cls.objects.create(
            organization=organization,
            label=label,
            prefix=prefix,
            key_hash=_hash_key(raw),
        )
        return obj, raw

    def verify(self, raw_key: str) -> bool:
        return secrets.compare_digest(_hash_key(raw_key), self.key_hash)

    @staticmethod
    def resolve(raw_key: str) -> Optional["ApiKey"]:
        if not raw_key or not raw_key.startswith("eeg_oss_"):
            return None
        prefix = raw_key[:14]
        digest = _hash_key(raw_key)
        return (
            ApiKey.objects.select_related("organization")
            .filter(prefix=prefix, key_hash=digest, is_active=True)
            .first()
        )

    def touch_used(self) -> None:
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])

    def revoke(self) -> None:
        self.is_active = False
        self.save(update_fields=["is_active"])


class GatewayConnector(models.Model):
    """Stored AI gateway provider credentials for an organization (OSS BYOK connectors)."""

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="gateway_connectors",
    )
    label = models.CharField(max_length=120)
    status = models.CharField(max_length=32, default="active", db_index=True)
    config = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]
        verbose_name = "Gateway Connector"
        verbose_name_plural = "Gateway Connectors"

    def __str__(self) -> str:
        return f"{self.label} ({self.status})"


class UserActivityLog(models.Model):
    """
    Timeline of actions for a user account (OSS: one user ≈ one org owner).
    Used in Profile → Logs: sign-in/out, org creation, project add/delete, API keys, limit blocks.
    """

    class EventType(models.TextChoices):
        ORGANIZATION_CREATED = "organization_created", "Organization created"
        USER_REGISTERED = "user_registered", "Account registered"
        USER_LOGIN = "user_login", "Signed in"
        USER_LOGOUT = "user_logout", "Signed out"
        PROJECT_CREATED = "project_created", "Project added"
        PROJECT_DELETED = "project_deleted", "Project deleted"
        PROJECT_CREATE_BLOCKED = "project_create_blocked", "Project add blocked (limit)"
        API_KEY_CREATED = "api_key_created", "API key generated"
        API_KEY_REVOKED = "api_key_revoked", "API key revoked"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="activity_logs",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activity_logs",
    )
    event_type = models.CharField(
        max_length=64,
        choices=EventType.choices,
        db_index=True,
    )
    actor_username = models.CharField(max_length=150, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.get_event_type_display()} @ {self.created_at}"
