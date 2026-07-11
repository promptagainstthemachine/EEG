"""
EEG OSS Project Models.

Projects represent AI applications, services, repositories, or gateway-connected apps.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.accounts.models import Organization


class Project(models.Model):
    """
    An AI project/service being monitored by EEG OSS.
    Can be a GitHub repo, cloud AI service, local app, or gateway-connected app.
    """

    class ProjectType(models.TextChoices):
        REPOSITORY = "repository", "Code Repository"
        AWS = "aws", "AWS AI Service"
        GCP = "gcp", "GCP AI Service"
        AZURE = "azure", "Azure AI Service"
        LOCAL = "local", "Local Application"
        API_ENDPOINT = "api_endpoint", "API Endpoint"
        GATEWAY = "gateway", "Gateway App"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        ERROR = "error", "Error"

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="projects"
    )
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=80)
    description = models.TextField(blank=True)
    project_type = models.CharField(
        max_length=32, choices=ProjectType.choices, default=ProjectType.REPOSITORY
    )
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.ACTIVE
    )

    repository_url = models.URLField(blank=True, help_text="GitHub/GitLab repository URL")
    cloud_resource_id = models.CharField(
        max_length=512, blank=True, help_text="Cloud resource identifier"
    )
    api_endpoint = models.URLField(blank=True, help_text="API endpoint URL for monitoring")
    local_path = models.CharField(
        max_length=1024, blank=True, help_text="Local filesystem path"
    )
    gateway_agent_key = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
        help_text="Agent key when this project is a gateway-connected app",
    )

    auto_scan_enabled = models.BooleanField(
        default=True, help_text="Enable automatic security scanning"
    )
    scan_schedule = models.CharField(
        max_length=64,
        default="0 */6 * * *",
        help_text="Cron expression for scheduled scans",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scan_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "slug"], name="unique_project_slug_per_org"
            ),
            models.UniqueConstraint(
                fields=["organization", "gateway_agent_key"],
                condition=models.Q(gateway_agent_key__gt=""),
                name="unique_gateway_agent_key_per_org",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.organization.name})"

    @property
    def is_gateway_app(self) -> bool:
        return bool(self.gateway_agent_key) or self.project_type == self.ProjectType.GATEWAY

    def is_gateway_connected(self) -> bool:
        """True when the linked gateway agent was seen within the configured window."""
        if not self.gateway_agent_key:
            return False
        from apps.security.models import ManagedAgent

        agent = (
            ManagedAgent.objects.filter(
                organization_id=self.organization_id,
                agent_key=self.gateway_agent_key,
            )
            .only("last_seen_at")
            .first()
        )
        if not agent or not agent.last_seen_at:
            return False
        window = int(getattr(settings, "EEG_GATEWAY_CONNECTED_WINDOW_SECONDS", 900))
        return agent.last_seen_at >= timezone.now() - timedelta(seconds=window)

    @property
    def connection_status(self) -> str:
        """UI status: connected/disconnected for gateway apps, else project status."""
        if self.is_gateway_app:
            return "connected" if self.is_gateway_connected() else "disconnected"
        return self.status

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)


class ScanRun(models.Model):
    """Record of a security scan execution against a project."""

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    class ScanType(models.TextChoices):
        CODE_SECURITY = "code_security", "Code Security"
        MODEL_ARTIFACT = "model_artifact", "Model Artifact"
        DEPENDENCY = "dependency", "Dependency Audit"
        REDTEAM = "redteam", "Red Team"
        AGENT_FORENSICS = "agent_forensics", "Agent Forensics"
        FULL = "full", "Full Security Scan"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="scan_runs")
    scan_type = models.CharField(max_length=32, choices=ScanType.choices)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    findings_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)

    result_summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.scan_type} scan for {self.project.name} ({self.status})"
