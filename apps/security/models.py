"""
EEG OSS Security Models.

Models for security findings, traces, and monitoring data.
"""
import uuid

from django.db import models

from apps.accounts.models import Organization
from apps.projects.models import Project


class SecurityFinding(models.Model):
    """A security finding detected by EEG scanning or monitoring."""

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Info"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"
        IN_PROGRESS = "in_progress", "In Progress"
        RESOLVED = "resolved", "Resolved"
        FALSE_POSITIVE = "false_positive", "False Positive"
        DISMISSED = "dismissed", "Dismissed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="findings"
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True,
    )

    rule_id = models.CharField(max_length=128, db_index=True)
    title = models.CharField(max_length=512)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, db_index=True)
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.OPEN, db_index=True
    )

    source = models.CharField(max_length=64, blank=True, db_index=True)
    category = models.CharField(max_length=128, blank=True, db_index=True)
    subcategory = models.CharField(max_length=128, blank=True)

    file_path = models.CharField(max_length=1024, blank=True)
    line_number = models.IntegerField(null=True, blank=True)
    code_snippet = models.TextField(blank=True)

    recommendation = models.TextField(blank=True)
    cwe = models.CharField(max_length=32, blank=True)
    owasp_llm = models.CharField(max_length=32, blank=True)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)

    metadata = models.JSONField(default=dict, blank=True)

    fingerprint = models.CharField(max_length=64, blank=True, db_index=True)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-first_seen_at"]
        indexes = [
            models.Index(fields=["organization", "severity"]),
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "category"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "project", "fingerprint"],
                name="uniq_security_finding_per_project",
            ),
        ]

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.rule_id}: {self.title[:50]}"


class AITrace(models.Model):
    """
    AI trace/span for LLM and agent observability.
    Records LLM calls, tool invocations, and agent actions.
    """

    class TraceType(models.TextChoices):
        LLM_CALL = "llm_call", "Prompt"
        TOOL_CALL = "tool_call", "Tool Call"
        AGENT_ACTION = "agent_action", "Agent Action"
        RETRIEVAL = "retrieval", "RAG"
        EMBEDDING = "embedding", "Embedding"
        MCP_TOOL = "mcp_tool", "MCP"
        AGENT_CONTROL = "agent_control", "Agent Control"

    class Status(models.TextChoices):
        SUCCESS = "success", "Success"
        ERROR = "error", "Error"
        BLOCKED = "blocked", "Blocked"
        TIMEOUT = "timeout", "Timeout"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="traces"
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="traces",
        null=True,
        blank=True,
    )

    trace_id = models.CharField(max_length=128, db_index=True)
    parent_span_id = models.CharField(max_length=128, blank=True)
    span_id = models.CharField(max_length=128)

    trace_type = models.CharField(max_length=32, choices=TraceType.choices)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.SUCCESS)

    provider = models.CharField(max_length=64, blank=True)
    model = models.CharField(max_length=128, blank=True)
    session_id = models.CharField(max_length=128, blank=True, db_index=True)
    user_id = models.CharField(max_length=128, blank=True, db_index=True)

    input_text = models.TextField(blank=True)
    output_text = models.TextField(blank=True)
    input_tokens = models.IntegerField(default=0)
    output_tokens = models.IntegerField(default=0)

    latency_ms = models.IntegerField(default=0)
    cost_usd = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)

    risk_score = models.FloatField(default=0.0)
    risk_signals = models.JSONField(default=list, blank=True)

    metadata = models.JSONField(default=dict, blank=True)

    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["organization", "trace_type"]),
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["trace_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.trace_type} ({self.trace_id[:8]}...)"


class ManagedAgent(models.Model):
    """Runtime-managed agent identity with pause / start / quarantine controls."""

    class ControlStatus(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        QUARANTINED = "quarantined", "Quarantined"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="managed_agents"
    )
    agent_key = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    control_status = models.CharField(
        max_length=32,
        choices=ControlStatus.choices,
        default=ControlStatus.ACTIVE,
        db_index=True,
    )
    framework = models.CharField(max_length=128, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_control_action = models.CharField(max_length=32, blank=True)
    last_control_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        unique_together = [("organization", "agent_key")]
        indexes = [
            models.Index(fields=["organization", "control_status"]),
        ]

    def __str__(self) -> str:
        return f"{self.name or self.agent_key} ({self.control_status})"
