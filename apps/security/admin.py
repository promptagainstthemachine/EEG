"""EEG OSS security admin configuration."""
from django.contrib import admin

from .models import AITrace, SecurityFinding


@admin.register(SecurityFinding)
class SecurityFindingAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "severity", "status", "organization", "project", "first_seen_at")
    list_filter = ("severity", "status", "category", "source")
    search_fields = ("rule_id", "title", "file_path")
    raw_id_fields = ("organization", "project")
    readonly_fields = ("id", "first_seen_at", "last_seen_at", "created_at")


@admin.register(AITrace)
class AITraceAdmin(admin.ModelAdmin):
    list_display = ("trace_type", "trace_id", "provider", "model", "status", "risk_score", "started_at")
    list_filter = ("trace_type", "status", "provider")
    search_fields = ("trace_id", "session_id", "user_id")
    raw_id_fields = ("organization", "project")
    readonly_fields = ("id", "started_at", "completed_at", "created_at")
