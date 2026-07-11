"""EEG OSS projects admin configuration."""
from django.contrib import admin

from .models import Project, ScanRun


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "project_type", "status", "auto_scan_enabled", "created_at")
    list_filter = ("status", "project_type", "auto_scan_enabled", "organization")
    search_fields = ("name", "slug", "repository_url")
    raw_id_fields = ("organization",)
    readonly_fields = ("created_at", "updated_at", "last_scan_at")


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("project", "scan_type", "status", "findings_count", "created_at")
    list_filter = ("status", "scan_type")
    search_fields = ("project__name",)
    raw_id_fields = ("project",)
    readonly_fields = ("created_at", "started_at", "completed_at")
