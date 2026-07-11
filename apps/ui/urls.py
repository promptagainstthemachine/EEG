"""EEG OSS UI URLs."""
from django.urls import include, path

from . import views

app_name = "ui"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path(
        "dashboard/set-project/",
        views.set_dashboard_project,
        name="set_dashboard_project",
    ),
    path("command-center/", views.security_command_center, name="command_center"),
    path("findings/", views.findings_explorer, name="findings_explorer"),
    path("findings/code/", views.findings_explorer, name="findings_code"),
    path("findings/runtime/", views.findings_runtime, name="findings_runtime"),
    path("traces/", views.traces_dashboard, name="traces_dashboard"),
    path("compliance/", views.compliance_dashboard, name="compliance"),
    path("agents/", views.agents_dashboard, name="agents"),
    path("agents/<uuid:agent_id>/control/", views.agent_control_action, name="agent_control"),
    path("threat-intel/", views.threat_intel, name="threat_intel"),
    path(
        "threat-intel/refresh/",
        views.refresh_threat_intel,
        name="refresh_threat_intel",
    ),
    path(
        "threat-intel/status/",
        views.threat_intel_scan_status,
        name="threat_intel_scan_status",
    ),
    path("threat-graph/", views.threat_graph, name="threat_graph"),
    path("threat-graph/code/", views.threat_graph, name="threat_graph_code"),
    path("threat-graph/runtime/", views.threat_graph_runtime, name="threat_graph_runtime"),
    # Legacy runtime inspector → compliance
    path("runtime/", views.compliance_dashboard, name="runtime_lattice"),
    path(
        "runtime/inspect/",
        views.runtime_lattice_inspect_gone,
        name="runtime_lattice_inspect",
    ),
    path(
        "runtime/conduit/",
        views.runtime_lattice_inspect_gone,
        name="runtime_conduit_check",
    ),
    
    # Project management
    path("projects/", include("apps.projects.urls", namespace="projects")),
    
    # Probe endpoints (HTMX) — scans run from each project page (Full Scan only)
    path("probes/redteam/", views.run_redteam, name="run_redteam"),
    path("probes/run/", views.run_probe, name="run_probe"),
    
    # HTMX partials
    path("partials/findings-feed/", views.findings_feed, name="findings_feed"),
    path("partials/vuln-feed/", views.vuln_feed, name="vuln_feed"),
    path(
        "partials/threat-graph/",
        views.threat_vulnerability_graph,
        name="threat_vulnerability_graph",
    ),
    path(
        "partials/dashboard-timeline/",
        views.dashboard_timeline,
        name="dashboard_timeline",
    ),
]
