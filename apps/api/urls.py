"""EEG OSS API URLs."""
from django.urls import path

from . import gateway_views, views

app_name = "api"

urlpatterns = [
    path("schema/", views.OpenApiSchemaView.as_view(), name="schema"),
    path("health/", views.HealthView.as_view(), name="health"),
    path("organization/", views.OrganizationView.as_view(), name="organization"),
    path("projects/", views.ProjectListView.as_view(), name="projects"),
    path("projects/<int:project_id>/", views.ProjectDetailView.as_view(), name="project_detail"),
    path(
        "projects/<int:project_id>/scans/",
        views.ProjectScansView.as_view(),
        name="project_scans",
    ),
    path("scan/types/", views.ScanTypesView.as_view(), name="scan_types"),
    path("scan/", views.ScanView.as_view(), name="scan"),
    path("probe/", views.ProbeView.as_view(), name="probe"),
    path("findings/", views.FindingsView.as_view(), name="findings"),
    path(
        "findings/<uuid:finding_id>/",
        views.FindingDetailView.as_view(),
        name="finding_detail",
    ),
    path("threatintel/", views.ThreatIntelView.as_view(), name="threat_intel"),
    path("traces/", views.TracesView.as_view(), name="traces"),
    path(
        "compliance/evaluate/",
        views.ComplianceEvaluateView.as_view(),
        name="compliance_evaluate",
    ),
    path(
        "compliance/posture/",
        views.CompliancePostureView.as_view(),
        name="compliance_posture",
    ),
    path(
        "compliance/audit/",
        views.ComplianceAuditView.as_view(),
        name="compliance_audit",
    ),
    path("agents/", views.AgentsView.as_view(), name="agents"),
    path(
        "agents/<uuid:agent_id>/control/",
        views.AgentControlView.as_view(),
        name="agent_control",
    ),
    path(
        "gateway/guard/",
        gateway_views.GatewayGuardView.as_view(),
        name="gateway_guard",
    ),
    path(
        "gateway/lattice/",
        gateway_views.GatewayLatticeView.as_view(),
        name="gateway_lattice",
    ),
    path(
        "gateway/lattice/packs/",
        gateway_views.GatewayLatticePacksView.as_view(),
        name="gateway_lattice_packs",
    ),
    path(
        "gateway/conduit/",
        gateway_views.GatewayConduitView.as_view(),
        name="gateway_conduit",
    ),
    path(
        "gateway/chat/completions/",
        gateway_views.GatewayChatCompletionsView.as_view(),
        name="gateway_chat_completions",
    ),
    path(
        "gateway/providers/",
        gateway_views.GatewayProvidersView.as_view(),
        name="gateway_providers",
    ),
    path(
        "gateway/embeddings/",
        gateway_views.GatewayEmbeddingsView.as_view(),
        name="gateway_embeddings",
    ),
    path(
        "gateway/images/generations/",
        gateway_views.GatewayImagesView.as_view(),
        name="gateway_images",
    ),
    path(
        "gateway/audio/speech/",
        gateway_views.GatewaySpeechView.as_view(),
        name="gateway_speech",
    ),
    path(
        "gateway/audio/transcriptions/",
        gateway_views.GatewayTranscriptionsView.as_view(),
        name="gateway_transcriptions",
    ),
]
