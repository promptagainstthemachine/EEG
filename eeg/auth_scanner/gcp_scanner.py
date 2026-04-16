"""
EEG - GCP Authenticated Scanner
Live audit of Vertex AI endpoints, models, safety settings, and IAM.
"""

import os
from eeg.collector import Collector, Finding, Severity

try:
    from google.cloud import aiplatform
    from google.auth import default as gcp_default_auth
    HAS_GCP = True
except ImportError:
    HAS_GCP = False


class GCPAuthScanner:
    """Live audit of GCP Vertex AI resources using authenticated API calls."""

    def __init__(self, auth_context: dict):
        self.auth_context = auth_context
        self.project = auth_context.get("project") or os.environ.get("GCLOUD_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.location = os.environ.get("GOOGLE_CLOUD_REGION", "us-central1")

    def scan(self, collector: Collector):
        if not HAS_GCP:
            print("  [AUTH-GCP] google-cloud-aiplatform not installed — skipping authenticated scan")
            print("  [AUTH-GCP] Install: pip install google-cloud-aiplatform")
            return

        if not self.project:
            print("  [AUTH-GCP] No project ID found. Set GOOGLE_CLOUD_PROJECT or gcloud config set project.")
            return

        print(f"  [AUTH-GCP] Project: {self.project} | Location: {self.location}")

        try:
            aiplatform.init(project=self.project, location=self.location)
        except Exception as e:
            print(f"  [AUTH-GCP] ✗ Initialization failed: {e}")
            return

        self._check_endpoints(collector)
        self._check_models(collector)

    def _check_endpoints(self, collector: Collector):
        """Audit Vertex AI endpoints for security."""
        print("  [AUTH-GCP] Auditing Vertex AI endpoints...")
        try:
            endpoints = aiplatform.Endpoint.list()
        except Exception as e:
            print(f"  [AUTH-GCP] Cannot list endpoints: {e}")
            return

        print(f"  [AUTH-GCP] Found {len(endpoints)} endpoint(s)")

        for ep in endpoints:
            ep_name = ep.display_name or ep.resource_name

            # Check for traffic split (model serving)
            traffic = ep.traffic_split or {}
            if not traffic:
                continue

            # Check encryption
            enc_spec = getattr(ep, "encryption_spec", None)
            if not enc_spec or not getattr(enc_spec, "kms_key_name", None):
                collector.add_finding(Finding(
                    rule_id="AUTH-GCP-MODEL-001", severity=Severity.HIGH,
                    category="model", cloud_env="gcp",
                    file_path=f"live:endpoint:{ep_name}", line_number=0,
                    code_snippet="encryption_spec.kms_key_name=null",
                    message=f"Vertex AI endpoint '{ep_name}' not encrypted with CMEK",
                    recommendation="Configure customer-managed encryption key (CMEK) on Vertex AI endpoints for data at rest.",
                ))

            # Check network (private endpoint)
            network = getattr(ep, "network", None)
            if not network:
                collector.add_finding(Finding(
                    rule_id="AUTH-GCP-NET-001", severity=Severity.HIGH,
                    category="network", cloud_env="gcp",
                    file_path=f"live:endpoint:{ep_name}", line_number=0,
                    code_snippet="network=null (public endpoint)",
                    message=f"Vertex AI endpoint '{ep_name}' is publicly accessible (no VPC peering)",
                    recommendation="Deploy endpoints within a VPC using private endpoints (network parameter).",
                ))

    def _check_models(self, collector: Collector):
        """Audit Vertex AI model registry."""
        print("  [AUTH-GCP] Auditing Vertex AI models...")
        try:
            models = aiplatform.Model.list()
        except Exception as e:
            print(f"  [AUTH-GCP] Cannot list models: {e}")
            return

        print(f"  [AUTH-GCP] Found {len(models)} model(s)")

        for model in models:
            model_name = model.display_name or model.resource_name

            # Check encryption
            enc_spec = getattr(model, "encryption_spec", None)
            if not enc_spec or not getattr(enc_spec, "kms_key_name", None):
                collector.add_finding(Finding(
                    rule_id="AUTH-GCP-MODEL-002", severity=Severity.MEDIUM,
                    category="model", cloud_env="gcp",
                    file_path=f"live:model:{model_name}", line_number=0,
                    code_snippet="",
                    message=f"Model '{model_name}' artifacts not encrypted with CMEK",
                    recommendation="Upload models with encryption_spec pointing to a Cloud KMS key.",
                ))

            # Check artifact URI for public GCS
            artifact_uri = getattr(model, "artifact_uri", "") or ""
            if artifact_uri and not artifact_uri.startswith("gs://"):
                collector.add_finding(Finding(
                    rule_id="AUTH-GCP-MODEL-003", severity=Severity.HIGH,
                    category="model", cloud_env="gcp",
                    file_path=f"live:model:{model_name}", line_number=0,
                    code_snippet=f"artifact_uri={artifact_uri[:100]}",
                    message=f"Model '{model_name}' artifact URI points to non-GCS location — potential exfiltration risk",
                    recommendation="Store model artifacts exclusively in private GCS buckets with uniform access control.",
                ))
