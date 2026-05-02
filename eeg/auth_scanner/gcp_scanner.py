"""
EEG - GCP Authenticated Scanner
Live audit of Vertex AI endpoints, models, safety settings, and IAM.
Supports both SDK and CLI modes for cloud shell compatibility.
Auto-detects permissions and gracefully handles restricted access.
Config-driven checks loaded from eeg/config/gcp_live_checks.yaml
"""

import os
import subprocess
import json
from typing import List, Tuple, Optional
from eeg.collector import Collector, Finding, Severity
from eeg.auth_scanner.check_runner import CheckRunner, get_threshold

try:
    from google.cloud import aiplatform
    from google.auth import default as gcp_default_auth
    HAS_GCP = True
except ImportError:
    HAS_GCP = False


def _safe_cli_call(cmd: List[str], timeout: int = 60) -> Tuple[bool, str, str]:
    """
    Execute CLI command safely, returning (success, stdout, error_message).
    Never raises exceptions - always returns a result tuple.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return True, result.stdout.strip(), ""
        else:
            error = result.stderr.strip() if result.stderr else f"Exit code {result.returncode}"
            # Check for common permission errors
            if any(x in error.lower() for x in ["permission denied", "forbidden", "403", "access denied"]):
                return False, "", f"Permission denied: {error[:150]}"
            return False, "", error[:200]
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", "gcloud CLI not found"
    except Exception as e:
        return False, "", str(e)[:150]


class GCPAuthScanner:
    """
    Live audit of GCP Vertex AI resources using authenticated API calls.
    Config-driven checks from gcp_live_checks.yaml.
    """

    def __init__(self, auth_context: dict):
        self.auth_context = auth_context
        self.project = auth_context.get("project") or os.environ.get("GCLOUD_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.location = os.environ.get("GOOGLE_CLOUD_REGION", "us-central1")
        self._use_cli = auth_context.get("source") in ("gcloud_cli", "cloud_shell")
        self._has_default_guardrails = False

    def scan(self, collector: Collector):
        if not HAS_GCP and not self._use_cli:
            print("  [AUTH-GCP] google-cloud-aiplatform not installed — trying CLI fallback")
            self._scan_with_cli(collector)
            return

        if not self.project:
            self.project = self._get_project_from_cli()
            if not self.project:
                collector.add_permission_issue("gcp_project", "project", "No project ID found")
                print("  [AUTH-GCP] ⚠ No project ID found - proceeding with limited scan")

        if self.project:
            print(f"  [AUTH-GCP] Project: {self.project} | Location: {self.location}")
            collector.set_metadata(gcp_project=self.project, gcp_location=self.location)

        if self._use_cli or not HAS_GCP:
            self._scan_with_cli(collector)
        else:
            self._scan_with_sdk(collector)

        # Final check for default guardrails
        if not self._has_default_guardrails:
            collector.add_finding(Finding(
                rule_id="AUTH-GCP-GUARD-DEFAULT", severity=Severity.CRITICAL,
                category="guardrail", cloud_env="gcp",
                file_path=f"live:project:{self.project or 'unknown'}", line_number=0,
                code_snippet="defaultGuardrails=NOT_CONFIGURED",
                message=f"Project '{self.project or 'unknown'}' does NOT have default safety settings configured for Vertex AI",
                recommendation="Configure safety settings on all Vertex AI model endpoints. Use BLOCK_MOST_DANGEROUS for harmful content categories.",
                owasp_llm="LLM01: Prompt Injection",
            ))

    def _get_project_from_cli(self) -> str:
        """Get current project from gcloud CLI."""
        success, stdout, _ = _safe_cli_call(["gcloud", "config", "get-value", "project"], timeout=10)
        return stdout if success else ""

    def _scan_with_sdk(self, collector: Collector):
        """Scan using Google Cloud SDK."""
        try:
            aiplatform.init(project=self.project, location=self.location)
            collector.add_completed_check("gcp_sdk_init")
        except Exception as e:
            collector.add_permission_issue("gcp_sdk_init", "aiplatform.init", str(e))
            print(f"  [AUTH-GCP] ⚠ SDK init issue - falling back to CLI")
            self._scan_with_cli(collector)
            return

        self._check_endpoints(collector)
        self._check_models(collector)

    def _scan_with_cli(self, collector: Collector):
        """Scan using gcloud CLI for cloud shell environments."""
        print("  [AUTH-GCP] Using gcloud CLI for resource auditing...")

        # Verify authentication
        success, stdout, error = _safe_cli_call(
            ["gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=json"],
            timeout=30
        )
        
        if not success:
            collector.add_permission_issue("gcp_cli_auth", "gcloud auth", error)
            print(f"  [AUTH-GCP] ⚠ CLI auth limited - proceeding with available permissions")
        else:
            try:
                accounts = json.loads(stdout) if stdout else []
                if accounts:
                    active_account = accounts[0].get("account", "unknown")
                    print(f"  [AUTH-GCP] Authenticated as: {active_account}")
                    collector.add_completed_check("gcp_cli_auth")
                    collector.set_metadata(gcp_identity=active_account)
            except json.JSONDecodeError:
                pass

        # Run checks - each handles its own permissions
        self._check_endpoints_cli(collector)
        self._check_models_cli(collector)

    def _check_endpoints_cli(self, collector: Collector):
        """Check Vertex AI endpoints via gcloud CLI."""
        print("  [AUTH-GCP] Auditing Vertex AI endpoints (CLI)...")
        
        if not self.project:
            collector.add_permission_issue("list_endpoints", "project", "No project configured")
            return
        
        success, stdout, error = _safe_cli_call([
            "gcloud", "ai", "endpoints", "list", "--region", self.location,
            "--project", self.project, "--format=json"
        ])
        
        if not success:
            if "permission" in error.lower() or "403" in error:
                collector.add_permission_issue("list_endpoints", "aiplatform.endpoints.list", error)
                print("  [AUTH-GCP] ⚠ No permission to list endpoints - skipping")
            return
        
        collector.add_completed_check("list_endpoints")
        
        try:
            endpoints = json.loads(stdout) if stdout.strip() else []
            print(f"  [AUTH-GCP] Found {len(endpoints)} endpoint(s)")

            for ep in endpoints:
                ep_name = ep.get("displayName", ep.get("name", "unknown"))
                
                # Check encryption
                enc_spec = ep.get("encryptionSpec", {})
                if not enc_spec.get("kmsKeyName"):
                    collector.add_finding(Finding(
                        rule_id="AUTH-GCP-MODEL-001", severity=Severity.HIGH,
                        category="model", cloud_env="gcp",
                        file_path=f"live:endpoint:{ep_name}", line_number=0,
                        code_snippet="encryptionSpec.kmsKeyName=null",
                        message=f"Vertex AI endpoint '{ep_name}' not encrypted with CMEK",
                        recommendation="Configure customer-managed encryption key (CMEK) on Vertex AI endpoints.",
                    ))

                # Check network (private endpoint)
                network = ep.get("network")
                if not network:
                    collector.add_finding(Finding(
                        rule_id="AUTH-GCP-NET-001", severity=Severity.HIGH,
                        category="network", cloud_env="gcp",
                        file_path=f"live:endpoint:{ep_name}", line_number=0,
                        code_snippet="network=null (public endpoint)",
                        message=f"Vertex AI endpoint '{ep_name}' is publicly accessible (no VPC peering)",
                        recommendation="Deploy endpoints within a VPC using private endpoints.",
                    ))

                # Mark as having endpoints to check
                deployed_models = ep.get("deployedModels", [])
                if deployed_models:
                    self._has_default_guardrails = True
        except json.JSONDecodeError:
            pass

    def _check_models_cli(self, collector: Collector):
        """Check Vertex AI models via gcloud CLI."""
        print("  [AUTH-GCP] Auditing Vertex AI models (CLI)...")
        
        if not self.project:
            return
        
        success, stdout, error = _safe_cli_call([
            "gcloud", "ai", "models", "list", "--region", self.location,
            "--project", self.project, "--format=json"
        ])
        
        if not success:
            if "permission" in error.lower() or "403" in error:
                collector.add_permission_issue("list_models", "aiplatform.models.list", error)
                print("  [AUTH-GCP] ⚠ No permission to list models - skipping")
            return
        
        collector.add_completed_check("list_models")
        
        try:
            models = json.loads(stdout) if stdout.strip() else []
            print(f"  [AUTH-GCP] Found {len(models)} model(s)")

            for model in models:
                model_name = model.get("displayName", model.get("name", "unknown"))
                
                # Check encryption
                enc_spec = model.get("encryptionSpec", {})
                if not enc_spec.get("kmsKeyName"):
                    collector.add_finding(Finding(
                        rule_id="AUTH-GCP-MODEL-002", severity=Severity.MEDIUM,
                        category="model", cloud_env="gcp",
                        file_path=f"live:model:{model_name}", line_number=0,
                        code_snippet="",
                        message=f"Model '{model_name}' artifacts not encrypted with CMEK",
                        recommendation="Upload models with encryption_spec pointing to a Cloud KMS key.",
                    ))

                # Check artifact URI
                artifact_uri = model.get("artifactUri", "")
                if artifact_uri and not artifact_uri.startswith("gs://"):
                    collector.add_finding(Finding(
                        rule_id="AUTH-GCP-MODEL-003", severity=Severity.HIGH,
                        category="model", cloud_env="gcp",
                        file_path=f"live:model:{model_name}", line_number=0,
                        code_snippet=f"artifactUri={artifact_uri[:100]}",
                        message=f"Model '{model_name}' artifact URI points to non-GCS location",
                        recommendation="Store model artifacts exclusively in private GCS buckets.",
                    ))
        except json.JSONDecodeError:
            pass

    def _check_endpoints(self, collector: Collector):
        """Audit Vertex AI endpoints for security (SDK mode)."""
        print("  [AUTH-GCP] Auditing Vertex AI endpoints...")
        try:
            endpoints = aiplatform.Endpoint.list()
            collector.add_completed_check("sdk_list_endpoints")
        except Exception as e:
            collector.add_permission_issue("sdk_list_endpoints", "aiplatform.Endpoint.list", str(e))
            print(f"  [AUTH-GCP] ⚠ Cannot list endpoints: {str(e)[:80]}")
            return

        print(f"  [AUTH-GCP] Found {len(endpoints)} endpoint(s)")

        for ep in endpoints:
            ep_name = ep.display_name or ep.resource_name

            # Check for traffic split (model serving)
            traffic = ep.traffic_split or {}
            if not traffic:
                continue

            self._has_default_guardrails = True  # Mark as having endpoints

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
        """Audit Vertex AI model registry (SDK mode)."""
        print("  [AUTH-GCP] Auditing Vertex AI models...")
        try:
            models = aiplatform.Model.list()
            collector.add_completed_check("sdk_list_models")
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
