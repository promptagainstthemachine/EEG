"""
EEG - Azure Authenticated Scanner
Live audit of Azure OpenAI, AI Foundry, AI Search, and related services.
"""

import os
from typing import Optional
from eeg.collector import Collector, Finding, Severity

try:
    from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
    from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


class AzureAuthScanner:
    """Live audit of Azure AI resources using authenticated API calls."""

    def __init__(self, auth_context: dict):
        self.auth_context = auth_context
        self.subscription_id = auth_context.get("subscription") or os.environ.get("AZURE_SUBSCRIPTION_ID")
        self.tenant = auth_context.get("tenant")

    def scan(self, collector: Collector):
        if not HAS_AZURE:
            print("  [AUTH-AZ] azure-identity/azure-mgmt not installed — skipping authenticated scan")
            print("  [AUTH-AZ] Install: pip install azure-identity azure-mgmt-cognitiveservices azure-mgmt-resource")
            return

        if not self.subscription_id:
            print("  [AUTH-AZ] No subscription ID found. Set AZURE_SUBSCRIPTION_ID or authenticate with az login.")
            return

        print(f"  [AUTH-AZ] Subscription: {self.subscription_id}")

        try:
            credential = DefaultAzureCredential()
            cog_client = CognitiveServicesManagementClient(credential, self.subscription_id)
        except Exception as e:
            print(f"  [AUTH-AZ] ✗ Authentication failed: {e}")
            return

        self._check_cognitive_accounts(cog_client, collector)

    def _check_cognitive_accounts(self, cog_client, collector: Collector):
        """Audit all Cognitive Services accounts (Azure OpenAI, AI Services)."""
        print("  [AUTH-AZ] Auditing Cognitive Services accounts...")

        try:
            accounts = list(cog_client.accounts.list())
        except Exception as e:
            print(f"  [AUTH-AZ] Cannot list accounts: {e}")
            return

        ai_accounts = [a for a in accounts if a.kind in ("OpenAI", "AIServices", "CognitiveServices")]
        print(f"  [AUTH-AZ] Found {len(ai_accounts)} AI service account(s)")

        for account in ai_accounts:
            name = account.name
            rg = account.id.split("/")[4] if account.id else "unknown"
            props = account.properties or {}

            # Public network access
            public_access = props.public_network_access or "Enabled"
            if public_access == "Enabled":
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-NET-001", severity=Severity.HIGH,
                    category="network", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet=f"publicNetworkAccess={public_access}",
                    message=f"Azure AI account '{name}' has public network access enabled",
                    recommendation="Disable public network access. Use private endpoints for all AI service connections.",
                ))

            # Local auth (API key) enabled
            disable_local_auth = props.disable_local_auth
            if not disable_local_auth:
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-IAM-001", severity=Severity.HIGH,
                    category="iam", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet=f"disableLocalAuth={disable_local_auth}",
                    message=f"Azure AI account '{name}' allows API key authentication (local auth enabled)",
                    recommendation="Set disableLocalAuth=true. Use Managed Identity (Azure AD) for authentication instead of API keys.",
                ))

            # Encryption — customer managed key
            encryption = account.properties.encryption if hasattr(account.properties, 'encryption') else None
            if not encryption or not getattr(encryption, 'key_vault_properties', None):
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-MODEL-001", severity=Severity.MEDIUM,
                    category="model", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet="encryption=Microsoft-managed",
                    message=f"Azure AI account '{name}' uses Microsoft-managed keys (no CMK)",
                    recommendation="Configure customer-managed encryption keys (CMK) via Azure Key Vault for sensitive AI workloads.",
                ))

            # Network ACLs
            network_acls = props.network_acls
            if network_acls:
                default_action = getattr(network_acls, 'default_action', 'Allow')
                if default_action == "Allow":
                    collector.add_finding(Finding(
                        rule_id="AUTH-AZ-POL-001", severity=Severity.HIGH,
                        category="policy", cloud_env="azure",
                        file_path=f"live:cognitive:{name}", line_number=0,
                        code_snippet=f"networkAcls.defaultAction={default_action}",
                        message=f"Azure AI account '{name}' network ACLs default to Allow",
                        recommendation="Set network ACLs defaultAction to Deny. Whitelist specific IPs and VNet subnets.",
                    ))

            # Check deployments for content filter configuration
            try:
                deployments = list(cog_client.deployments.list(rg, name))
                for dep in deployments:
                    dep_name = dep.name
                    dep_props = dep.properties or {}
                    # Content filter presence
                    rai_policy = getattr(dep_props, 'rai_policy_name', None) or getattr(dep_props, 'content_filter', None)
                    if not rai_policy:
                        collector.add_finding(Finding(
                            rule_id="AUTH-AZ-GUARD-001", severity=Severity.CRITICAL,
                            category="guardrail", cloud_env="azure",
                            file_path=f"live:deployment:{name}/{dep_name}", line_number=0,
                            code_snippet="raiPolicyName=null",
                            message=f"Deployment '{dep_name}' on '{name}' has no content filter / RAI policy attached",
                            recommendation="Attach a Responsible AI content filter policy with jailbreak detection, hate/violence/sexual/self-harm filtering.",
                            owasp_llm="LLM01: Prompt Injection",
                        ))
            except Exception:
                pass
