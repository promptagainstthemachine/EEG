"""
EEG - Azure Authenticated Scanner
Live audit of Azure OpenAI, AI Foundry, AI Search, and related services.
Includes comprehensive IAM, network, guardrails, and diagnostic settings auditing.
Auto-detects permissions and gracefully handles restricted access.
Config-driven checks loaded from eeg/config/azure_live_checks.yaml
"""

import os
import subprocess
import json
from typing import Optional, List, Dict, Tuple
from eeg.collector import Collector, Finding, Severity
from eeg.auth_scanner.check_runner import CheckRunner, get_threshold

try:
    from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
    from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


def _safe_cli_call(cmd: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
    """
    Execute CLI command safely, returning (success, stdout, error_message).
    Never raises exceptions - always returns a result tuple.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return True, result.stdout.strip(), ""
        else:
            # Extract meaningful error from stderr
            error = result.stderr.strip() if result.stderr else f"Exit code {result.returncode}"
            # Check for common permission errors
            if any(x in error.lower() for x in ["authorization", "forbidden", "access denied", "not authorized", "permission"]):
                return False, "", f"Permission denied: {error[:150]}"
            return False, "", error[:200]
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", "CLI tool not found"
    except Exception as e:
        return False, "", str(e)[:150]


class AzureAuthScanner:
    """
    Live audit of Azure AI resources using authenticated API calls.
    Config-driven checks from azure_live_checks.yaml.
    """
    """
    Live audit of Azure AI resources using authenticated API calls.
    Gracefully handles permission restrictions without breaking scan flow.
    """

    def __init__(self, auth_context: dict):
        self.auth_context = auth_context
        self.subscription_id = auth_context.get("subscription") or os.environ.get("AZURE_SUBSCRIPTION_ID")
        self.tenant = auth_context.get("tenant")
        self._use_cli = auth_context.get("source") in ("azure_cli", "cloud_shell")
        self._permission_level = "unknown"  # Will be updated during scan

    def scan(self, collector: Collector):
        if not HAS_AZURE and not self._use_cli:
            print("  [AUTH-AZ] azure-identity/azure-mgmt not installed — trying CLI fallback")
            self._scan_with_cli(collector)
            return

        if not self.subscription_id:
            self.subscription_id = self._get_subscription_from_cli()
            if not self.subscription_id:
                collector.add_permission_issue("azure_auth", "subscription", "No subscription ID found")
                print("  [AUTH-AZ] ⚠ No subscription ID found - attempting limited scan")
                # Still try to scan with whatever we have
                self._scan_with_cli(collector)
                return

        print(f"  [AUTH-AZ] Subscription: {self.subscription_id}")
        collector.set_metadata(azure_subscription=self.subscription_id)

        if self._use_cli or not HAS_AZURE:
            self._scan_with_cli(collector)
        else:
            self._scan_with_sdk(collector)

    def _get_subscription_from_cli(self) -> Optional[str]:
        """Get current subscription from Azure CLI."""
        success, stdout, _ = _safe_cli_call(["az", "account", "show", "--query", "id", "-o", "tsv"], timeout=10)
        return stdout if success else None

    def _scan_with_sdk(self, collector: Collector):
        """Scan using Azure Python SDK."""
        try:
            credential = DefaultAzureCredential()
            collector.add_completed_check("azure_sdk_auth")
        except Exception as e:
            collector.add_permission_issue("azure_sdk_auth", "credential", str(e))
            print(f"  [AUTH-AZ] ⚠ SDK auth issue - falling back to CLI: {str(e)[:80]}")
            self._scan_with_cli(collector)
            return

        # Get all subscriptions to audit
        subscriptions = self._cli_get_subscriptions(collector)
        if not subscriptions:
            subscriptions = [self.subscription_id] if self.subscription_id else []

        if not subscriptions:
            print("  [AUTH-AZ] ⚠ No subscriptions accessible - check permissions")
            return

        print(f"  [AUTH-AZ] Will audit {len(subscriptions)} subscription(s) using SDK...")

        for sub in subscriptions:
            if not sub:
                continue
            print(f"  [AUTH-AZ] Auditing subscription: {sub}")
            
            try:
                cog_client = CognitiveServicesManagementClient(credential, sub)
                self._check_cognitive_accounts_sdk(cog_client, collector, credential, sub)
                print(f"  [AUTH-AZ] Completed subscription: {sub}")
            except Exception as e:
                print(f"  [AUTH-AZ] ⚠ Error auditing subscription {sub}: {str(e)[:100]} - continuing to next subscription")
                collector.add_permission_issue(f"sdk_audit_subscription_{sub}", sub, str(e)[:150])
                continue

    def _scan_with_cli(self, collector: Collector):
        """Scan using Azure CLI commands (for cloud shell and CLI-only environments)."""
        print("  [AUTH-AZ] Using Azure CLI for resource auditing...")
        
        # Get all subscriptions if we have access
        subscriptions = self._cli_get_subscriptions(collector)
        if not subscriptions:
            subscriptions = [self.subscription_id] if self.subscription_id else []

        if not subscriptions:
            print("  [AUTH-AZ] ⚠ No subscriptions accessible - check permissions")
            return

        for sub in subscriptions:
            if not sub:
                continue
            print(f"  [AUTH-AZ] Auditing subscription: {sub}")
            
            try:
                if not self._cli_set_subscription(sub, collector):
                    print(f"  [AUTH-AZ] ⚠ Failed to set subscription {sub} - continuing to next subscription")
                    continue
                
                # Audit AI resources
                resources = self._cli_get_ai_resources(collector)
                if not resources:
                    print(f"  [AUTH-AZ] No AI resources found or accessible in subscription {sub}")
                    continue

                print(f"  [AUTH-AZ] Found {len(resources)} AI resource(s)")

                for resource in resources:
                    name = resource.get("name", "")
                    rg = resource.get("resourceGroup", "")
                    resource_id = resource.get("id", "")
                    
                    if not name or not rg:
                        continue

                    print(f"    > Auditing: {name}")
                    
                    try:
                        # Get detailed resource info
                        details = self._cli_get_resource_details(name, rg, collector)
                        if not details:
                            print(f"    > Skipping {name} - unable to get details, continuing to next resource")
                            continue

                        # Run all checks - each handles its own permissions gracefully
                        self._check_network_cli(name, rg, details, collector)
                        self._check_iam_cli(name, rg, resource_id, collector)
                        self._check_diagnostics_cli(name, rg, resource_id, collector)
                        self._check_deployments_cli(name, rg, collector)
                        self._check_default_guardrails_cli(name, rg, details, collector)
                    except Exception as e:
                        print(f"    > Error auditing {name}: {str(e)[:100]} - continuing to next resource")
                        collector.add_permission_issue(f"audit_resource_{name}", f"{rg}/{name}", str(e)[:150])
                        continue
                        
                print(f"  [AUTH-AZ] Completed subscription: {sub}")
                
            except Exception as e:
                print(f"  [AUTH-AZ] ⚠ Error auditing subscription {sub}: {str(e)[:100]} - continuing to next subscription")
                collector.add_permission_issue(f"audit_subscription_{sub}", sub, str(e)[:150])
                continue

    # ── CLI Helper Methods with Permission Handling ─────────────────
    def _cli_get_subscriptions(self, collector: Collector) -> List[str]:
        """Get list of subscription IDs."""
        success, stdout, error = _safe_cli_call(["az", "account", "list", "--query", "[].id", "-o", "tsv"])
        if success:
            collector.add_completed_check("list_subscriptions")
            return [s.strip() for s in stdout.split("\n") if s.strip()]
        else:
            collector.add_permission_issue("list_subscriptions", "subscriptions", error)
            return []

    def _cli_set_subscription(self, sub_id: str, collector: Collector) -> bool:
        """Set active subscription."""
        success, _, error = _safe_cli_call(["az", "account", "set", "--subscription", sub_id], timeout=10)
        if not success:
            collector.add_permission_issue("set_subscription", sub_id, error)
            return False
        return True

    def _cli_get_ai_resources(self, collector: Collector) -> List[Dict]:
        """Get AI resources (Cognitive Services accounts)."""
        success, stdout, error = _safe_cli_call([
            "az", "cognitiveservices", "account", "list",
            "--query", "[].{name:name, resourceGroup:resourceGroup, id:id, kind:kind}",
            "-o", "json"
        ])
        if success:
            collector.add_completed_check("list_ai_resources")
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return []
        else:
            collector.add_permission_issue("list_ai_resources", "cognitive_services", error)
            return []

    def _cli_get_resource_details(self, name: str, rg: str, collector: Collector) -> Optional[Dict]:
        """Get detailed resource information."""
        success, stdout, error = _safe_cli_call([
            "az", "cognitiveservices", "account", "show", "-n", name, "-g", rg, "-o", "json"
        ])
        if success:
            collector.add_completed_check(f"get_resource_{name}")
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return None
        else:
            collector.add_permission_issue(f"get_resource_{name}", f"{rg}/{name}", error)
            return None

    def _check_network_cli(self, name: str, rg: str, details: Dict, collector: Collector):
        """Check network security configuration."""
        collector.add_completed_check(f"network_check_{name}")
        
        # Ensure details is a dict
        if not isinstance(details, dict):
            return
        props = details.get("properties", {})
        if not isinstance(props, dict):
            props = {}
        
        # Public network access
        public_access = props.get("publicNetworkAccess", "Enabled")
        if public_access == "Enabled":
            collector.add_finding(Finding(
                rule_id="AUTH-AZ-NET-001", severity=Severity.HIGH,
                category="network", cloud_env="azure",
                file_path=f"live:cognitive:{name}", line_number=0,
                code_snippet=f"publicNetworkAccess={public_access}",
                message=f"Azure AI account '{name}' has public network access enabled",
                recommendation="Disable public network access. Use private endpoints for all AI service connections.",
            ))

        # Private endpoint check
        pe_connections = props.get("privateEndpointConnections", [])
        if not pe_connections:
            collector.add_finding(Finding(
                rule_id="AUTH-AZ-NET-002", severity=Severity.MEDIUM,
                category="network", cloud_env="azure",
                file_path=f"live:cognitive:{name}", line_number=0,
                code_snippet="privateEndpointConnections=[]",
                message=f"Azure AI account '{name}' has no private endpoint connections",
                recommendation="Configure private endpoints to secure AI service traffic within your VNet.",
            ))

        # Network ACLs
        network_acls = props.get("networkAcls", {})
        if network_acls and isinstance(network_acls, dict):
            default_action = network_acls.get("defaultAction", "Allow")
            if default_action == "Allow":
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-NET-003", severity=Severity.HIGH,
                    category="network", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet=f"networkAcls.defaultAction={default_action}",
                    message=f"Azure AI account '{name}' network ACLs default to Allow",
                    recommendation="Set network ACLs defaultAction to Deny. Whitelist specific IPs and VNet subnets.",
                ))

    def _check_iam_cli(self, name: str, rg: str, resource_id: str, collector: Collector):
        """Check IAM configuration on the resource."""
        # Get role assignments at resource scope
        success, stdout, error = _safe_cli_call([
            "az", "role", "assignment", "list", "--scope", resource_id,
            "--query", "[].{role:roleDefinitionName, principal:principalName, type:principalType}",
            "-o", "json"
        ])
        
        if success:
            collector.add_completed_check(f"iam_check_{name}")
            try:
                assignments = json.loads(stdout)
                # Handle both list and dict responses
                if isinstance(assignments, dict):
                    assignments = assignments.get("value", [])
                if not isinstance(assignments, list):
                    assignments = []
                # Check for overly permissive assignments
                for assignment in assignments:
                    if not isinstance(assignment, dict):
                        continue
                    role = assignment.get("role", "")
                    principal_type = assignment.get("type", "")
                    
                    # Flag Owner/Contributor on AI resources
                    if role in ("Owner", "Contributor"):
                        collector.add_finding(Finding(
                            rule_id="AUTH-AZ-IAM-002", severity=Severity.MEDIUM,
                            category="iam", cloud_env="azure",
                            file_path=f"live:cognitive:{name}", line_number=0,
                            code_snippet=f"role={role}, principalType={principal_type}",
                            message=f"Azure AI account '{name}' has {role} role assigned at resource level",
                            recommendation="Use least-privilege roles. Prefer 'Cognitive Services User' or 'Cognitive Services OpenAI User' instead of broad Owner/Contributor.",
                        ))
            except json.JSONDecodeError:
                pass
        else:
            # Only log as permission issue if it's actually a permission error
            if "permission" in error.lower() or "authorization" in error.lower():
                collector.add_permission_issue(f"iam_check_{name}", resource_id, error)
            # Continue - don't break the flow

        # Check local auth (API key) status from existing details
        details = self._cli_get_resource_details(name, rg, collector)
        if details and isinstance(details, dict):
            props = details.get("properties", {})
            if isinstance(props, dict):
                disable_local_auth = props.get("disableLocalAuth", False)
                if not disable_local_auth:
                    collector.add_finding(Finding(
                        rule_id="AUTH-AZ-IAM-001", severity=Severity.HIGH,
                        category="iam", cloud_env="azure",
                        file_path=f"live:cognitive:{name}", line_number=0,
                        code_snippet=f"disableLocalAuth={disable_local_auth}",
                        message=f"Azure AI account '{name}' allows API key authentication (local auth enabled)",
                        recommendation="Set disableLocalAuth=true. Use Managed Identity (Azure AD) for authentication instead of API keys.",
                    ))

    def _check_diagnostics_cli(self, name: str, rg: str, resource_id: str, collector: Collector):
        """Check diagnostic settings for logging and monitoring."""
        success, stdout, error = _safe_cli_call([
            "az", "monitor", "diagnostic-settings", "list", "--resource", resource_id, "-o", "json"
        ])
        
        if not success:
            # Permission issue - log but don't break
            if "permission" in error.lower() or "authorization" in error.lower():
                collector.add_permission_issue(f"diagnostics_check_{name}", resource_id, error)
            return
        
        collector.add_completed_check(f"diagnostics_check_{name}")
        
        try:
            settings = json.loads(stdout)
        except json.JSONDecodeError:
            return
        
        # Handle both list and dict responses from Azure CLI
        if isinstance(settings, list):
            settings_list = settings
        else:
            settings_list = settings.get("value", [])
        
        if not settings_list:
            collector.add_finding(Finding(
                rule_id="AUTH-AZ-LOG-001", severity=Severity.HIGH,
                category="logging", cloud_env="azure",
                file_path=f"live:cognitive:{name}", line_number=0,
                code_snippet="diagnosticSettings=[]",
                message=f"Azure AI account '{name}' has no diagnostic settings configured",
                recommendation="Configure diagnostic settings to send logs to Log Analytics, Storage, or Event Hub for security monitoring.",
            ))
        else:
            # Check for audit and request/response logging
            has_audit = False
            has_request_response = False
            
            for setting in settings_list:
                if not isinstance(setting, dict):
                    continue
                for log in setting.get("logs", []):
                    if not isinstance(log, dict):
                        continue
                    if log.get("enabled"):
                        category = log.get("category", "")
                        if "Audit" in category:
                            has_audit = True
                        if "RequestResponse" in category:
                            has_request_response = True
            
            if not has_audit:
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-LOG-002", severity=Severity.MEDIUM,
                    category="logging", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet="auditLogs=disabled",
                    message=f"Azure AI account '{name}' has audit logging disabled",
                    recommendation="Enable Audit category in diagnostic settings to track administrative operations.",
                ))
            
            if not has_request_response:
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-LOG-003", severity=Severity.MEDIUM,
                    category="logging", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet="requestResponseLogs=disabled",
                    message=f"Azure AI account '{name}' has request/response logging disabled",
                    recommendation="Enable RequestResponse category to log prompts and completions for security analysis.",
                ))

    def _check_deployments_cli(self, name: str, rg: str, collector: Collector):
        """Check model deployments for guardrail configuration."""
        success, stdout, error = _safe_cli_call([
            "az", "cognitiveservices", "account", "deployment", "list",
            "-n", name, "-g", rg, "-o", "json"
        ])
        
        if not success:
            if "permission" in error.lower() or "authorization" in error.lower():
                collector.add_permission_issue(f"deployments_check_{name}", f"{rg}/{name}", error)
            return
        
        collector.add_completed_check(f"deployments_check_{name}")
        
        try:
            deployments = json.loads(stdout)
        except json.JSONDecodeError:
            return
        
        # Handle both list and dict responses
        if isinstance(deployments, dict):
            deployments = deployments.get("value", [])
        if not isinstance(deployments, list):
            return
        
        for dep in deployments:
            if not isinstance(dep, dict):
                continue
            dep_name = dep.get("name", "")
            props = dep.get("properties", {})
            if not isinstance(props, dict):
                props = {}
            
            # Check for RAI policy (content filter)
            rai_policy = props.get("raiPolicyName") or props.get("contentFilter")
            
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

    def _check_default_guardrails_cli(self, name: str, rg: str, details: Dict, collector: Collector):
        """
        Check if the project/resource has default guardrails configured.
        This is a key finding that indicates whether AI safety is properly configured.
        """
        props = details.get("properties", {}) if isinstance(details, dict) else {}
        if not isinstance(props, dict):
            props = {}
        capabilities = props.get("capabilities", [])
        
        # Extract capability names - handle both list of dicts and other formats
        cap_names = []
        if isinstance(capabilities, list):
            for c in capabilities:
                if isinstance(c, dict):
                    cap_names.append(c.get("name", ""))
                elif isinstance(c, str):
                    cap_names.append(c)
        
        # Check for default content moderation capabilities
        safety_caps = ["ContentSafety", "TextModeration", "ImageModeration", "Hate", "SelfHarm", "Sexual", "Violence"]
        has_safety_caps = any(cap in cap_names for cap in safety_caps)
        
        # Check for guardrail-related properties
        content_filter = props.get("contentFilter") or props.get("defaultContentFilterPolicy")
        rai_policy = props.get("raiPolicyName") or props.get("responsibleAiPolicy")
        
        # Determine if default guardrails are configured
        has_default_guardrails = bool(content_filter or rai_policy or has_safety_caps)
        
        if not has_default_guardrails:
            collector.add_finding(Finding(
                rule_id="AUTH-AZ-GUARD-002", severity=Severity.CRITICAL,
                category="guardrail", cloud_env="azure",
                file_path=f"live:cognitive:{name}", line_number=0,
                code_snippet=f"defaultGuardrails=NOT_CONFIGURED, capabilities={cap_names[:5]}",
                message=f"Azure AI account '{name}' does NOT have default guardrails configured",
                recommendation="Configure default content filtering policies at the account level. Enable Hate, SelfHarm, Sexual, Violence, and PromptInjection filters as baseline protection.",
                owasp_llm="LLM01: Prompt Injection",
            ))
        else:
            # Even if guardrails exist, check if they cover all categories
            missing_caps = [cap for cap in ["Hate", "SelfHarm", "Sexual", "Violence"] if cap not in cap_names]
            if missing_caps and not content_filter:
                collector.add_finding(Finding(
                    rule_id="AUTH-AZ-GUARD-003", severity=Severity.HIGH,
                    category="guardrail", cloud_env="azure",
                    file_path=f"live:cognitive:{name}", line_number=0,
                    code_snippet=f"missingFilters={missing_caps}",
                    message=f"Azure AI account '{name}' has incomplete default guardrails - missing: {', '.join(missing_caps)}",
                    recommendation=f"Enable content filters for: {', '.join(missing_caps)}. All four content categories should be protected.",
                    owasp_llm="LLM01: Prompt Injection",
                ))

        # Check for prompt injection protection specifically
        has_prompt_injection = "PromptInjection" in cap_names or props.get("jailbreakDetection")
        if not has_prompt_injection and not content_filter:
            collector.add_finding(Finding(
                rule_id="AUTH-AZ-GUARD-004", severity=Severity.CRITICAL,
                category="guardrail", cloud_env="azure",
                file_path=f"live:cognitive:{name}", line_number=0,
                code_snippet="promptInjectionProtection=NOT_CONFIGURED",
                message=f"Azure AI account '{name}' has no prompt injection / jailbreak protection enabled",
                recommendation="Enable jailbreak detection and prompt injection filters. This is critical for preventing adversarial attacks on AI models.",
                owasp_llm="LLM01: Prompt Injection",
            ))

    # ── SDK Methods (when azure-mgmt is available) ──────────────────
    def _check_cognitive_accounts_sdk(self, cog_client, collector: Collector, credential, subscription_id: str = ""):
        """Audit all Cognitive Services accounts using SDK."""
        sub_label = f" in subscription {subscription_id}" if subscription_id else ""
        print(f"  [AUTH-AZ] Auditing Cognitive Services accounts{sub_label} (SDK mode)...")

        try:
            accounts = list(cog_client.accounts.list())
        except Exception as e:
            print(f"  [AUTH-AZ] Cannot list accounts{sub_label}: {e}")
            return

        ai_accounts = [a for a in accounts if a.kind in ("OpenAI", "AIServices", "CognitiveServices")]
        print(f"  [AUTH-AZ] Found {len(ai_accounts)} AI service account(s){sub_label}")

        for account in ai_accounts:
            name = account.name
            rg = account.id.split("/")[4] if account.id else "unknown"
            
            try:
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
                            rule_id="AUTH-AZ-NET-003", severity=Severity.HIGH,
                            category="network", cloud_env="azure",
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
                
                # Check default guardrails (SDK mode)
                self._check_default_guardrails_sdk(name, props, collector)
                
            except Exception as e:
                print(f"  [AUTH-AZ] Error auditing account {name}: {str(e)[:100]} - continuing to next account")
                collector.add_permission_issue(f"audit_account_{name}", name, str(e)[:150])
                continue

    def _check_default_guardrails_sdk(self, name: str, props, collector: Collector):
        """Check for default guardrails using SDK properties."""
        capabilities = getattr(props, 'capabilities', []) or []
        cap_names = [getattr(c, 'name', '') for c in capabilities]
        
        # Check for safety capabilities
        safety_caps = ["ContentSafety", "TextModeration", "Hate", "SelfHarm", "Sexual", "Violence"]
        has_safety_caps = any(cap in cap_names for cap in safety_caps)
        
        content_filter = getattr(props, 'content_filter', None) or getattr(props, 'default_content_filter_policy', None)
        
        if not has_safety_caps and not content_filter:
            collector.add_finding(Finding(
                rule_id="AUTH-AZ-GUARD-002", severity=Severity.CRITICAL,
                category="guardrail", cloud_env="azure",
                file_path=f"live:cognitive:{name}", line_number=0,
                code_snippet=f"defaultGuardrails=NOT_CONFIGURED",
                message=f"Azure AI account '{name}' does NOT have default guardrails configured",
                recommendation="Configure default content filtering policies at the account level. Enable Hate, SelfHarm, Sexual, Violence, and PromptInjection filters.",
                owasp_llm="LLM01: Prompt Injection",
            ))

