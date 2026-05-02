"""
EEG - AWS Authenticated Scanner
Live audit of Bedrock agents, guardrails, knowledge bases, model logging,
IAM, and network. Supports both SDK and CLI modes for cloud shell compatibility.
Auto-detects permissions and gracefully handles restricted access.
Config-driven checks loaded from eeg/config/aws_live_checks.yaml
"""

import os
import sys
import subprocess
import json
from typing import List, Dict, Optional, Tuple
from eeg.collector import Collector, Finding, Severity
from eeg.auth_scanner.check_runner import CheckRunner, get_threshold

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


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
            error = result.stderr.strip() if result.stderr else f"Exit code {result.returncode}"
            # Check for common permission errors
            if any(x in error.lower() for x in ["accessdenied", "not authorized", "forbidden", "permission"]):
                return False, "", f"Permission denied: {error[:150]}"
            return False, "", error[:200]
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", "AWS CLI not found"
    except Exception as e:
        return False, "", str(e)[:150]


def _paginate(method, result_key, **kwargs):
    """Generic AWS paginator using nextToken."""
    items = []
    next_token = None
    while True:
        if next_token:
            kwargs["nextToken"] = next_token
        try:
            resp = method(**kwargs)
        except Exception:
            break
        items.extend(resp.get(result_key, []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


class AWSAuthScanner:
    """
    Live audit of AWS Bedrock resources using authenticated API calls.
    Gracefully handles permission restrictions without breaking scan flow.
    Config-driven checks from aws_live_checks.yaml.
    """

    def __init__(self, auth_context: dict):
        self.auth_context = auth_context
        self.profile = auth_context.get("profile")
        self.region = auth_context.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        self._use_cli = auth_context.get("source") in ("aws_cli", "cloud_shell")
        self._has_default_guardrails = False
        self._check_runner: Optional[CheckRunner] = None

    def scan(self, collector: Collector):
        # Initialize config-driven check runner
        self._check_runner = CheckRunner("aws", collector)
        
        if not HAS_BOTO3 and not self._use_cli:
            print("  [AUTH-AWS] boto3 not installed — trying CLI fallback")
            self._scan_with_cli(collector)
            return

        if HAS_BOTO3:
            self._scan_with_sdk(collector)
        else:
            self._scan_with_cli(collector)
        
        # Final check: Report if no default guardrails exist (AUTH-AWS-GUARD-001)
        if not self._has_default_guardrails:
            self._check_runner.add_finding_if_enabled(
                "AUTH-AWS-GUARD-001",
                file_path="live:bedrock:account",
                code_snippet="guardrails=[]",
                message_override="Account has no Bedrock guardrails — all models vulnerable to prompt injection",
            )

    def _scan_with_sdk(self, collector: Collector):
        """Scan using boto3 SDK."""
        print("  [AUTH-AWS] Initializing AWS session...")
        session_params = {}
        if self.profile:
            session_params["profile_name"] = self.profile
        if self.region:
            session_params["region_name"] = self.region

        try:
            session = boto3.Session(**session_params)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity["Account"]
            print(f"  [AUTH-AWS] Account: {account_id} | Region: {session.region_name}")
            collector.add_completed_check("aws_sdk_auth")
            collector.set_metadata(aws_account=account_id, aws_region=session.region_name)
        except (ClientError, NoCredentialsError) as e:
            collector.add_permission_issue("aws_sdk_auth", "sts:GetCallerIdentity", str(e))
            print(f"  [AUTH-AWS] ⚠ SDK auth issue - falling back to CLI")
            self._scan_with_cli(collector)
            return

        # Create clients - each check will handle its own permission errors
        try:
            bedrock = session.client("bedrock")
            bedrock_agent = session.client("bedrock-agent")
            s3 = session.client("s3")
            iam = session.client("iam")
        except Exception as e:
            collector.add_permission_issue("aws_client_init", "boto3", str(e))
            print(f"  [AUTH-AWS] ⚠ Client init issue - falling back to CLI")
            self._scan_with_cli(collector)
            return

        # Run each check - they handle their own permissions gracefully
        self._check_guardrails(bedrock, collector)
        self._check_agents(bedrock_agent, bedrock, collector)
        self._check_knowledge_bases(bedrock_agent, s3, collector)
        self._check_model_invocation_logging(bedrock, collector)
        self._check_iam_policies(iam, collector)
        self._check_evaluation_jobs(bedrock, collector)
        self._check_fine_tuning(bedrock, collector)
        self._check_provisioned_throughput(bedrock, collector)

    def _scan_with_cli(self, collector: Collector):
        """Scan using AWS CLI for cloud shell environments."""
        print("  [AUTH-AWS] Using AWS CLI for resource auditing...")
        
        # Verify authentication
        success, stdout, error = _safe_cli_call(["aws", "sts", "get-caller-identity", "--output", "json"])
        
        if not success:
            collector.add_permission_issue("aws_cli_auth", "sts:GetCallerIdentity", error)
            print(f"  [AUTH-AWS] ⚠ CLI auth limited - proceeding with available permissions")
        else:
            collector.add_completed_check("aws_cli_auth")
            try:
                identity = json.loads(stdout)
                print(f"  [AUTH-AWS] Account: {identity.get('Account')} | User: {identity.get('Arn', '').split('/')[-1]}")
                collector.set_metadata(aws_account=identity.get('Account'))
            except json.JSONDecodeError:
                pass

        # Run checks - each handles its own permissions
        self._check_guardrails_cli(collector)
        self._check_agents_cli(collector)
        self._check_logging_cli(collector)
        self._check_evaluation_jobs_cli(collector)
        self._check_fine_tuning_cli(collector)
        self._check_provisioned_throughput_cli(collector)
        self._check_knowledge_bases_cli(collector)

    def _check_guardrails_cli(self, collector: Collector):
        """Check Bedrock guardrails using AWS CLI."""
        print("  [AUTH-AWS] Auditing Bedrock guardrails (CLI)...")
        
        success, stdout, error = _safe_cli_call(["aws", "bedrock", "list-guardrails", "--output", "json"])
        
        if not success:
            if "permission" in error.lower() or "accessdenied" in error.lower():
                collector.add_permission_issue("list_guardrails", "bedrock:ListGuardrails", error)
                print("  [AUTH-AWS] ⚠ No permission to list guardrails - skipping")
            return
        
        collector.add_completed_check("list_guardrails")
        
        try:
            data = json.loads(stdout)
            guardrails = data.get("guardrails", [])
            
            if guardrails:
                self._has_default_guardrails = True
                print(f"  [AUTH-AWS] Found {len(guardrails)} guardrail(s)")
                
                for gr in guardrails:
                    gr_id = gr.get("id", "")
                    gr_name = gr.get("name", gr_id)
                    self._check_guardrail_details_cli(gr_id, gr_name, collector)
            else:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-001", severity=Severity.CRITICAL,
                    category="guardrail", cloud_env="aws",
                    file_path="live:bedrock:guardrails", line_number=0,
                    code_snippet="", message="No Bedrock guardrails found in account",
                    recommendation="Create guardrails with content filters (PROMPT_ATTACK HIGH), PII blocking, and topic denial.",
                    owasp_llm="LLM01: Prompt Injection",
                ))
        except json.JSONDecodeError:
            pass

    def _check_guardrail_details_cli(self, gr_id: str, gr_name: str, collector: Collector):
        """Check individual guardrail details via CLI."""
        success, stdout, error = _safe_cli_call([
            "aws", "bedrock", "get-guardrail", "--guardrail-identifier", gr_id, "--output", "json"
        ])
        
        if not success:
            if "permission" in error.lower():
                collector.add_permission_issue(f"get_guardrail_{gr_name}", "bedrock:GetGuardrail", error)
            return
        
        try:
            detail = json.loads(stdout)
            
            content_policy = detail.get("contentPolicy", {})
            filters = content_policy.get("filtersConfig", [])
            has_prompt_attack = False
            
            for f in filters:
                ftype = f.get("type", "")
                inp = f.get("inputStrength", "NONE")
                
                if ftype == "PROMPT_ATTACK":
                    has_prompt_attack = True
                
                if inp in ("LOW", "NONE"):
                    collector.add_finding(Finding(
                        rule_id="AUTH-AWS-GUARD-002", severity=Severity.HIGH,
                        category="guardrail", cloud_env="aws",
                        file_path=f"live:guardrail:{gr_name}", line_number=0,
                        code_snippet=f"filter={ftype} inputStrength={inp}",
                        message=f"Guardrail '{gr_name}' has weak {ftype} filter (inputStrength={inp})",
                        recommendation=f"Set {ftype} inputStrength to HIGH.",
                        owasp_llm="LLM01: Prompt Injection",
                    ))
            
            if not has_prompt_attack:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-003", severity=Severity.CRITICAL,
                    category="guardrail", cloud_env="aws",
                    file_path=f"live:guardrail:{gr_name}", line_number=0,
                    code_snippet="",
                    message=f"Guardrail '{gr_name}' missing PROMPT_ATTACK content filter",
                    recommendation="Add PROMPT_ATTACK filter with inputStrength=HIGH.",
                    owasp_llm="LLM01: Prompt Injection",
                ))
        except json.JSONDecodeError:
            pass

    def _check_agents_cli(self, collector: Collector):
        """Check Bedrock agents using AWS CLI."""
        print("  [AUTH-AWS] Auditing Bedrock agents (CLI)...")
        
        success, stdout, error = _safe_cli_call(["aws", "bedrock-agent", "list-agents", "--output", "json"])
        
        if not success:
            if "permission" in error.lower() or "accessdenied" in error.lower():
                collector.add_permission_issue("list_agents", "bedrock:ListAgents", error)
                print("  [AUTH-AWS] ⚠ No permission to list agents - skipping")
            return
        
        collector.add_completed_check("list_agents")
        
        try:
            data = json.loads(stdout)
            agents = data.get("agentSummaries", [])
            print(f"  [AUTH-AWS] Found {len(agents)} agent(s)")
            
            for agent in agents:
                agent_id = agent.get("agentId", "")
                agent_name = agent.get("agentName", agent_id)
                self._check_agent_details_cli(agent_id, agent_name, collector)
        except json.JSONDecodeError:
            pass

    def _check_agent_details_cli(self, agent_id: str, agent_name: str, collector: Collector):
        """Check individual agent details via CLI."""
        success, stdout, error = _safe_cli_call([
            "aws", "bedrock-agent", "get-agent", "--agent-id", agent_id, "--output", "json"
        ])
        
        if not success:
            if "permission" in error.lower():
                collector.add_permission_issue(f"get_agent_{agent_name}", "bedrock:GetAgent", error)
            return
        
        try:
            data = json.loads(stdout)
            agent_cfg = data.get("agent", {})
            
            # Check guardrail attachment
            gr_cfg = agent_cfg.get("guardrailConfiguration")
            if not gr_cfg or not gr_cfg.get("guardrailIdentifier"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-AGENT-001", severity=Severity.CRITICAL,
                    category="policy", cloud_env="aws",
                    file_path=f"live:agent:{agent_name}", line_number=0,
                    code_snippet="guardrailConfiguration: null",
                    message=f"Agent '{agent_name}' has NO guardrail — vulnerable to prompt injection",
                    recommendation="Attach a Bedrock guardrail with PROMPT_ATTACK filter to this agent.",
                    owasp_llm="LLM01: Prompt Injection",
                ))
        except json.JSONDecodeError:
            pass

    def _check_logging_cli(self, collector: Collector):
        """Check model invocation logging via CLI."""
        print("  [AUTH-AWS] Auditing model invocation logging (CLI)...")
        
        success, stdout, error = _safe_cli_call([
            "aws", "bedrock", "get-model-invocation-logging-configuration", "--output", "json"
        ])
        
        if not success:
            if "permission" in error.lower() or "accessdenied" in error.lower():
                collector.add_permission_issue("get_logging_config", "bedrock:GetModelInvocationLoggingConfiguration", error)
                print("  [AUTH-AWS] ⚠ No permission to check logging config - skipping")
            else:
                # Logging not configured is also an error code
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-LOG-001", severity=Severity.CRITICAL,
                    category="logging", cloud_env="aws",
                    file_path="live:bedrock:logging", line_number=0,
                    code_snippet="",
                    message="Model invocation logging not configured — no audit trail for AI inference",
                    recommendation="Enable model invocation logging to S3 and CloudWatch.",
                ))
            return
        
        collector.add_completed_check("get_logging_config")
        
        try:
            data = json.loads(stdout)
            logging_cfg = data.get("loggingConfig", {})
            
            cw_cfg = logging_cfg.get("cloudWatchConfig", {})
            s3_cfg = logging_cfg.get("s3Config", {})
            
            if not cw_cfg.get("logGroupName") and not s3_cfg.get("bucketName"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-LOG-001", severity=Severity.CRITICAL,
                    category="logging", cloud_env="aws",
                    file_path="live:bedrock:logging", line_number=0,
                    code_snippet="",
                    message="Model invocation logging not configured — no audit trail for AI inference",
                    recommendation="Enable model invocation logging to S3 and CloudWatch.",
                ))
        except json.JSONDecodeError:
            pass

    def _check_logging_cli(self, collector: Collector):
        """Check model invocation logging via CLI."""
        print("  [AUTH-AWS] Auditing model invocation logging (CLI)...")
        
        success, stdout, error = _safe_cli_call(
            ["aws", "bedrock", "get-model-invocation-logging-configuration", "--output", "json"]
        )
        
        if not success:
            collector.add_permission_issue("cli_logging_config", "bedrock:GetModelInvocationLoggingConfiguration", error)
            collector.add_skipped_check("cli_logging_config")
            return
        
        collector.add_completed_check("cli_logging_config")
        
        try:
            data = json.loads(stdout)
            logging_cfg = data.get("loggingConfig", {})
            
            cw_cfg = logging_cfg.get("cloudWatchConfig", {})
            s3_cfg = logging_cfg.get("s3Config", {})
            
            if not cw_cfg.get("logGroupName") and not s3_cfg.get("bucketName"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-LOG-001", severity=Severity.CRITICAL,
                    category="logging", cloud_env="aws",
                    file_path="live:bedrock:logging", line_number=0,
                    code_snippet="",
                    message="Model invocation logging not configured — no audit trail for AI inference",
                    recommendation="Enable model invocation logging to S3 and CloudWatch.",
                ))
        except json.JSONDecodeError:
            pass

    # ── Guardrails ──────────────────────────────────────────────────
    def _check_guardrails(self, bedrock, collector: Collector):
        print("  [AUTH-AWS] Auditing Bedrock guardrails...")
        try:
            guardrails = _paginate(bedrock.list_guardrails, "guardrails", maxResults=100)
        except ClientError:
            print("  [AUTH-AWS] Cannot list guardrails (permission denied or none exist)")
            collector.add_finding(Finding(
                rule_id="AUTH-AWS-GUARD-001", severity=Severity.CRITICAL,
                category="guardrail", cloud_env="aws",
                file_path="live:bedrock:guardrails", line_number=0,
                code_snippet="", message="No Bedrock guardrails found in account",
                recommendation="Create guardrails with content filters (PROMPT_ATTACK HIGH), PII blocking, and topic denial.",
                owasp_llm="LLM01: Prompt Injection",
            ))
            return

        if not guardrails:
            collector.add_finding(Finding(
                rule_id="AUTH-AWS-GUARD-001", severity=Severity.CRITICAL,
                category="guardrail", cloud_env="aws",
                file_path="live:bedrock:guardrails", line_number=0,
                code_snippet="", message="No Bedrock guardrails found in account",
                recommendation="Create guardrails with content filters (PROMPT_ATTACK HIGH), PII blocking, and topic denial.",
                owasp_llm="LLM01: Prompt Injection",
            ))
            return

        # Mark that we have default guardrails
        self._has_default_guardrails = True

        print(f"  [AUTH-AWS] Found {len(guardrails)} guardrail(s)")
        for gr in guardrails:
            gr_id = gr["id"]
            gr_name = gr.get("name", gr_id)
            try:
                detail = bedrock.get_guardrail(guardrailIdentifier=gr_id, guardrailVersion="DRAFT")
            except ClientError:
                continue

            # Check content filter strengths
            content_policy = detail.get("contentPolicy", {})
            filters = content_policy.get("filtersConfig", [])
            has_prompt_attack = False
            for f in filters:
                ftype = f.get("type", "")
                inp = f.get("inputStrength", "NONE")
                out = f.get("outputStrength", "NONE")
                if ftype == "PROMPT_ATTACK":
                    has_prompt_attack = True
                if inp in ("LOW", "NONE"):
                    collector.add_finding(Finding(
                        rule_id="AUTH-AWS-GUARD-002", severity=Severity.HIGH,
                        category="guardrail", cloud_env="aws",
                        file_path=f"live:guardrail:{gr_name}", line_number=0,
                        code_snippet=f"filter={ftype} inputStrength={inp} outputStrength={out}",
                        message=f"Guardrail '{gr_name}' has weak {ftype} filter (inputStrength={inp})",
                        recommendation=f"Set {ftype} inputStrength to HIGH. LOW/NONE filters miss ~70% of adversarial prompts.",
                        owasp_llm="LLM01: Prompt Injection",
                    ))

            if not has_prompt_attack:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-003", severity=Severity.CRITICAL,
                    category="guardrail", cloud_env="aws",
                    file_path=f"live:guardrail:{gr_name}", line_number=0,
                    code_snippet="",
                    message=f"Guardrail '{gr_name}' missing PROMPT_ATTACK content filter",
                    recommendation="Add PROMPT_ATTACK filter with inputStrength=HIGH to detect jailbreaks and prompt injection.",
                    owasp_llm="LLM01: Prompt Injection",
                ))

            # PII check
            sensitive_policy = detail.get("sensitiveInformationPolicy", {})
            pii_entities = sensitive_policy.get("piiEntitiesConfig", [])
            if not pii_entities:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-004", severity=Severity.HIGH,
                    category="guardrail", cloud_env="aws",
                    file_path=f"live:guardrail:{gr_name}", line_number=0,
                    code_snippet="",
                    message=f"Guardrail '{gr_name}' has no PII entity filters",
                    recommendation="Add PII filters for AWS_ACCESS_KEY, AWS_SECRET_KEY, EMAIL, PHONE, SSN with action=BLOCK.",
                ))
            else:
                for pii in pii_entities:
                    if pii.get("action") == "ANONYMIZE":
                        collector.add_finding(Finding(
                            rule_id="AUTH-AWS-GUARD-005", severity=Severity.MEDIUM,
                            category="guardrail", cloud_env="aws",
                            file_path=f"live:guardrail:{gr_name}", line_number=0,
                            code_snippet=f"type={pii.get('type')} action=ANONYMIZE",
                            message=f"Guardrail '{gr_name}' PII filter uses ANONYMIZE instead of BLOCK for {pii.get('type')}",
                            recommendation="Set PII entity action to BLOCK. ANONYMIZE still leaks PII patterns.",
                        ))

            # Topic policy check
            topic_policy = detail.get("topicPolicy", {})
            if not topic_policy.get("topicsConfig"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-006", severity=Severity.MEDIUM,
                    category="guardrail", cloud_env="aws",
                    file_path=f"live:guardrail:{gr_name}", line_number=0,
                    code_snippet="",
                    message=f"Guardrail '{gr_name}' has no topic denial policies",
                    recommendation="Configure topic denial policies to prevent model from responding to harmful or off-scope topics.",
                ))

            # Contextual grounding check
            grounding = detail.get("contextualGroundingPolicy", {})
            if not grounding.get("filtersConfig"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-007", severity=Severity.HIGH,
                    category="guardrail", cloud_env="aws",
                    file_path=f"live:guardrail:{gr_name}", line_number=0,
                    code_snippet="",
                    message=f"Guardrail '{gr_name}' has no contextual grounding — hallucination risk",
                    recommendation="Enable contextual grounding with GROUNDING threshold >= 0.7 and RELEVANCE threshold >= 0.7.",
                    owasp_llm="LLM09: Overreliance",
                ))

            # Version check — DRAFT in production
            version = detail.get("version", "DRAFT")
            status = detail.get("status", "")
            if version == "DRAFT" and status != "CREATING":
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-GUARD-008", severity=Severity.MEDIUM,
                    category="guardrail", cloud_env="aws",
                    file_path=f"live:guardrail:{gr_name}", line_number=0,
                    code_snippet=f"version={version}",
                    message=f"Guardrail '{gr_name}' is still in DRAFT — not production-ready",
                    recommendation="Create a versioned PRODUCTION guardrail and assign it to agents/models.",
                ))

    # ── Agents ──────────────────────────────────────────────────────
    def _check_agents(self, bedrock_agent, bedrock, collector: Collector):
        print("  [AUTH-AWS] Auditing Bedrock agents...")
        try:
            agents = _paginate(bedrock_agent.list_agents, "agentSummaries", maxResults=100)
        except ClientError:
            print("  [AUTH-AWS] Cannot list agents")
            return

        if not agents:
            print("  [AUTH-AWS] No agents found")
            return

        print(f"  [AUTH-AWS] Found {len(agents)} agent(s)")
        for ag in agents:
            agent_id = ag["agentId"]
            agent_name = ag.get("agentName", agent_id)
            try:
                detail = bedrock_agent.get_agent(agentId=agent_id)
                agent_cfg = detail.get("agent", {})
            except ClientError:
                continue

            # Check guardrail attachment
            gr_cfg = agent_cfg.get("guardrailConfiguration")
            if not gr_cfg or not gr_cfg.get("guardrailIdentifier"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-AGENT-001", severity=Severity.CRITICAL,
                    category="policy", cloud_env="aws",
                    file_path=f"live:agent:{agent_name}", line_number=0,
                    code_snippet="guardrailConfiguration: null",
                    message=f"Agent '{agent_name}' has NO guardrail — vulnerable to prompt injection",
                    recommendation="Attach a Bedrock guardrail with PROMPT_ATTACK filter to this agent.",
                    owasp_llm="LLM01: Prompt Injection",
                ))

            # Check action groups for excessive agency
            try:
                action_groups = _paginate(
                    bedrock_agent.list_agent_action_groups, "actionGroupSummaries",
                    agentId=agent_id, agentVersion="DRAFT", maxResults=100,
                )
            except ClientError:
                action_groups = []

            for ag_summary in action_groups:
                if ag_summary.get("actionGroupState") == "DISABLED":
                    continue
                try:
                    ag_detail = bedrock_agent.get_agent_action_group(
                        agentId=agent_id, agentVersion="DRAFT",
                        actionGroupId=ag_summary["actionGroupId"],
                    )
                    ag_cfg = ag_detail.get("agentActionGroup", {})
                except ClientError:
                    continue

                executor = ag_cfg.get("actionGroupExecutor", {})
                if "lambda" in executor:
                    collector.add_finding(Finding(
                        rule_id="AUTH-AWS-AGENT-002", severity=Severity.HIGH,
                        category="policy", cloud_env="aws",
                        file_path=f"live:agent:{agent_name}/action-group:{ag_summary.get('actionGroupName','')}",
                        line_number=0,
                        code_snippet=f"executor=lambda:{executor.get('lambda','')}",
                        message=f"Agent '{agent_name}' action group has direct Lambda execution without human confirmation",
                        recommendation="Use RETURN_CONTROL executor for mutating actions. Require human confirmation before execution.",
                        owasp_llm="LLM06: Excessive Agency",
                    ))

            # Check memory encryption
            memory_cfg = agent_cfg.get("memoryConfiguration", {})
            if memory_cfg and not memory_cfg.get("kmsKeyArn"):
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-AGENT-003", severity=Severity.HIGH,
                    category="policy", cloud_env="aws",
                    file_path=f"live:agent:{agent_name}", line_number=0,
                    code_snippet="memoryConfiguration.kmsKeyArn: null",
                    message=f"Agent '{agent_name}' memory not encrypted with customer KMS key",
                    recommendation="Set kmsKeyArn on agent memory configuration to encrypt conversation history.",
                ))

    # ── Knowledge Bases ─────────────────────────────────────────────
    def _check_knowledge_bases(self, bedrock_agent, s3, collector: Collector):
        print("  [AUTH-AWS] Auditing Bedrock knowledge bases...")
        try:
            kbs = _paginate(bedrock_agent.list_knowledge_bases, "knowledgeBaseSummaries", maxResults=100)
        except ClientError:
            print("  [AUTH-AWS] Cannot list knowledge bases")
            return

        if not kbs:
            print("  [AUTH-AWS] No knowledge bases found")
            return

        print(f"  [AUTH-AWS] Found {len(kbs)} knowledge base(s)")
        for kb in kbs:
            kb_id = kb["knowledgeBaseId"]
            kb_name = kb.get("name", kb_id)

            # Check data sources → S3 bucket security
            try:
                data_sources = _paginate(
                    bedrock_agent.list_data_sources, "dataSourceSummaries",
                    knowledgeBaseId=kb_id, maxResults=100,
                )
            except ClientError:
                continue

            for ds in data_sources:
                try:
                    ds_detail = bedrock_agent.get_data_source(
                        knowledgeBaseId=kb_id, dataSourceId=ds["dataSourceId"],
                    )
                    ds_cfg = ds_detail.get("dataSource", {}).get("dataSourceConfiguration", {})
                except ClientError:
                    continue

                s3_cfg = ds_cfg.get("s3Configuration", {})
                bucket_arn = s3_cfg.get("bucketArn", "")
                if not bucket_arn:
                    continue
                bucket_name = bucket_arn.split(":::")[-1]

                # Check public access block
                try:
                    bpa = s3.get_public_access_block(Bucket=bucket_name)
                    cfg = bpa.get("PublicAccessBlockConfiguration", {})
                    if not all([
                        cfg.get("BlockPublicAcls"),
                        cfg.get("IgnorePublicAcls"),
                        cfg.get("BlockPublicPolicy"),
                        cfg.get("RestrictPublicBuckets"),
                    ]):
                        collector.add_finding(Finding(
                            rule_id="AUTH-AWS-KB-001", severity=Severity.CRITICAL,
                            category="storage", cloud_env="aws",
                            file_path=f"live:s3:{bucket_name}", line_number=0,
                            code_snippet=f"BlockPublicAcls={cfg.get('BlockPublicAcls')} BlockPublicPolicy={cfg.get('BlockPublicPolicy')}",
                            message=f"KB '{kb_name}' S3 bucket '{bucket_name}' lacks complete public access blocking — RAG data poisoning risk",
                            recommendation="Enable all Block Public Access settings on the KB data source bucket.",
                            owasp_llm="LLM03: Training Data Poisoning",
                        ))
                except ClientError:
                    pass

                # Check encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    has_kms = any(
                        r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
                        for r in rules
                    )
                    if not has_kms:
                        collector.add_finding(Finding(
                            rule_id="AUTH-AWS-KB-002", severity=Severity.HIGH,
                            category="storage", cloud_env="aws",
                            file_path=f"live:s3:{bucket_name}", line_number=0,
                            code_snippet="",
                            message=f"KB '{kb_name}' S3 bucket '{bucket_name}' not encrypted with KMS",
                            recommendation="Enable KMS server-side encryption for AI training data and embeddings.",
                        ))
                except ClientError:
                    pass

    # ── Model Invocation Logging ────────────────────────────────────
    def _check_model_invocation_logging(self, bedrock, collector: Collector):
        print("  [AUTH-AWS] Auditing model invocation logging...")
        try:
            log_cfg = bedrock.get_model_invocation_logging_configuration()
            logging = log_cfg.get("loggingConfig", {})
        except ClientError:
            collector.add_finding(Finding(
                rule_id="AUTH-AWS-LOG-001", severity=Severity.CRITICAL,
                category="logging", cloud_env="aws",
                file_path="live:bedrock:logging", line_number=0,
                code_snippet="",
                message="Model invocation logging not configured — no audit trail for AI inference",
                recommendation="Enable model invocation logging to S3 and CloudWatch via put_model_invocation_logging_configuration.",
            ))
            return

        cw_cfg = logging.get("cloudWatchConfig", {})
        s3_cfg = logging.get("s3Config", {})
        text_enabled = logging.get("textDataDeliveryEnabled", False)
        image_enabled = logging.get("imageDataDeliveryEnabled", False)

        if not cw_cfg.get("logGroupName") and not s3_cfg.get("bucketName"):
            collector.add_finding(Finding(
                rule_id="AUTH-AWS-LOG-001", severity=Severity.CRITICAL,
                category="logging", cloud_env="aws",
                file_path="live:bedrock:logging", line_number=0,
                code_snippet=f"cloudWatch={bool(cw_cfg.get('logGroupName'))} s3={bool(s3_cfg.get('bucketName'))}",
                message="Model invocation logging has no destination configured (no CloudWatch, no S3)",
                recommendation="Configure both CloudWatch logGroupName and S3 bucketName for model invocation logging.",
            ))

        if not text_enabled:
            collector.add_finding(Finding(
                rule_id="AUTH-AWS-LOG-002", severity=Severity.HIGH,
                category="logging", cloud_env="aws",
                file_path="live:bedrock:logging", line_number=0,
                code_snippet=f"textDataDeliveryEnabled={text_enabled}",
                message="Text data delivery disabled in model invocation logging — prompt/response content not captured",
                recommendation="Enable textDataDeliveryEnabled for full audit trail of prompts and responses.",
            ))

    # ── IAM Policies ────────────────────────────────────────────────
    def _check_iam_policies(self, iam, collector: Collector):
        print("  [AUTH-AWS] Auditing IAM policies for Bedrock access...")
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local", MaxItems=200):
                for policy in page.get("Policies", []):
                    arn = policy["Arn"]
                    version_id = policy.get("DefaultVersionId", "v1")
                    try:
                        ver = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                        doc = ver.get("PolicyVersion", {}).get("Document", {})
                    except ClientError:
                        continue

                    if isinstance(doc, str):
                        import json
                        try:
                            doc = json.loads(doc)
                        except Exception:
                            continue

                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        resources = stmt.get("Resource", [])
                        if isinstance(resources, str):
                            resources = [resources]

                        # Wildcard bedrock:*
                        for action in actions:
                            if action in ("bedrock:*", "*"):
                                collector.add_finding(Finding(
                                    rule_id="AUTH-AWS-IAM-001", severity=Severity.CRITICAL,
                                    category="iam", cloud_env="aws",
                                    file_path=f"live:iam:policy:{policy['PolicyName']}",
                                    line_number=0,
                                    code_snippet=f"Action={action} Resource={resources}",
                                    message=f"IAM policy '{policy['PolicyName']}' grants wildcard Bedrock access ({action})",
                                    recommendation="Scope Bedrock permissions to specific actions (bedrock:InvokeModel) and specific model ARNs.",
                                    owasp_llm="LLM06: Excessive Agency",
                                ))
        except ClientError as e:
            print(f"  [AUTH-AWS] IAM audit error: {e}")

    # ── Evaluation Jobs (SDK) ───────────────────────────────────────
    def _check_evaluation_jobs(self, bedrock, collector: Collector):
        """Check if evaluation/red-team jobs exist (SDK)."""
        print("  [AUTH-AWS] Auditing evaluation jobs...")
        try:
            jobs = _paginate(bedrock.list_evaluation_jobs, "jobSummaries", maxResults=100)
            collector.add_completed_check("sdk_list_evaluation_jobs")
            
            if not jobs:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-EVAL-001", severity=Severity.MEDIUM,
                    category="evaluation", cloud_env="aws",
                    file_path="live:bedrock:evaluations", line_number=0,
                    code_snippet="evaluationJobs=[]",
                    message="No model evaluation jobs found — AI red-teaming not configured",
                    recommendation="Create evaluation jobs using human or automated evaluators to test model safety and accuracy before production.",
                ))
            else:
                print(f"  [AUTH-AWS] Found {len(jobs)} evaluation job(s)")
                completed = [j for j in jobs if j.get("status") == "Completed"]
                if not completed:
                    collector.add_finding(Finding(
                        rule_id="AUTH-AWS-EVAL-002", severity=Severity.LOW,
                        category="evaluation", cloud_env="aws",
                        file_path="live:bedrock:evaluations", line_number=0,
                        code_snippet=f"evaluationJobs={len(jobs)} completed=0",
                        message="Evaluation jobs exist but none have completed successfully",
                        recommendation="Ensure evaluation jobs complete to get model safety metrics.",
                    ))
        except ClientError as e:
            collector.add_permission_issue("sdk_list_evaluation_jobs", "bedrock:ListEvaluationJobs", str(e))
            print(f"  [AUTH-AWS] Cannot list evaluation jobs: {str(e)[:80]}")

    def _check_fine_tuning(self, bedrock, collector: Collector):
        """Check fine-tuning/customization jobs for security (SDK)."""
        print("  [AUTH-AWS] Auditing fine-tuning jobs...")
        try:
            jobs = _paginate(bedrock.list_model_customization_jobs, "modelCustomizationJobSummaries", maxResults=100)
            collector.add_completed_check("sdk_list_customization_jobs")
            
            if jobs:
                print(f"  [AUTH-AWS] Found {len(jobs)} fine-tuning job(s)")
                for job in jobs:
                    job_name = job.get("jobName", "unknown")
                    job_arn = job.get("jobArn", "")
                    
                    try:
                        detail = bedrock.get_model_customization_job(jobIdentifier=job_arn)
                        
                        # Check output KMS encryption
                        output_cfg = detail.get("outputDataConfig", {})
                        if not output_cfg.get("kmsKeyId"):
                            collector.add_finding(Finding(
                                rule_id="AUTH-AWS-FT-002", severity=Severity.HIGH,
                                category="model", cloud_env="aws",
                                file_path=f"live:fine-tune:{job_name}", line_number=0,
                                code_snippet="outputDataConfig.kmsKeyId=null",
                                message=f"Fine-tuning job '{job_name}' output not encrypted with KMS",
                                recommendation="Specify kmsKeyId in outputDataConfig to encrypt fine-tuned model artifacts.",
                            ))
                    except ClientError:
                        pass
        except ClientError as e:
            collector.add_permission_issue("sdk_list_customization_jobs", "bedrock:ListModelCustomizationJobs", str(e))
            print(f"  [AUTH-AWS] Cannot list fine-tuning jobs: {str(e)[:80]}")

    def _check_provisioned_throughput(self, bedrock, collector: Collector):
        """Check rate limits and provisioned throughput (SDK)."""
        print("  [AUTH-AWS] Auditing provisioned throughput...")
        try:
            throughputs = _paginate(bedrock.list_provisioned_model_throughputs, "provisionedModelSummaries", maxResults=100)
            collector.add_completed_check("sdk_list_throughputs")
            
            if not throughputs:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-RATE-001", severity=Severity.LOW,
                    category="policy", cloud_env="aws",
                    file_path="live:bedrock:provisioned-throughput", line_number=0,
                    code_snippet="provisionedThroughputs=[]",
                    message="No provisioned throughput configured — using on-demand which may have rate variability",
                    recommendation="Consider provisioned throughput for production workloads to ensure consistent rate limits.",
                ))
            else:
                print(f"  [AUTH-AWS] Found {len(throughputs)} provisioned throughput(s)")
        except ClientError as e:
            collector.add_permission_issue("sdk_list_throughputs", "bedrock:ListProvisionedModelThroughputs", str(e))
            print(f"  [AUTH-AWS] Cannot list provisioned throughputs: {str(e)[:80]}")

    # ── Evaluation Jobs (Red-Team Detection) ────────────────────────
    def _check_evaluation_jobs_cli(self, collector: Collector):
        """Check if evaluation/red-team jobs exist."""
        print("  [AUTH-AWS] Auditing evaluation jobs (CLI)...")
        
        success, stdout, error = _safe_cli_call(
            ["aws", "bedrock", "list-evaluation-jobs", "--output", "json"]
        )
        
        if not success:
            if "not recognized" in error.lower() or "unknown" in error.lower():
                collector.add_skipped_check("evaluation_jobs_not_supported")
                return
            collector.add_permission_issue("list_evaluation_jobs", "bedrock:ListEvaluationJobs", error)
            collector.add_skipped_check("list_evaluation_jobs")
            return
        
        collector.add_completed_check("list_evaluation_jobs")
        
        try:
            data = json.loads(stdout)
            jobs = data.get("jobSummaries", [])
            
            if not jobs:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-EVAL-001", severity=Severity.MEDIUM,
                    category="evaluation", cloud_env="aws",
                    file_path="live:bedrock:evaluations", line_number=0,
                    code_snippet="evaluationJobs=[]",
                    message="No model evaluation jobs found — AI red-teaming not configured",
                    recommendation="Create evaluation jobs using human or automated evaluators to test model safety and accuracy before production.",
                ))
            else:
                print(f"  [AUTH-AWS] Found {len(jobs)} evaluation job(s)")
                # Check for recent evaluations
                completed = [j for j in jobs if j.get("status") == "COMPLETED"]
                if not completed:
                    collector.add_finding(Finding(
                        rule_id="AUTH-AWS-EVAL-002", severity=Severity.LOW,
                        category="evaluation", cloud_env="aws",
                        file_path="live:bedrock:evaluations", line_number=0,
                        code_snippet=f"evaluationJobs={len(jobs)} completed=0",
                        message="Evaluation jobs exist but none have completed successfully",
                        recommendation="Ensure evaluation jobs complete to get model safety metrics.",
                    ))
        except json.JSONDecodeError:
            pass

    def _check_fine_tuning_cli(self, collector: Collector):
        """Check fine-tuning/customization jobs for security."""
        print("  [AUTH-AWS] Auditing fine-tuning/customization jobs (CLI)...")
        
        # Check customization jobs
        success, stdout, error = _safe_cli_call(
            ["aws", "bedrock", "list-model-customization-jobs", "--output", "json"]
        )
        
        if success:
            collector.add_completed_check("list_customization_jobs")
            try:
                data = json.loads(stdout)
                jobs = data.get("modelCustomizationJobSummaries", [])
                
                if jobs:
                    print(f"  [AUTH-AWS] Found {len(jobs)} fine-tuning job(s)")
                    for job in jobs:
                        job_name = job.get("jobName", "unknown")
                        job_arn = job.get("jobArn", "")
                        
                        # Check for training data location (S3)
                        # Get job details
                        detail_success, detail_stdout, _ = _safe_cli_call(
                            ["aws", "bedrock", "get-model-customization-job", "--job-identifier", job_arn, "--output", "json"]
                        )
                        
                        if detail_success:
                            try:
                                detail = json.loads(detail_stdout)
                                training_data = detail.get("trainingDataConfig", {})
                                s3_uri = training_data.get("s3Uri", "")
                                
                                if s3_uri and "public" in s3_uri.lower():
                                    collector.add_finding(Finding(
                                        rule_id="AUTH-AWS-FT-001", severity=Severity.CRITICAL,
                                        category="model", cloud_env="aws",
                                        file_path=f"live:fine-tune:{job_name}", line_number=0,
                                        code_snippet=f"trainingDataS3Uri={s3_uri[:100]}",
                                        message=f"Fine-tuning job '{job_name}' uses potentially public S3 training data",
                                        recommendation="Ensure training data S3 bucket has strict access controls to prevent data poisoning.",
                                        owasp_llm="LLM03: Training Data Poisoning",
                                    ))
                                
                                # Check output KMS encryption
                                output_cfg = detail.get("outputDataConfig", {})
                                kms_key = output_cfg.get("kmsKeyId")
                                if not kms_key:
                                    collector.add_finding(Finding(
                                        rule_id="AUTH-AWS-FT-002", severity=Severity.HIGH,
                                        category="model", cloud_env="aws",
                                        file_path=f"live:fine-tune:{job_name}", line_number=0,
                                        code_snippet="outputDataConfig.kmsKeyId=null",
                                        message=f"Fine-tuning job '{job_name}' output not encrypted with KMS",
                                        recommendation="Specify kmsKeyId in outputDataConfig to encrypt fine-tuned model artifacts.",
                                    ))
                            except json.JSONDecodeError:
                                pass
            except json.JSONDecodeError:
                pass
        else:
            if "permission" in error.lower():
                collector.add_permission_issue("list_customization_jobs", "bedrock:ListModelCustomizationJobs", error)
            collector.add_skipped_check("list_customization_jobs")

    def _check_provisioned_throughput_cli(self, collector: Collector):
        """Check rate limits and provisioned throughput."""
        print("  [AUTH-AWS] Auditing provisioned model throughput (CLI)...")
        
        success, stdout, error = _safe_cli_call(
            ["aws", "bedrock", "list-provisioned-model-throughputs", "--output", "json"]
        )
        
        if not success:
            if "permission" in error.lower():
                collector.add_permission_issue("list_throughputs", "bedrock:ListProvisionedModelThroughputs", error)
            collector.add_skipped_check("list_throughputs")
            return
        
        collector.add_completed_check("list_throughputs")
        
        try:
            data = json.loads(stdout)
            throughputs = data.get("provisionedModelSummaries", [])
            
            if not throughputs:
                collector.add_finding(Finding(
                    rule_id="AUTH-AWS-RATE-001", severity=Severity.LOW,
                    category="policy", cloud_env="aws",
                    file_path="live:bedrock:provisioned-throughput", line_number=0,
                    code_snippet="provisionedThroughputs=[]",
                    message="No provisioned throughput configured — using on-demand which may have rate variability",
                    recommendation="Consider provisioned throughput for production workloads to ensure consistent rate limits and cost predictability.",
                ))
            else:
                print(f"  [AUTH-AWS] Found {len(throughputs)} provisioned throughput(s)")
        except json.JSONDecodeError:
            pass

    def _check_knowledge_bases_cli(self, collector: Collector):
        """Check knowledge bases security via CLI."""
        print("  [AUTH-AWS] Auditing knowledge bases (CLI)...")
        
        success, stdout, error = _safe_cli_call(
            ["aws", "bedrock-agent", "list-knowledge-bases", "--output", "json"]
        )
        
        if not success:
            if "permission" in error.lower():
                collector.add_permission_issue("list_knowledge_bases", "bedrock-agent:ListKnowledgeBases", error)
            collector.add_skipped_check("list_knowledge_bases")
            return
        
        collector.add_completed_check("list_knowledge_bases")
        
        try:
            data = json.loads(stdout)
            kbs = data.get("knowledgeBaseSummaries", [])
            
            if kbs:
                print(f"  [AUTH-AWS] Found {len(kbs)} knowledge base(s)")
                
                for kb in kbs:
                    kb_id = kb.get("knowledgeBaseId", "")
                    kb_name = kb.get("name", kb_id)
                    
                    # Get KB details
                    detail_success, detail_stdout, _ = _safe_cli_call(
                        ["aws", "bedrock-agent", "get-knowledge-base", "--knowledge-base-id", kb_id, "--output", "json"]
                    )
                    
                    if detail_success:
                        try:
                            detail = json.loads(detail_stdout)
                            kb_cfg = detail.get("knowledgeBase", {})
                            
                            # Check storage config
                            storage = kb_cfg.get("storageConfiguration", {})
                            storage_type = storage.get("type", "")
                            
                            # Check for encryption
                            if storage_type == "OPENSEARCH_SERVERLESS":
                                oss_cfg = storage.get("opensearchServerlessConfiguration", {})
                                # OpenSearch Serverless should have encryption
                                if not oss_cfg.get("collectionArn"):
                                    collector.add_finding(Finding(
                                        rule_id="AUTH-AWS-KB-003", severity=Severity.MEDIUM,
                                        category="storage", cloud_env="aws",
                                        file_path=f"live:kb:{kb_name}", line_number=0,
                                        code_snippet=f"storageType={storage_type}",
                                        message=f"Knowledge base '{kb_name}' storage configuration incomplete",
                                        recommendation="Ensure OpenSearch Serverless collection is properly configured with encryption.",
                                    ))
                            
                            # Check data sources
                            self._check_kb_data_sources_cli(kb_id, kb_name, collector)
                            
                        except json.JSONDecodeError:
                            pass
        except json.JSONDecodeError:
            pass

    def _check_kb_data_sources_cli(self, kb_id: str, kb_name: str, collector: Collector):
        """Check knowledge base data sources for security issues."""
        success, stdout, error = _safe_cli_call(
            ["aws", "bedrock-agent", "list-data-sources", "--knowledge-base-id", kb_id, "--output", "json"]
        )
        
        if not success:
            return
        
        try:
            data = json.loads(stdout)
            sources = data.get("dataSourceSummaries", [])
            
            for ds in sources:
                ds_id = ds.get("dataSourceId", "")
                ds_name = ds.get("name", ds_id)
                status = ds.get("status", "")
                
                # Get data source details
                detail_success, detail_stdout, _ = _safe_cli_call(
                    ["aws", "bedrock-agent", "get-data-source", 
                     "--knowledge-base-id", kb_id, 
                     "--data-source-id", ds_id, 
                     "--output", "json"]
                )
                
                if detail_success:
                    try:
                        detail = json.loads(detail_stdout)
                        ds_cfg = detail.get("dataSource", {}).get("dataSourceConfiguration", {})
                        
                        # Check S3 configuration
                        s3_cfg = ds_cfg.get("s3Configuration", {})
                        bucket_arn = s3_cfg.get("bucketArn", "")
                        
                        if bucket_arn:
                            bucket_name = bucket_arn.split(":::")[-1] if ":::" in bucket_arn else bucket_arn
                            
                            # Check if bucket allows public access
                            # (we can't directly check without S3 permissions, but flag if name suggests public)
                            if any(x in bucket_name.lower() for x in ["public", "open", "shared"]):
                                collector.add_finding(Finding(
                                    rule_id="AUTH-AWS-KB-004", severity=Severity.HIGH,
                                    category="storage", cloud_env="aws",
                                    file_path=f"live:kb:{kb_name}:ds:{ds_name}", line_number=0,
                                    code_snippet=f"s3Bucket={bucket_name}",
                                    message=f"Knowledge base data source uses bucket with potentially public naming: {bucket_name}",
                                    recommendation="Verify bucket has proper access controls. RAG data sources should never be publicly accessible.",
                                    owasp_llm="LLM03: Training Data Poisoning",
                                ))
                    except json.JSONDecodeError:
                        pass
        except json.JSONDecodeError:
            pass
