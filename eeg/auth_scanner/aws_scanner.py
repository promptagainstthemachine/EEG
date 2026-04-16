"""
EEG - AWS Authenticated Scanner
Live audit of Bedrock agents, guardrails, knowledge bases, model logging,
IAM, and network.

import sys
from typing import List, Dict, Optional
from eeg.collector import Collector, Finding, Severity

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


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
    """Live audit of AWS Bedrock resources using authenticated API calls."""

    def __init__(self, auth_context: dict):
        self.auth_context = auth_context
        self.profile = auth_context.get("profile")
        self.region = auth_context.get("region", "us-east-1")

    def scan(self, collector: Collector):
        if not HAS_BOTO3:
            print("  [AUTH-AWS] boto3 not installed — skipping authenticated scan")
            return

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
        except (ClientError, NoCredentialsError) as e:
            print(f"  [AUTH-AWS] ✗ Authentication failed: {e}")
            return

        bedrock = session.client("bedrock")
        bedrock_agent = session.client("bedrock-agent")
        s3 = session.client("s3")
        iam = session.client("iam")

        self._check_guardrails(bedrock, collector)
        self._check_agents(bedrock_agent, bedrock, collector)
        self._check_knowledge_bases(bedrock_agent, s3, collector)
        self._check_model_invocation_logging(bedrock, collector)
        self._check_iam_policies(iam, collector)

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
