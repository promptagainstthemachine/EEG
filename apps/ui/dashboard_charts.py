"""Dashboard chart data builders."""

from __future__ import annotations

from datetime import timedelta

from django.db.models import Count, QuerySet
from django.utils import timezone

from apps.security.threat_categories import count_bucket_from_qs

SEVERITY_ORDER = (
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
)

CATEGORY_BUCKETS = (
    ("command_injection", "Command Injection"),
    ("prompt_injection", "Prompt Injection"),
    ("secrets", "Secrets"),
    ("mcp", "MCP"),
    ("supply_chain", "Supply Chain"),
    ("agent_control", "Agent Control"),
)

THREAT_RADAR_BUCKETS = (
    ("prompt_injection", "Prompt Injection"),
    ("command_injection", "Command Injection"),
    ("secrets", "Secret Exposure"),
    ("mcp", "MCP Security"),
    ("supply_chain", "Supply Chain"),
    ("agent_control", "Agent Control"),
)


def _severity_counts(open_findings_qs: QuerySet) -> dict[str, int]:
    """Aggregate open findings by severity (case-insensitive)."""
    buckets = {key: 0 for key, _ in SEVERITY_ORDER}
    for row in open_findings_qs.values("severity").annotate(count=Count("id")):
        raw = (row["severity"] or "").lower()
        count = row["count"]
        if raw in buckets:
            buckets[raw] += count
        else:
            buckets["medium"] += count
    return buckets


def build_severity_distribution_from_counts(counts: dict[str, int]) -> dict:
    """Severity doughnut from a pre-aggregated counts map."""
    normalized = {key: 0 for key, _ in SEVERITY_ORDER}
    for key, value in (counts or {}).items():
        raw = (key or "").lower()
        n = int(value or 0)
        if raw in normalized:
            normalized[raw] += n
        elif n:
            normalized["medium"] += n
    labels: list[str] = []
    values: list[int] = []
    keys: list[str] = []
    for key, label in SEVERITY_ORDER:
        value = normalized[key]
        if value > 0:
            labels.append(label)
            values.append(value)
            keys.append(key)
    total = sum(normalized.values())
    return {
        "labels": labels,
        "values": values,
        "keys": keys,
        "counts": normalized,
        "has_data": total > 0,
        "total": total,
    }


def build_severity_distribution(open_findings_qs: QuerySet) -> dict:
    """Open findings by severity for the doughnut chart."""
    return build_severity_distribution_from_counts(_severity_counts(open_findings_qs))


def runtime_threat_bucket(row: dict) -> str | None:
    """Map a runtime finding dict onto a threat-radar / category bucket."""
    meta = row.get("metadata") or {}
    tags = meta.get("detection_tags") or row.get("risk_signals") or []
    tag_blob = " ".join(str(t) for t in tags).lower()
    tt = str(row.get("trace_type") or "").strip()
    blob = " ".join(
        [
            str(row.get("category") or ""),
            str(row.get("title") or ""),
            str(row.get("rule_id") or ""),
            tt,
            tag_blob,
        ]
    ).lower()

    # Prefer explicit gateway surface types so agent_control is not lost to
    # loose keyword matches (e.g. "control" never matched the old buckets).
    if tt in ("agent_control", "agent_action"):
        return "agent_control"
    if tt == "llm_call":
        return "prompt_injection"
    if tt == "mcp_tool":
        return "mcp"
    if tt == "tool_call":
        return "command_injection"
    if tt in ("retrieval", "embedding"):
        return "supply_chain"

    if any(tok in blob for tok in ("secret", "credential", "api_key", "api-key", "token leak")):
        return "secrets"
    if "mcp" in blob:
        return "mcp"
    if any(
        tok in blob
        for tok in ("command injection", "shell", "subprocess", "os.system", "code injection")
    ):
        return "command_injection"
    if any(
        tok in blob
        for tok in (
            "prompt injection",
            "jailbreak",
            "toxicity",
            "llm_call",
            "blocked prompt",
            "blocked ",
        )
    ):
        return "prompt_injection"
    if any(tok in blob for tok in ("supply", "cve", "dependency", "retrieval", "rag")):
        return "supply_chain"
    if "agent_control" in blob or "agent control" in blob:
        return "agent_control"

    # Keep gateway detections visible on the map/category charts.
    if tt or str(row.get("source") or "").lower() == "runtime":
        return "agent_control"
    return None


def count_runtime_buckets(runtime_rows: list[dict]) -> dict[str, int]:
    """Count runtime findings per threat bucket."""
    counts = {bucket_id: 0 for bucket_id, _ in CATEGORY_BUCKETS}
    for row in runtime_rows or []:
        bucket = runtime_threat_bucket(row)
        if bucket and bucket in counts:
            counts[bucket] += 1
    return counts


def build_category_distribution_from_counts(bucket_counts: dict[str, int]) -> dict:
    """Category bar chart from pre-aggregated threat-bucket counts."""
    labels: list[str] = []
    values: list[int] = []
    keys: list[str] = []
    for bucket_id, label in CATEGORY_BUCKETS:
        value = int((bucket_counts or {}).get(bucket_id, 0) or 0)
        if value > 0:
            labels.append(label)
            values.append(value)
            keys.append(bucket_id)
    total = sum(values)
    return {
        "labels": labels,
        "values": values,
        "keys": keys,
        "has_data": total > 0,
        "total": total,
    }


def build_category_distribution(open_findings_qs: QuerySet) -> dict:
    """Open findings by threat-radar category for the bar chart."""
    bucket_counts = {
        bucket_id: count_bucket_from_qs(open_findings_qs, bucket_id)
        for bucket_id, _ in CATEGORY_BUCKETS
    }
    return build_category_distribution_from_counts(bucket_counts)


def build_security_coverage(
    *,
    open_findings_qs: QuerySet,
    prompt_injection_count: int,
    command_injection_count: int,
    secrets_count: int,
    mcp_count: int,
    supply_chain_count: int,
    config_count: int,
    owasp_count: int,
    category_map: dict[str, int],
    runtime_protection_enabled: bool,
    auto_redteam_enabled: bool,
    cloud_project_count: int,
) -> dict:
    """EEG product capabilities for the dashboard security coverage map."""
    from django.db.models import Q

    model_count = sum(
        count
        for key, count in category_map.items()
        if key
        and any(
            token in key.lower()
            for token in ("model", "artifact", "pickle", "serialization", "safetensors")
        )
    )
    cloud_finding_count = open_findings_qs.filter(
        Q(category__icontains="cloud")
        | Q(category__icontains="aws")
        | Q(category__icontains="azure")
        | Q(category__icontains="gcp")
        | Q(category__icontains="bedrock")
        | Q(category__icontains="vertex")
        | Q(rule_id__icontains="CLOUD")
        | Q(rule_id__icontains="AWS-")
        | Q(rule_id__icontains="AZURE-")
        | Q(rule_id__icontains="GCP-")
    ).count()
    probe_surface_count = config_count + owasp_count

    services = [
        {
            "id": "code_sast",
            "name": "Code & AI SAST",
            "description": "Shift-left static rules for prompt injection, command execution, and unsafe LLM/tool chains.",
            "count": prompt_injection_count + command_injection_count,
            "href": "/findings/?threat=prompt_injection",
            "status_label": "In Full Scan",
            "accent": "#58a6ff",
        },
        {
            "id": "agent_mcp",
            "name": "Agent & MCP Forensics",
            "description": "Agent-audit packs for MCP servers, hooks, browser surfaces, and autonomous tool misuse.",
            "count": mcp_count,
            "href": "/findings/?threat=mcp",
            "status_label": "In Full Scan",
            "accent": "#a371f7",
        },
        {
            "id": "secrets",
            "name": "Secrets & Credentials",
            "description": "Hard-coded API keys, tokens, and credential leakage across code and agent configs.",
            "count": secrets_count,
            "href": "/findings/?threat=secrets",
            "status_label": "In Full Scan",
            "accent": "#d29922",
        },
        {
            "id": "supply_chain",
            "name": "Supply Chain & CVE Intel",
            "description": "Dependency audit with OSV, NVD, and GHSA correlation during Full Scan.",
            "count": supply_chain_count,
            "href": "/findings/?threat=supply_chain",
            "status_label": "In Full Scan",
            "accent": "#3fb950",
        },
        {
            "id": "model_artifacts",
            "name": "Model Artifacts",
            "description": "Unsafe serialization and malicious payloads in model weights and artifact files.",
            "count": model_count,
            "href": "/findings/?q=model",
            "status_label": "In Full Scan",
            "accent": "#f778ba",
        },
        {
            "id": "runtime_gateway",
            "name": "Compliance",
            "description": "Framework posture from findings and gateway traces (NIST, ISO 42001, EU AI Act, and more).",
            "count": None,
            "href": "/compliance/",
            "status_label": "Enabled" if runtime_protection_enabled else "Available",
            "accent": "#39d353",
        },
        {
            "id": "endpoint_probes",
            "name": "Endpoint & MCP Probes",
            "description": "Live HTTP, gateway, and MCP surface checks for exposed AI endpoints.",
            "count": probe_surface_count,
            "href": "/findings/?category=config",
            "status_label": "In Full Scan",
            "accent": "#79c0ff",
        },
        {
            "id": "cloud_posture",
            "name": "Cloud AI Posture",
            "description": "Live AWS Bedrock, Azure Foundry/OpenAI, and GCP Vertex auth & config checks.",
            "count": cloud_finding_count,
            "href": "/projects/",
            "status_label": (
                f"{cloud_project_count} cloud project{'s' if cloud_project_count != 1 else ''}"
                if cloud_project_count
                else "Add AWS/Azure/GCP project"
            ),
            "accent": "#ff7b72",
        },
    ]
    if auto_redteam_enabled:
        services.append(
            {
                "id": "red_team",
                "name": "Auto Red Team",
                "description": "Adversarial probes against API endpoints when enabled for your organization.",
                "count": None,
                "href": "/findings/?category=owasp",
                "status_label": "Enabled",
                "accent": "#f85149",
            },
        )

    open_total = sum(s["count"] or 0 for s in services)
    return {
        "services": services,
        "has_findings": open_total > 0,
        "open_total": open_total,
    }


SCAN_TYPE_BUCKETS = (
    ("full", "Full Scan"),
    ("code_security", "Code Security"),
    ("dependency", "Dependency Audit"),
    ("model_artifact", "Model Artifact"),
    ("agent_forensics", "Agent Forensics"),
    ("redteam", "Red Team"),
)

GATEWAY_ACTIVITY_BUCKETS = (
    ("llm_call", "Prompts"),
    ("blocked", "Blocked"),
    ("tool_call", "Tools"),
    ("mcp_tool", "MCP"),
    ("retrieval", "RAG"),
    ("agent_control", "Controls"),
)


def build_scan_distribution(scan_runs_qs: QuerySet, *, days: int = 90) -> dict:
    """Recent scan runs grouped by scan type for the dashboard bar chart."""
    days = max(1, min(int(days), 90))
    cutoff = timezone.now() - timedelta(days=days)
    qs = scan_runs_qs.filter(created_at__gte=cutoff)
    labels: list[str] = []
    values: list[int] = []
    keys: list[str] = []
    for key, label in SCAN_TYPE_BUCKETS:
        value = qs.filter(scan_type=key).count()
        if value > 0:
            labels.append(label)
            values.append(value)
            keys.append(key)
    total = sum(values)
    return {
        "labels": labels,
        "values": values,
        "keys": keys,
        "has_data": total > 0,
        "total": total,
        "days": days,
    }


def build_activity_distribution(
    organization,
    scan_runs_qs: QuerySet,
    *,
    days: int = 90,
    project=None,
) -> dict:
    """
    Combined scan + gateway activity for the dashboard activity chart.

    Prefer showing real gateway traffic when scans are absent so the panel
    is not an empty “run Full Scan” dead-end.
    Gateway activity is scoped to ``project`` when provided; with no project,
    only scan buckets (already filtered by the caller) are shown.
    """
    from apps.security.models import AITrace

    days = max(1, min(int(days), 90))
    cutoff = timezone.now() - timedelta(days=days)

    labels: list[str] = []
    values: list[int] = []
    keys: list[str] = []
    kinds: list[str] = []

    scans = scan_runs_qs.filter(created_at__gte=cutoff)
    for key, label in SCAN_TYPE_BUCKETS:
        value = scans.filter(scan_type=key).count()
        if value > 0:
            labels.append(label)
            values.append(value)
            keys.append(key)
            kinds.append("scan")

    if organization is not None and project is not None:
        traces = AITrace.objects.filter(
            organization=organization,
            project=project,
            started_at__gte=cutoff,
        )
        for key, label in GATEWAY_ACTIVITY_BUCKETS:
            if key == "blocked":
                value = traces.filter(status=AITrace.Status.BLOCKED).count()
            else:
                value = traces.filter(trace_type=key).count()
            if value > 0:
                labels.append(label)
                values.append(value)
                keys.append(key)
                kinds.append("gateway")

    total = sum(values)
    return {
        "labels": labels,
        "values": values,
        "keys": keys,
        "kinds": kinds,
        "has_data": total > 0,
        "total": total,
        "days": days,
        "scan_total": sum(v for v, k in zip(values, kinds) if k == "scan"),
        "gateway_total": sum(v for v, k in zip(values, kinds) if k == "gateway"),
    }


def build_threat_radar_from_counts(bucket_counts: dict[str, int]) -> dict:
    """Threat radar spider chart from pre-aggregated bucket counts."""
    labels: list[str] = []
    values: list[int] = []
    keys: list[str] = []
    for bucket_id, label in THREAT_RADAR_BUCKETS:
        labels.append(label)
        values.append(int((bucket_counts or {}).get(bucket_id, 0) or 0))
        keys.append(bucket_id)
    max_val = max(values) if values else 0
    return {
        "labels": labels,
        "values": values,
        "keys": keys,
        "has_data": max_val > 0,
        "scale_max": max(5, int(max_val * 1.2) + 1) if max_val else 5,
    }


def build_threat_radar(open_findings_qs: QuerySet) -> dict:
    """Threat radar spider chart series (all buckets, including zeros)."""
    bucket_counts = {
        bucket_id: count_bucket_from_qs(open_findings_qs, bucket_id)
        for bucket_id, _ in THREAT_RADAR_BUCKETS
    }
    return build_threat_radar_from_counts(bucket_counts)
