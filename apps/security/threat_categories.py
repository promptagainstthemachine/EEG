"""Threat radar bucket definitions (dashboard counts + drill-down)."""

from __future__ import annotations

from typing import Dict, List, Tuple

from django.db.models import Q, QuerySet

from apps.security.finding_filters import exclude_vuln_intel_findings
from apps.security.models import SecurityFinding

# Categories that must NOT be treated as LLM prompt injection
_COMMAND_INJECTION_MARKERS = (
    "command_injection",
    "sql_injection",
    "code_injection",
    "shell_injection",
    "os_command",
)

_COMMAND_TEXT_MARKERS = (
    "command injection",
    "os command",
    "command execution",
    "code injection",
    "shell injection",
    "shell=true",
    "subprocess",
    "os.system",
    "arbitrary os command",
)

_PROMPT_TEXT_MARKERS = (
    "prompt injection",
    "jailbreak",
    "system prompt",
    "system message",
    "goal hijack",
    "injectable system prompt",
)

_COMMAND_RULE_MARKERS = (
    "COMMAND-INJ",
    "CMD-INJ",
    "COMMAND-INJECTION",
    "MCP-COMMAND",
    "AGENT-001",
    "AGENT-026",
    "AGENT-035",
)

_COMMAND_INJECTION_EXCLUDE_Q = (
    Q(category__icontains="command_injection")
    | Q(category__icontains="sql_injection")
    | Q(category__icontains="code_injection")
    | Q(category__icontains="shell_injection")
    | Q(title__icontains="command injection")
    | Q(title__icontains="os command")
    | Q(title__icontains="command execution")
    | Q(title__icontains="code injection")
    | Q(title__icontains="subprocess")
    | Q(title__icontains="os.system")
    | Q(description__icontains="command injection")
    | Q(description__icontains="os command")
    | Q(description__icontains="command execution")
    | Q(rule_id__icontains="COMMAND-INJ")
    | Q(rule_id__icontains="CMD-INJ")
    | Q(rule_id__icontains="command-injection")
    | Q(rule_id__icontains="mcp-command")
    | Q(cwe__icontains="CWE-78")
)

# bucket_id -> (display label, category keys summed on dashboard, extra Q filters)
# Order matters for bucket_for_finding: more specific buckets first.
THREAT_BUCKETS: Dict[str, Dict] = {
    "command_injection": {
        "label": "Command Injection",
        "keys": ("command_injection", "command"),
        "extra_q": (
            Q(category__iexact="command_injection")
            | Q(category__icontains="command_injection")
            | Q(category__icontains="sql_injection")
            | Q(category__icontains="code_injection")
            | Q(category__icontains="shell_injection")
            | Q(title__icontains="command injection")
            | Q(title__icontains="os command")
            | Q(title__icontains="command execution")
            | Q(title__icontains="code injection")
            | Q(title__icontains="subprocess")
            | Q(title__icontains="os.system")
            | Q(description__icontains="command injection")
            | Q(description__icontains="os command")
            | Q(description__icontains="command execution")
            | Q(rule_id__icontains="COMMAND-INJ")
            | Q(rule_id__icontains="CMD-INJ")
            | Q(rule_id__icontains="command-injection")
            | Q(rule_id__icontains="mcp-command")
            | Q(cwe__icontains="CWE-78")
        ),
    },
    "prompt_injection": {
        "label": "Prompt Injection",
        "keys": ("prompt_injection", "prompt"),
        "exclude_q": _COMMAND_INJECTION_EXCLUDE_Q,
        "extra_q": (
            Q(category__iexact="prompt_injection")
            | Q(category__iexact="jailbreak")
            | Q(category__icontains="jailbreak")
            | Q(category__icontains="redteam")
            | Q(title__icontains="prompt injection")
            | Q(title__icontains="jailbreak")
            | Q(title__icontains="system prompt")
            | Q(description__icontains="prompt injection")
            | Q(description__icontains="jailbreak")
        ),
    },
    "secrets": {
        "label": "Secret Exposure",
        "keys": ("secrets", "credential"),
        "extra_q": (
            Q(category__icontains="secret")
            | Q(category__icontains="credential")
            | Q(rule_id__icontains="SECRET")
            | Q(title__icontains="secret")
            | Q(title__icontains="api key")
            | Q(title__icontains="password")
            | Q(title__icontains="credential")
        ),
    },
    "mcp": {
        "label": "MCP Security",
        "keys": ("mcp",),
        "extra_q": Q(category__icontains="mcp"),
    },
    "supply_chain": {
        "label": "Supply Chain",
        "keys": ("supply_chain", "dependency"),
        "extra_q": (
            Q(category__icontains="supply")
            | Q(category__icontains="chain")
            | Q(category__icontains="dependency")
            | Q(category__icontains="third_party")
        ),
    },
    "agent_control": {
        "label": "Agent Control",
        "keys": ("agent_control", "runtime_agent_control", "agent_action"),
        "extra_q": (
            Q(category__icontains="agent_control")
            | Q(category__icontains="agent_action")
            | Q(category__icontains="runtime_agent")
            | Q(title__icontains="agent control")
            | Q(rule_id__icontains="runtime.agent_control")
            | Q(rule_id__icontains="agent_control")
        ),
    },
}


def _finding_text_blob(finding) -> str:
    parts = [
        getattr(finding, "category", None) or "",
        getattr(finding, "title", None) or "",
        getattr(finding, "description", None) or "",
        getattr(finding, "code_snippet", None) or "",
        getattr(finding, "rule_id", None) or "",
        getattr(finding, "cwe", None) or "",
    ]
    return " ".join(parts).lower()


def _text_fields(finding) -> Tuple[str, str, str]:
    cat = (getattr(finding, "category", None) or "").lower()
    title = (getattr(finding, "title", None) or "").lower()
    rule = (getattr(finding, "rule_id", None) or "").upper()
    return cat, title, rule


def _has_prompt_injection_text(blob: str) -> bool:
    return any(marker in blob for marker in _PROMPT_TEXT_MARKERS)


def _has_command_injection_text(blob: str) -> bool:
    return any(marker in blob for marker in _COMMAND_TEXT_MARKERS)


def is_command_injection_finding(finding) -> bool:
    """True for OS/shell/SQL/code command injection (not LLM prompt injection)."""
    cat, title, rule = _text_fields(finding)
    blob = _finding_text_blob(finding)
    cwe = (getattr(finding, "cwe", None) or "").upper()

    if any(marker in cat for marker in _COMMAND_INJECTION_MARKERS):
        return True
    if "CWE-78" in cwe:
        return True
    if _has_command_injection_text(blob):
        return True
    if any(marker in rule for marker in _COMMAND_RULE_MARKERS):
        return True
    # Mis-tagged static rules: category "prompt" but message is OS/code injection.
    if cat == "prompt" and _has_command_injection_text(blob) and not _has_prompt_injection_text(
        blob
    ):
        return True
    if cat == "injection" and _has_command_injection_text(blob):
        return True
    return False


def is_prompt_injection_finding(finding) -> bool:
    """True for LLM prompt injection / jailbreak (excludes command injection)."""
    if is_command_injection_finding(finding):
        return False

    cat, title, rule = _text_fields(finding)
    blob = _finding_text_blob(finding)

    if cat in ("prompt_injection", "jailbreak", "redteam"):
        return True
    if any(t in cat for t in ("prompt_injection", "jailbreak", "redteam")):
        return True
    if _has_prompt_injection_text(blob):
        return True
    if "PROMPT" in rule and "INJ" in rule:
        return True
    # Legacy mis-tag: category "prompt" only when text is clearly LLM prompt-related.
    if cat == "prompt" and _has_prompt_injection_text(blob):
        return True
    if cat == "injection" and _has_prompt_injection_text(blob):
        return True
    return False


def count_bucket_from_qs(qs: QuerySet, bucket_id: str) -> int:
    """Count open findings in a threat radar bucket (matches drill-down filter)."""
    return filter_findings_by_bucket(qs, bucket_id).count()


def count_bucket(category_map: Dict[str, int], bucket_id: str) -> int:
    """Sum dashboard counts for a bucket from aggregated category_map."""
    spec = THREAT_BUCKETS.get(bucket_id)
    if not spec:
        return 0
    total = sum(category_map.get(key, 0) for key in spec["keys"])
    if total:
        return total
    for cat, n in category_map.items():
        cat_l = (cat or "").lower()
        for key in spec["keys"]:
            if key in cat_l:
                total += n
    return total


def filter_findings_by_bucket(qs: QuerySet, bucket_id: str) -> QuerySet:
    """Filter open code findings for a threat radar bucket."""
    spec = THREAT_BUCKETS.get(bucket_id)
    if not spec:
        return qs.none()

    if bucket_id == "command_injection":
        return qs.filter(spec["extra_q"]).distinct()

    if bucket_id == "prompt_injection":
        return qs.filter(spec["extra_q"]).exclude(spec["exclude_q"]).distinct()

    q = Q()
    for key in spec["keys"]:
        q |= Q(category__iexact=key) | Q(category__icontains=key)
    q |= spec["extra_q"]
    result = qs.filter(q)
    exclude = spec.get("exclude_q")
    if exclude is not None:
        result = result.exclude(exclude)
    return result.distinct()


def open_findings_for_bucket(organization, bucket_id: str, *, limit: int = 25) -> QuerySet:
    qs = exclude_vuln_intel_findings(
        SecurityFinding.objects.filter(
            organization=organization,
            status__in=[
                SecurityFinding.Status.OPEN,
                SecurityFinding.Status.ACKNOWLEDGED,
                SecurityFinding.Status.IN_PROGRESS,
            ],
        ).select_related("project")
    )
    return filter_findings_by_bucket(qs, bucket_id).order_by(
        "-severity", "-first_seen_at"
    )[:limit]


def bucket_choices() -> List[Tuple[str, str]]:
    return [(bid, spec["label"]) for bid, spec in THREAT_BUCKETS.items()]


def finding_matches_bucket(finding, bucket_id: str) -> bool:
    """True if a finding instance belongs to a threat radar bucket (no DB)."""
    if bucket_id == "command_injection":
        return is_command_injection_finding(finding)
    if bucket_id == "prompt_injection":
        return is_prompt_injection_finding(finding)

    spec = THREAT_BUCKETS.get(bucket_id)
    if not spec:
        return False
    cat, title, rule = _text_fields(finding)
    for key in spec["keys"]:
        key_l = key.lower()
        if cat == key_l or key_l in cat:
            return True
    if bucket_id == "secrets":
        return (
            any(t in cat for t in ("secret", "credential"))
            or "SECRET" in rule
            or any(t in title for t in ("secret", "api key", "password", "credential"))
        )
    if bucket_id == "mcp":
        return "mcp" in cat
    if bucket_id == "supply_chain":
        return any(
            t in cat
            for t in ("supply", "chain", "dependency", "third_party")
        )
    return False


def bucket_for_finding(finding) -> str | None:
    for bucket_id in THREAT_BUCKETS:
        if finding_matches_bucket(finding, bucket_id):
            return bucket_id
    return None
