"""Map gateway traces and security findings to framework control breaches."""

from __future__ import annotations

from typing import Any

ControlSignalSpec = dict[str, Any]

CONTROL_SIGNAL_MAP: dict[tuple[str, str], ControlSignalSpec] = {
    ("nist_rmf", "ID.AM"): {
        "finding_kw": ["inventory", "mcp", "agent", "model", "tool", "surface"],
        "trace_kw": ["shadow", "unknown", "tool"],
        "runtime_any": True,
    },
    ("nist_rmf", "ID.RA"): {
        "finding_kw": ["injection", "jailbreak", "risk", "owasp", "abuse", "malicious"],
        "trace_kw": ["prompt_injection", "jailbreak", "malicious", "adaptive"],
        "runtime_any": False,
    },
    ("nist_rmf", "PR.DS"): {
        "finding_kw": ["secret", "credential", "pii", "leak", "key", "token", "exfil"],
        "trace_kw": ["pii", "secret", "credential", "exfil"],
        "runtime_any": False,
    },
    ("nist_rmf", "DE.CM"): {
        "finding_kw": ["monitor", "log", "trace", "telemetry"],
        "trace_kw": ["blocked", "policy", "detection", "guard"],
        "runtime_any": True,
    },
    ("nist_rmf", "RS.MI"): {
        "finding_kw": ["incident", "breach", "quarantine"],
        "trace_kw": ["blocked", "quarantine", "critical"],
        "runtime_any": False,
    },
    ("hipaa", "164.312(a)(1)"): {
        "finding_kw": ["access", "auth", "credential", "phi", "pii"],
        "trace_kw": ["pii", "credential", "unauthorized"],
        "runtime_any": False,
    },
    ("hipaa", "164.312(b)"): {
        "finding_kw": ["audit", "log", "monitor"],
        "trace_kw": ["trace", "blocked", "detection"],
        "runtime_any": True,
    },
    ("hipaa", "164.308(a)(4)"): {
        "finding_kw": ["policy", "training", "governance"],
        "trace_kw": ["policy", "blocked"],
        "runtime_any": False,
    },
    ("iso27001", "A.8.1"): {
        "finding_kw": ["asset", "inventory", "model", "mcp"],
        "trace_kw": ["shadow", "unknown"],
        "runtime_any": True,
    },
    ("iso27001", "A.8.2"): {
        "finding_kw": ["classification", "label", "data"],
        "trace_kw": ["pii", "sensitive"],
        "runtime_any": False,
    },
    ("iso27001", "A.5.7"): {
        "finding_kw": ["threat", "intelligence", "risk"],
        "trace_kw": ["malicious", "jailbreak", "injection"],
        "runtime_any": False,
    },
    ("soc2", "CC6.1"): {
        "finding_kw": ["access", "auth", "credential", "secret"],
        "trace_kw": ["credential", "unauthorized"],
        "runtime_any": False,
    },
    ("soc2", "CC7.2"): {
        "finding_kw": ["monitor", "detect", "alert"],
        "trace_kw": ["detection", "blocked", "policy"],
        "runtime_any": True,
    },
    ("soc2", "CC8.1"): {
        "finding_kw": ["change", "deploy", "release"],
        "trace_kw": ["agent_control"],
        "runtime_any": False,
    },
    ("eu_ai_act", "Art-9"): {
        "finding_kw": ["risk", "assessment", "governance"],
        "trace_kw": ["malicious", "high", "critical"],
        "runtime_any": False,
    },
    ("eu_ai_act", "Art-10"): {
        "finding_kw": ["data", "quality", "training", "bias"],
        "trace_kw": ["pii", "toxicity"],
        "runtime_any": False,
    },
    ("eu_ai_act", "Art-15"): {
        "finding_kw": ["robust", "security", "attack", "injection"],
        "trace_kw": ["jailbreak", "prompt_injection", "blocked"],
        "runtime_any": False,
    },
    ("iso_42001", "A.5.1"): {
        "finding_kw": ["policy", "governance", "leadership"],
        "trace_kw": ["policy"],
        "runtime_any": False,
    },
    ("iso_42001", "A.6.2"): {
        "finding_kw": ["risk", "assessment", "treatment"],
        "trace_kw": ["risk", "threat", "malicious"],
        "runtime_any": False,
    },
    ("iso_42001", "A.8.1"): {
        "finding_kw": ["operation", "deploy", "agent"],
        "trace_kw": ["tool", "agent_control"],
        "runtime_any": True,
    },
    ("iso_42001", "A.8.3"): {
        "finding_kw": ["monitor", "log", "observe"],
        "trace_kw": ["trace", "detection", "blocked"],
        "runtime_any": True,
    },
    ("iso_42001", "A.9.4"): {
        "finding_kw": ["incident", "response", "recovery"],
        "trace_kw": ["blocked", "quarantine", "critical"],
        "runtime_any": False,
    },
}


def _finding_blob(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("title", ""),
        finding.get("category", ""),
        finding.get("rule_id", ""),
        finding.get("owasp_llm", ""),
        finding.get("description", ""),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _trace_blob(trace: dict[str, Any]) -> str:
    tags = trace.get("detection_tags") or []
    tag_text = " ".join(str(t) for t in tags)
    parts = [
        tag_text,
        trace.get("threat_level", ""),
        trace.get("model_name", ""),
        trace.get("trace_type", ""),
        trace.get("status", ""),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _severity_rank(value: str | None) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get((value or "").lower(), 0)


def resolve_control_breach(
    framework: str,
    control: str,
    findings: list[dict[str, Any]],
    traces: list[dict[str, Any]],
) -> dict[str, Any] | None:
    spec = CONTROL_SIGNAL_MAP.get((framework, control))
    if not spec:
        return None

    finding_kw = spec.get("finding_kw", [])
    trace_kw = spec.get("trace_kw", [])
    runtime_any = bool(spec.get("runtime_any"))

    best: dict[str, Any] | None = None
    best_rank = 0

    for finding in findings:
        blob = _finding_blob(finding)
        if not blob:
            continue
        matched = any(kw in blob for kw in finding_kw)
        if not matched and finding.get("severity") in ("critical", "high") and finding_kw:
            matched = any(kw in blob for kw in ("secret", "injection", "risk", "policy"))
        if matched:
            rank = _severity_rank(finding.get("severity"))
            if rank >= best_rank:
                best_rank = rank
                best = {
                    "severity": finding.get("severity", "medium"),
                    "evidence": finding.get("title") or finding.get("rule_id") or "Security finding",
                    "source": finding.get("source") or "finding",
                    "control": control,
                }

    for trace in traces:
        blob = _trace_blob(trace)
        if not blob and not runtime_any:
            continue
        matched = runtime_any and bool(blob)
        if not matched:
            matched = any(kw in blob for kw in trace_kw)
        if trace.get("blocked_by_policy"):
            matched = matched or "blocked" in trace_kw or "policy" in trace_kw
        if matched:
            rank = _severity_rank(trace.get("threat_level")) + (1 if trace.get("blocked_by_policy") else 0)
            if rank >= best_rank:
                best_rank = rank
                tags = trace.get("detection_tags") or []
                tag_label = ", ".join(str(t) for t in tags[:4]) if tags else trace.get("model_name", "runtime")
                best = {
                    "severity": trace.get("threat_level") or ("high" if trace.get("blocked_by_policy") else "medium"),
                    "evidence": f"Gateway/runtime: {tag_label}",
                    "source": "gateway",
                    "control": control,
                }

    return best
