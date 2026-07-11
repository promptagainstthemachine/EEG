"""Real-time compliance audit orchestration for EEG OSS."""

from __future__ import annotations

from typing import Any

from eeg.compliance.framework_evaluate import evaluate as evaluate_framework_gaps


def _infer_gate_evidence(
    findings: list[dict[str, Any]],
    traces: list[dict[str, Any]],
) -> dict[str, bool]:
    has_high = any(f.get("severity") in ("critical", "high") for f in findings)
    has_blocks = any(
        t.get("blocked_by_policy")
        or t.get("status") == "blocked"
        or (t.get("metadata") or {}).get("blocked_by_policy")
        for t in traces
    )
    has_runtime = bool(traces)
    has_incident = any(
        float(t.get("risk_score") or 0) >= 0.8
        or t.get("threat_level") in ("critical", "high")
        for t in traces
    )
    return {
        "domain_and_data_coverage": not has_high,
        "uncertainty_handling": not has_high,
        "fallback_and_degraded_mode": has_blocks or not has_high,
        "monitoring_and_observability": has_runtime,
        "human_escalation_and_override": has_blocks,
        "incident_response_and_recovery": not has_incident,
        "accountability_signoff": not has_high,
        "post_release_review_plan": has_runtime,
    }


def _release_verdict(evidence: dict[str, bool]) -> dict[str, Any]:
    passed = sum(1 for v in evidence.values() if v)
    total = max(len(evidence), 1)
    ratio = passed / total
    if ratio >= 0.85:
        verdict = "go"
    elif ratio >= 0.55:
        verdict = "conditional_go"
    else:
        verdict = "no_go"
    return {
        "verdict": verdict,
        "gates_passed": passed,
        "gates_total": total,
        "evidence": evidence,
        "readiness_score": round(100.0 * ratio, 1),
    }


def run_realtime_compliance_audit(
    *,
    findings: list[dict[str, Any]] | None = None,
    traces: list[dict[str, Any]] | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    findings = findings or []
    traces = traces or []
    framework_audit = evaluate_framework_gaps(
        findings=findings, traces=traces, frameworks=frameworks
    )
    evidence = _infer_gate_evidence(findings, traces)
    release_audit = _release_verdict(evidence)
    gate_ready = (
        100.0
        if release_audit["verdict"] == "go"
        else 60.0
        if release_audit["verdict"] == "conditional_go"
        else 20.0
    )
    composite = round(
        (float(framework_audit["compliance_score"]) + gate_ready) / 2.0,
        1,
    )
    return {
        "audit_type": "realtime",
        "composite_score": composite,
        "framework_audit": framework_audit,
        "release_gate_audit": release_audit,
        "signals": {
            "findings_count": len(findings),
            "traces_count": len(traces),
        },
    }
