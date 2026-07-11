"""Structured compliance posture cards for OSS dashboard APIs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from eeg.compliance.framework_evaluate import _DISPLAY, _load_framework, evaluate


def build_posture_dashboard(
    *,
    findings: list[dict[str, Any]] | None = None,
    traces: list[dict[str, Any]] | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    findings = findings or []
    traces = traces or []
    frameworks = frameworks or list(_DISPLAY.keys())

    raw = evaluate(findings=findings, traces=traces, frameworks=frameworks)
    gaps_by_fw: dict[str, list[dict]] = {}
    for gap in raw.get("gaps", []):
        gaps_by_fw.setdefault(gap["framework"], []).append(gap)

    cards: list[dict[str, Any]] = []
    for fw in frameworks:
        controls = _load_framework(fw)
        open_issues = len(gaps_by_fw.get(fw, []))
        total = max(len(controls), 1)
        coverage = max(0.0, round(100.0 * (1 - open_issues / total), 1))
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for g in gaps_by_fw.get(fw, []):
            s = (g.get("severity") or "medium").lower()
            if s in sev:
                sev[s] += 1
        cards.append(
            {
                "framework_id": fw,
                "display_name": _DISPLAY.get(fw, fw.replace("_", " ").title()),
                "coverage_percent": coverage,
                "controls_total": len(controls),
                "controls_passing": max(0, len(controls) - open_issues),
                "open_issues": open_issues,
                "severity_breakdown": sev,
                "trend": "stable",
            }
        )

    overall = float(raw.get("compliance_score") or 0)
    return {
        "overall_score": overall,
        "frameworks_evaluated": len(cards),
        "cards": cards,
        "finding_count": len(findings),
        "runtime_signal_count": len(traces),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
