"""Regulatory framework gap evaluation from findings and runtime traces."""

from __future__ import annotations

from typing import Any

from eeg.compliance.signal_control_bridge import CONTROL_SIGNAL_MAP, resolve_control_breach

_BUILTIN: dict[str, list[str]] = {
    "nist_rmf": ["ID.AM", "ID.RA", "PR.DS", "DE.CM", "RS.MI"],
    "hipaa": ["164.312(a)(1)", "164.312(b)", "164.308(a)(4)"],
    "iso27001": ["A.8.1", "A.8.2", "A.5.7"],
    "soc2": ["CC6.1", "CC7.2", "CC8.1"],
    "eu_ai_act": ["Art-9", "Art-10", "Art-15"],
    "iso_42001": ["A.5.1", "A.6.2", "A.8.1", "A.8.3", "A.9.4"],
}

_DISPLAY = {
    "nist_rmf": "NIST AI RMF",
    "hipaa": "HIPAA Security",
    "iso27001": "ISO 27001",
    "soc2": "SOC 2",
    "eu_ai_act": "EU AI Act",
    "iso_42001": "ISO/IEC 42001",
}


def _load_framework(framework: str) -> list[str]:
    controls = sorted({cid for (fw, cid) in CONTROL_SIGNAL_MAP if fw == framework})
    if controls:
        return controls
    return list(_BUILTIN.get(framework, []))


def evaluate(
    *,
    findings: list[dict[str, Any]] | None = None,
    traces: list[dict[str, Any]] | None = None,
    frameworks: list[str] | None = None,
    enabled_pack_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Score frameworks from finding/trace evidence and emit open gaps."""
    del enabled_pack_ids  # packs reserved for future OSS policy-pack wiring
    findings = findings or []
    traces = traces or []
    frameworks = frameworks or list(_BUILTIN.keys())

    gaps: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    maturity_values: list[float] = []
    controls_assessed = 0
    total_controls = 0
    score_parts: list[float] = []
    gateway_gaps = 0
    finding_gaps = 0

    for fw in frameworks:
        controls = _load_framework(fw)
        if not controls:
            continue
        fw_gaps: list[dict[str, Any]] = []
        passing = 0
        for cid in controls:
            breach = resolve_control_breach(fw, cid, findings, traces)
            controls_assessed += 1
            total_controls += 1
            if breach:
                row = {
                    "framework": fw,
                    "control_id": cid,
                    "severity": breach.get("severity", "medium"),
                    "evidence": breach.get("evidence", ""),
                    "source": breach.get("source", "finding"),
                    "status": "breached",
                }
                fw_gaps.append(row)
                gaps.append(row)
                if row["source"] == "gateway":
                    gateway_gaps += 1
                else:
                    finding_gaps += 1
            else:
                passing += 1

        open_n = len(fw_gaps)
        total = max(len(controls), 1)
        score = round(100.0 * (1 - open_n / total), 1)
        maturity = round(4.0 * (passing / total), 2)
        score_parts.append(score)
        maturity_values.append(maturity)
        assessments.append(
            {
                "framework": fw,
                "display_name": _DISPLAY.get(fw, fw.replace("_", " ").title()),
                "score": score,
                "controls_assessed": len(controls),
                "controls_passing": passing,
                "controls_breached": open_n,
                "maturity_average": maturity,
                "gaps": fw_gaps,
                "status": "partial" if open_n else "implemented",
            }
        )

    compliance_score = round(sum(score_parts) / len(score_parts), 1) if score_parts else 100.0
    return {
        "frameworks": frameworks,
        "compliance_score": compliance_score,
        "gaps": gaps,
        "controls_total": total_controls,
        "controls_assessed": controls_assessed,
        "finding_count": len(findings),
        "runtime_signal_count": len(traces),
        "violation_sources": {
            "gateway": gateway_gaps,
            "findings": finding_gaps,
            "total": len(gaps),
        },
        "assessments": assessments,
        "maturity_average": (
            round(sum(maturity_values) / len(maturity_values), 2) if maturity_values else 0.0
        ),
    }
