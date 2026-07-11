"""SARIF 2.1.0 export for EEG scan findings (GitHub Code Scanning / CI)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _severity_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(str(severity or "MEDIUM").upper(), "warning")


def _rule_descriptor(finding: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = str(finding.get("rule_id") or "eeg-unknown")
    desc = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": rule_id},
        "fullDescription": {"text": str(finding.get("message") or rule_id)},
        "helpUri": "https://github.com/extensive-exposure-guard/eeg",
    }
    cwe = finding.get("cwe")
    if cwe:
        desc["properties"] = {"tags": [f"CWE-{cwe}" if not str(cwe).startswith("CWE") else str(cwe)]}
    return desc


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    *,
    tool_name: str = "EEG",
    tool_version: str = "1.0.0",
    target_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert flat EEG finding dicts to a SARIF 2.1.0 log."""
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("rule_id") or "eeg-unknown")
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _rule_descriptor(finding)

        file_path = str(finding.get("file_path") or "")
        line = int(finding.get("line_number") or 1)
        uri = file_path
        if target_uri and file_path and not file_path.startswith(("/", "file:")):
            base = target_uri.rstrip("/")
            uri = f"{base}/{file_path.lstrip('/')}"

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, line)},
            },
        }
        snippet = finding.get("code_snippet")
        if snippet:
            location["physicalLocation"]["region"]["snippet"] = {"text": str(snippet)[:500]}

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_level(str(finding.get("severity", "MEDIUM"))),
            "message": {"text": str(finding.get("message") or rule_id)},
            "locations": [location],
        }
        rec = finding.get("recommendation")
        if rec:
            result["properties"] = {"recommendation": str(rec)}
        results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://github.com/extensive-exposure-guard/eeg",
                "rules": list(rules_by_id.values()),
            }
        },
        "results": results,
    }
    if target_uri:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "commandLine": f"eeg scan {target_uri}",
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }
        ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def dumps_sarif(
    findings: List[Dict[str, Any]],
    *,
    tool_name: str = "EEG",
    tool_version: str = "1.0.0",
    target_uri: Optional[str] = None,
    indent: Optional[int] = 2,
) -> str:
    """Serialize findings as SARIF JSON."""
    doc = findings_to_sarif(
        findings,
        tool_name=tool_name,
        tool_version=tool_version,
        target_uri=target_uri,
    )
    return json.dumps(doc, indent=indent, ensure_ascii=False)


def new_fingerprint(finding: Dict[str, Any]) -> str:
    """Stable id for deduplication in merged scan output."""
    return "|".join(
        [
            str(finding.get("rule_id", "")),
            str(finding.get("file_path", "")),
            str(finding.get("line_number", "")),
        ]
    )
