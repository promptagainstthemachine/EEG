"""
EEG - Extensive Exposure Guard
Collector module: aggregates findings from all detectors into a unified report structure.
"""

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    def __lt__(self, other):
        return self.weight < other.weight


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    cloud_env: str
    file_path: str
    line_number: int
    code_snippet: str
    message: str
    recommendation: str
    cwe: Optional[str] = None
    owasp_llm: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "cloud_env": self.cloud_env,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "owasp_llm": self.owasp_llm,
            "timestamp": self.timestamp,
        }


class Collector:
    """Central aggregator for all scan findings."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.scan_metadata: Dict = {}
        self._start_time = datetime.datetime.utcnow()
        self._seen_keys: set = set()

    def _dedup_key(self, finding: Finding) -> str:
        return f"{finding.rule_id}|{finding.file_path}|{finding.line_number}"

    def add_finding(self, finding: Finding):
        key = self._dedup_key(finding)
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self.findings.append(finding)

    def add_findings(self, findings: List[Finding]):
        for f in findings:
            self.add_finding(f)

    def set_metadata(self, **kwargs):
        self.scan_metadata.update(kwargs)

    def get_summary(self) -> Dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity.value] += 1

        elapsed = (datetime.datetime.utcnow() - self._start_time).total_seconds()
        return {
            "total_findings": len(self.findings),
            "by_severity": counts,
            "by_category": self._group_by("category"),
            "by_cloud": self._group_by("cloud_env"),
            "files_scanned": self.scan_metadata.get("files_scanned", 0),
            "scan_duration_seconds": round(elapsed, 2),
            "scan_time": self._start_time.isoformat(),
        }

    def get_findings_sorted(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def get_findings_by_category(self, category: str) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def _group_by(self, attr: str) -> Dict[str, int]:
        groups: Dict[str, int] = {}
        for f in self.findings:
            key = getattr(f, attr)
            groups[key] = groups.get(key, 0) + 1
        return groups

    def to_dict(self) -> Dict:
        return {
            "metadata": self.scan_metadata,
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.get_findings_sorted()],
        }

    @property
    def exit_code(self) -> int:
        """CI/CD exit code: 0=clean, 1=HIGH, 2=CRITICAL."""
        sev = self.get_summary()["by_severity"]
        if sev["CRITICAL"] > 0:
            return 2
        if sev["HIGH"] > 0:
            return 1
        return 0
