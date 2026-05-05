"""
EEG - CSV Report Generator
Produces a CSV report for spreadsheet integration and analysis.
"""

import csv
import io
from eeg.collector import Collector


class CSVReportGenerator:
    """Generate a CSV report from collected findings."""

    def __init__(self, collector: Collector):
        self.collector = collector

    def generate(self) -> str:
        findings = self.collector.get_findings_sorted()
        meta = self.collector.scan_metadata
        summary = self.collector.get_summary()

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        # Header row
        writer.writerow([
            "Rule_ID",
            "Severity",
            "Category",
            "Cloud_Env",
            "File_Path",
            "Line_Number",
            "Message",
            "Code_Snippet",
            "Recommendation",
            "CWE",
            "OWASP_LLM",
            "Timestamp",
        ])

        # Findings rows
        for f in findings:
            writer.writerow([
                f.rule_id,
                f.severity.value,
                f.category,
                f.cloud_env,
                f.file_path,
                f.line_number,
                f.message,
                f.code_snippet[:200] if f.code_snippet else "",
                f.recommendation,
                f.cwe or "",
                f.owasp_llm or "",
                f.timestamp,
            ])

        # Summary section (appended as comment rows)
        writer.writerow([])
        writer.writerow(["# SUMMARY"])
        writer.writerow(["# Cloud Environment", meta.get("cloud_env", "").upper()])
        writer.writerow(["# Files Scanned", summary.get("files_scanned", 0)])
        writer.writerow(["# Total Findings", summary.get("total_findings", 0)])
        writer.writerow(["# CRITICAL", summary["by_severity"]["CRITICAL"]])
        writer.writerow(["# HIGH", summary["by_severity"]["HIGH"]])
        writer.writerow(["# MEDIUM", summary["by_severity"]["MEDIUM"]])
        writer.writerow(["# LOW", summary["by_severity"]["LOW"]])
        writer.writerow(["# INFO", summary["by_severity"]["INFO"]])
        writer.writerow(["# Scan Duration (s)", summary.get("scan_duration_seconds", 0)])
        
        # Permission tracking
        completed = summary.get("completed_checks", 0)
        skipped = summary.get("skipped_checks", 0)
        perm_issues = summary.get("permission_issues", 0)
        
        if completed > 0 or skipped > 0:
            writer.writerow([])
            writer.writerow(["# PERMISSION STATUS"])
            writer.writerow(["# Checks Completed", completed])
            writer.writerow(["# Checks Skipped", skipped])
            writer.writerow(["# Permission Issues", perm_issues])
        
        # Include skipped checks details if any
        if self.collector.skipped_checks:
            writer.writerow([])
            writer.writerow(["# SKIPPED CHECKS"])
            for check in self.collector.skipped_checks:
                writer.writerow(["# -", check])

        return output.getvalue()
