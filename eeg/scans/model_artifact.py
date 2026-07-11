"""Model Artifact Scan — pickle/serialization safety inspection.

Scans model files (pickle, torch, keras) for unsafe deserialization patterns
without executing the payloads.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from eeg.scans import BaseScan, ScanResult, ScanRegistry


MODEL_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".h5", ".keras", ".joblib", ".npy", ".npz"}


@ScanRegistry.register
class ModelArtifactScan(BaseScan):
    """Model serialization safety scan (pickle opcode inspection)."""
    
    scan_id = "model_artifact"
    scan_type = "artifact"
    description = "Model file serialization safety (pickle, torch, keras)"
    categories = ["artifact", "model", "serialization", "supply_chain"]
    
    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        
        findings: List[Dict[str, Any]] = []
        scanned_files = 0
        errors: List[str] = []
        
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(self._find_model_files(target_path))
        
        for fpath in files:
            scanned_files += 1
            try:
                result = self._scan_file(fpath)
                if result:
                    findings.extend(result)
            except Exception as e:
                errors.append(f"{fpath}: {e}")
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM")
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed" if not errors else "partial",
            findings=findings,
            summary={
                "files_scanned": scanned_files,
                "total_findings": len(findings),
                "by_severity": severity_counts,
            },
            errors=errors,
        )
    
    def _find_model_files(self, root: Path) -> List[Path]:
        """Find model files in directory."""
        result = []
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in MODEL_EXTENSIONS:
                    result.append(Path(dirpath) / fname)
        return result
    
    def _scan_file(self, fpath: Path) -> List[Dict[str, Any]]:
        """Scan a single model file for unsafe patterns."""
        from eeg.scans.serialization_guard import scan_path
        
        result = scan_path(fpath)
        
        if not result:
            return []
        
        findings = []
        exit_code = result.get("exit_code", 0)
        issues = result.get("issues", [])
        
        if exit_code == 1 or issues:
            for issue in issues:
                sev = issue.get("severity", "CRITICAL")
                op = issue.get("operator", {})
                findings.append({
                    "rule_id": f"EEG-MODEL-{op.get('module', 'UNSAFE').upper()}",
                    "severity": sev,
                    "category": "model_serialization",
                    "file_path": str(fpath),
                    "message": f"Unsafe import: {op.get('module')}.{op.get('operator')}",
                    "operator": op,
                    "recommendation": "Avoid pickle for untrusted artifacts; use safetensors or signed formats.",
                })
        
        return findings
