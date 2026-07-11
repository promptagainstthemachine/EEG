"""Code Security Scan — static pattern matching for AI code vulnerabilities.

Executes bundled YAML rule packs (ai_practice_patterns, prompt_guard, etc.)
using the embedded regex engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from eeg.analysis.semantic_trace import AiPracticeSemanticEngine
from eeg.collector import Collector
from eeg.detectors.boundary_policy_pack import BoundaryPolicyPackDetector
from eeg.scans import BaseScan, ScanResult, ScanRegistry
from eeg.utils.repocrawler import RepoCrawler


@ScanRegistry.register
class CodeSecurityScan(BaseScan):
    """Static code security scan using bundled YAML rule patterns."""
    
    scan_id = "code_security"
    scan_type = "static"
    description = (
        "AI code security patterns (regex packs + semantic AST/taint for exec/eval/LLM flows)"
    )
    categories = ["code", "static", "secrets", "prompt", "mcp"]
    
    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        opts = options or {}
        cloud_env = opts.get("cloud_env", "any")
        
        collector = Collector()
        collector.set_metadata(
            target_path=str(target_path),
            scan_type=self.scan_type,
        )
        
        crawler = RepoCrawler(str(target_path))
        files = crawler.crawl()
        collector.set_metadata(files_scanned=len(files))
        
        detector = BoundaryPolicyPackDetector(cloud_env)
        detector.scan(files, collector)

        semantic = AiPracticeSemanticEngine()
        semantic.scan_to_collector(files, collector, cloud_env=cloud_env)

        data = collector.to_dict()
        
        return ScanResult(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            status="completed",
            findings=data.get("findings", []),
            summary=data.get("summary", {}),
            metadata=data.get("metadata", {}),
        )
