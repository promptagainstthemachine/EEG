"""EEG Modular Scan Framework.

Auto-discovers scan modules in this package. New scans added as Python modules
with a class inheriting from `BaseScan` are automatically registered.

Usage:
    from eeg.scans import ScanRegistry, get_all_scans, run_scan
    
    # Get all registered scans
    scans = get_all_scans()
    
    # Run a specific scan by ID
    result = run_scan("code_security", target_path, config)
"""

from __future__ import annotations

import importlib
import logging
import os
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type

logger = logging.getLogger(__name__)


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity", "medium")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


@dataclass
class ScanResult:
    """Unified result structure for all scan types."""
    
    scan_id: str
    scan_type: str
    status: str  # "completed", "failed", "partial"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        severity_counts = _count_by_severity(self.findings)
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "findings": self.findings,
            "summary": self.summary,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at or datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self.findings),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "info_count": severity_counts["info"],
            "by_severity": {
                "CRITICAL": severity_counts["critical"],
                "HIGH": severity_counts["high"],
                "MEDIUM": severity_counts["medium"],
                "LOW": severity_counts["low"],
                "INFO": severity_counts["info"],
            },
        }


class BaseScan(ABC):
    """Base class for all EEG scan modules.
    
    Implement this class to create new scan types that are auto-discovered.
    """
    
    scan_id: str = "base"
    scan_type: str = "base"
    description: str = "Base scan class"
    categories: List[str] = []
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
    
    @abstractmethod
    def execute(
        self,
        target_path: Path,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """Execute the scan against the target path.
        
        Args:
            target_path: Directory or file to scan
            options: Scan-specific options
            
        Returns:
            ScanResult with findings and metadata
        """
        pass
    
    def validate_target(self, target_path: Path) -> bool:
        """Validate that target is scannable. Override for custom validation."""
        return target_path.exists()
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """Return scan metadata for registry."""
        return {
            "scan_id": cls.scan_id,
            "scan_type": cls.scan_type,
            "description": cls.description,
            "categories": cls.categories,
        }


class ScanRegistry:
    """Registry for auto-discovered scan modules."""
    
    _instance: Optional["ScanRegistry"] = None
    _scans: Dict[str, Type[BaseScan]] = {}
    _initialized: bool = False
    
    def __new__(cls) -> "ScanRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def discover_scans(cls) -> None:
        """Auto-discover scan modules in this package."""
        if cls._initialized:
            return
            
        scans_dir = Path(__file__).parent
        
        for module_info in pkgutil.iter_modules([str(scans_dir)]):
            if module_info.name.startswith("_"):
                continue
            
            try:
                module = importlib.import_module(f"eeg.scans.{module_info.name}")
                
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseScan)
                        and attr is not BaseScan
                        and hasattr(attr, "scan_id")
                    ):
                        cls._scans[attr.scan_id] = attr
                        
            except ImportError as e:
                logger.warning(
                    "Failed to import scan module %s: %s",
                    module_info.name,
                    e,
                )
        
        cls._initialized = True
        logger.debug("Discovered %d EEG scans: %s", len(cls._scans), sorted(cls._scans))
    
    @classmethod
    def register(cls, scan_class: Type[BaseScan]) -> Type[BaseScan]:
        """Decorator to manually register a scan class."""
        cls._scans[scan_class.scan_id] = scan_class
        return scan_class
    
    @classmethod
    def get(cls, scan_id: str) -> Optional[Type[BaseScan]]:
        """Get a scan class by ID."""
        cls.discover_scans()
        return cls._scans.get(scan_id)
    
    @classmethod
    def get_all(cls) -> Dict[str, Type[BaseScan]]:
        """Get all registered scan classes."""
        cls.discover_scans()
        return dict(cls._scans)
    
    @classmethod
    def list_metadata(cls) -> List[Dict[str, Any]]:
        """List metadata for all registered scans."""
        cls.discover_scans()
        return [s.get_metadata() for s in cls._scans.values()]


def get_all_scans() -> Dict[str, Type[BaseScan]]:
    """Get all registered scan modules."""
    return ScanRegistry.get_all()


def run_scan(
    scan_id: str,
    target_path: Path | str,
    config: Optional[Dict[str, Any]] = None,
    options: Optional[Dict[str, Any]] = None,
) -> ScanResult:
    """Run a specific scan by ID.
    
    Args:
        scan_id: Registered scan identifier
        target_path: Path to scan
        config: Scan configuration
        options: Runtime options
        
    Returns:
        ScanResult from the scan execution
    """
    scan_class = ScanRegistry.get(scan_id)
    if not scan_class:
        return ScanResult(
            scan_id=scan_id,
            scan_type="unknown",
            status="failed",
            errors=[f"Scan '{scan_id}' not found in registry"],
        )
    
    path = Path(target_path).expanduser().resolve()
    scanner = scan_class(config)
    
    if not scanner.validate_target(path):
        return ScanResult(
            scan_id=scan_id,
            scan_type=scan_class.scan_type,
            status="failed",
            errors=[f"Target path validation failed: {path}"],
        )
    
    try:
        return scanner.execute(path, options=options)
    except Exception as e:
        return ScanResult(
            scan_id=scan_id,
            scan_type=scan_class.scan_type,
            status="failed",
            errors=[f"Scan execution error: {type(e).__name__}: {e}"],
        )


def run_all_scans(
    target_path: Path | str,
    *,
    scan_ids: Optional[Set[str]] = None,
    categories: Optional[Set[str]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, ScanResult]:
    """Run multiple scans against a target.
    
    Args:
        target_path: Path to scan
        scan_ids: Specific scan IDs to run (None = all)
        categories: Filter by scan categories
        config: Shared configuration
        
    Returns:
        Dict mapping scan_id to ScanResult
    """
    results: Dict[str, ScanResult] = {}
    all_scans = ScanRegistry.get_all()
    
    for scan_id, scan_class in all_scans.items():
        if scan_ids and scan_id not in scan_ids:
            continue
        if categories:
            scan_cats = set(scan_class.categories)
            if not scan_cats.intersection(categories):
                continue
        
        results[scan_id] = run_scan(scan_id, target_path, config)
    
    return results
