"""EEG Modular Probe Framework.

Probes are active security assessments that interact with endpoints, services,
or runtime environments. Unlike scans (static analysis), probes may make
network requests or execute dynamic tests.

Auto-discovers probe modules in this package. New probes added as Python modules
with a class inheriting from `BaseProbe` are automatically registered.

Usage:
    from eeg.probes import ProbeRegistry, get_all_probes, run_probe
    
    # Get all registered probes
    probes = get_all_probes()
    
    # Run a specific probe
    result = run_probe("mcp_transport", target_url, config)
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type

logger = logging.getLogger(__name__)


def _signals_to_probes(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adapt probe signals to UI-friendly probe rows."""
    probes: List[Dict[str, Any]] = []
    for signal in signals:
        context = signal.get("context") or {}
        category = signal.get("signal_category", "general")
        if category.startswith("redteam_"):
            category = category.replace("redteam_", "", 1)
        blocked = context.get("blocked")
        if blocked is None:
            blocked = signal.get("severity_band", "low") in ("low", "info")
        probes.append({
            "category": category.replace("_", " ").title(),
            "blocked": bool(blocked),
            "description": signal.get("pulse_summary", ""),
            "severity": signal.get("severity_band", "medium"),
        })
    return probes


@dataclass
class ProbeResult:
    """Unified result structure for all probe types."""
    
    probe_id: str
    probe_type: str
    posture_state: str  # "protected", "at_risk", "critical", "unknown"
    signals: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        probes = _signals_to_probes(self.signals)
        blocked = sum(1 for p in probes if p.get("blocked"))
        return {
            "probe_id": self.probe_id,
            "probe_type": self.probe_type,
            "posture_state": self.posture_state,
            "signals": self.signals,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at or datetime.now(timezone.utc).isoformat(),
            "success": self.posture_state not in ("unknown",) and not self.errors,
            "probes": probes,
            "blocked_count": blocked,
            "total_probes": len(probes),
        }


class BaseProbe(ABC):
    """Base class for all EEG probe modules.
    
    Implement this class to create new probe types that are auto-discovered.
    """
    
    probe_id: str = "base"
    probe_type: str = "base"
    description: str = "Base probe class"
    categories: List[str] = []
    requires_network: bool = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
    
    @abstractmethod
    def execute(
        self,
        target: str,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ProbeResult:
        """Execute the probe against the target.
        
        Args:
            target: URL, endpoint, or identifier to probe
            options: Probe-specific options
            
        Returns:
            ProbeResult with posture state and signals
        """
        pass
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """Return probe metadata for registry."""
        return {
            "probe_id": cls.probe_id,
            "probe_type": cls.probe_type,
            "description": cls.description,
            "categories": cls.categories,
            "requires_network": cls.requires_network,
        }


class ProbeRegistry:
    """Registry for auto-discovered probe modules."""
    
    _instance: Optional["ProbeRegistry"] = None
    _probes: Dict[str, Type[BaseProbe]] = {}
    _initialized: bool = False
    
    def __new__(cls) -> "ProbeRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def discover_probes(cls) -> None:
        """Auto-discover probe modules in this package."""
        if cls._initialized:
            return
            
        probes_dir = Path(__file__).parent
        
        for module_info in pkgutil.iter_modules([str(probes_dir)]):
            if module_info.name.startswith("_"):
                continue
            
            try:
                module = importlib.import_module(f"eeg.probes.{module_info.name}")
                
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseProbe)
                        and attr is not BaseProbe
                        and hasattr(attr, "probe_id")
                    ):
                        cls._probes[attr.probe_id] = attr
                        
            except ImportError as e:
                logger.warning(
                    "Failed to import probe module %s: %s",
                    module_info.name,
                    e,
                )
        
        cls._initialized = True
        logger.debug("Discovered %d EEG probes: %s", len(cls._probes), sorted(cls._probes))
    
    @classmethod
    def register(cls, probe_class: Type[BaseProbe]) -> Type[BaseProbe]:
        """Decorator to manually register a probe class."""
        cls._probes[probe_class.probe_id] = probe_class
        return probe_class
    
    @classmethod
    def get(cls, probe_id: str) -> Optional[Type[BaseProbe]]:
        """Get a probe class by ID."""
        cls.discover_probes()
        return cls._probes.get(probe_id)
    
    @classmethod
    def get_all(cls) -> Dict[str, Type[BaseProbe]]:
        """Get all registered probe classes."""
        cls.discover_probes()
        return dict(cls._probes)
    
    @classmethod
    def list_metadata(cls) -> List[Dict[str, Any]]:
        """List metadata for all registered probes."""
        cls.discover_probes()
        return [p.get_metadata() for p in cls._probes.values()]


def get_all_probes() -> Dict[str, Type[BaseProbe]]:
    """Get all registered probe modules."""
    return ProbeRegistry.get_all()


def run_probe(
    probe_id: str,
    target: str,
    config: Optional[Dict[str, Any]] = None,
    options: Optional[Dict[str, Any]] = None,
) -> ProbeResult:
    """Run a specific probe by ID.
    
    Args:
        probe_id: Registered probe identifier
        target: Target URL, endpoint, or identifier
        config: Probe configuration
        options: Runtime options
        
    Returns:
        ProbeResult from the probe execution
    """
    probe_class = ProbeRegistry.get(probe_id)
    if not probe_class:
        return ProbeResult(
            probe_id=probe_id,
            probe_type="unknown",
            posture_state="unknown",
            errors=[f"Probe '{probe_id}' not found in registry"],
        )
    
    prober = probe_class(config)
    
    try:
        return prober.execute(target, options=options)
    except Exception as e:
        return ProbeResult(
            probe_id=probe_id,
            probe_type=probe_class.probe_type,
            posture_state="unknown",
            errors=[f"Probe execution error: {type(e).__name__}: {e}"],
        )
