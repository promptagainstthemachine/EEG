"""
EEG Detectors Package
Loads category-specific detectors based on cloud environment and optional category skips.
"""

from typing import List, Optional, Set
from eeg.detectors.base import BaseDetector
from eeg.detectors.iam import IAMDetector
from eeg.detectors.storage import StorageDetector
from eeg.detectors.guardrail import GuardrailDetector
from eeg.detectors.model import ModelDetector
from eeg.detectors.network import NetworkDetector
from eeg.detectors.iac import IaCDetector
from eeg.detectors.policy import PolicyDetector
from eeg.detectors.prompt import PromptDetector
from eeg.detectors.secrets import SecretsDetector
from eeg.detectors.logging_monitor import LoggingDetector
from eeg.detectors.boundary_policy_pack import BoundaryPolicyPackDetector


ALL_DETECTORS = [
    IAMDetector,
    StorageDetector,
    GuardrailDetector,
    ModelDetector,
    NetworkDetector,
    IaCDetector,
    PolicyDetector,
    PromptDetector,
    SecretsDetector,
    LoggingDetector,
    BoundaryPolicyPackDetector,
]


def load_detectors(cloud_env: str, avoid: Optional[Set[str]] = None) -> List[BaseDetector]:
    """Instantiate all detectors for the given cloud, filtering out avoided categories."""
    skip = {c.strip().lower() for c in (avoid or set()) if c and str(c).strip()}
    detectors = []
    for cls in ALL_DETECTORS:
        if cls.category not in skip:
            detectors.append(cls(cloud_env))
    return detectors
