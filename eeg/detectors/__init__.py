"""
EEG Detectors Package
Loads category-specific detectors based on cloud environment and avoided categories.
"""

from typing import List, Set
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
]


def load_detectors(cloud_env: str, avoid: Set[str]) -> List[BaseDetector]:
    """Instantiate all detectors for the given cloud, filtering out avoided categories."""
    detectors = []
    for cls in ALL_DETECTORS:
        if cls.category not in avoid:
            detectors.append(cls(cloud_env))
    return detectors
