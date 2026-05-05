"""EEG - AI Guardrail Configuration Detector"""
from eeg.detectors.base import BaseDetector


class GuardrailDetector(BaseDetector):
    name = "guardrail"
    category = "guardrail"
