"""EEG - Secrets & Credential Exposure Detector"""
from eeg.detectors.base import BaseDetector


class SecretsDetector(BaseDetector):
    name = "secrets"
    category = "secrets"
