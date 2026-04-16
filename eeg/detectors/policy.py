"""EEG - Policy Misconfiguration Detector"""
from eeg.detectors.base import BaseDetector


class PolicyDetector(BaseDetector):
    name = "policy"
    category = "policy"
