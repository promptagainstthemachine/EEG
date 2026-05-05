"""EEG - IAM Misconfiguration Detector"""
from eeg.detectors.base import BaseDetector


class IAMDetector(BaseDetector):
    name = "iam"
    category = "iam"
