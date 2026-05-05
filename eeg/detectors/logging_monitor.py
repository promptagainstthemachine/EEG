"""EEG - Logging & Monitoring Detector"""
from eeg.detectors.base import BaseDetector


class LoggingDetector(BaseDetector):
    name = "logging"
    category = "logging"
