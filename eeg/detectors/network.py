"""EEG - Network Exposure Detector"""
from eeg.detectors.base import BaseDetector


class NetworkDetector(BaseDetector):
    name = "network"
    category = "network"
