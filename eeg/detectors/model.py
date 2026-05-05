"""EEG - Model Security Detector (endpoints, weights, inference)"""
from eeg.detectors.base import BaseDetector


class ModelDetector(BaseDetector):
    name = "model"
    category = "model"
