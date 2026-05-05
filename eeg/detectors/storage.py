"""EEG - Storage Security Detector (S3, Blob, GCS)"""
from eeg.detectors.base import BaseDetector


class StorageDetector(BaseDetector):
    name = "storage"
    category = "storage"
