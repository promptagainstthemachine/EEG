"""
EEG - Extensive Exposure Guard
Multi-Cloud AI Security static analysis engine embedded in EEG-SAAS.

Primary use: control plane (Django apps) calls :mod:`eeg.pipeline` against workspace paths.
Optional report helpers (JSON / HTML / CSV) consume :class:`eeg.collector.Collector` instances.
"""

__version__ = "2.0.0"
__author__ = "findthehead"
