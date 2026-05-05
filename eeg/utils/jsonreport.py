"""
EEG - JSON Report Generator
Produces machine-readable JSON for CI/CD integration.
"""

import json
from eeg.collector import Collector


class JSONReportGenerator:
    """Generate a JSON report from collected findings."""

    def __init__(self, collector: Collector):
        self.collector = collector

    def generate(self) -> str:
        data = self.collector.to_dict()
        return json.dumps(data, indent=2, default=str)
