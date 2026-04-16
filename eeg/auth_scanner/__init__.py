"""
EEG Auth Scanner Package
Authenticated live-audit engine.
Extends across AWS, Azure, and GCP cloud AI services.
"""

from eeg.auth_scanner.aws_scanner import AWSAuthScanner
from eeg.auth_scanner.azure_scanner import AzureAuthScanner
from eeg.auth_scanner.gcp_scanner import GCPAuthScanner


def get_auth_scanner(cloud_env: str, auth_context: dict):
    """Factory: return the correct auth scanner for the cloud."""
    scanners = {
        "aws": AWSAuthScanner,
        "azure": AzureAuthScanner,
        "gcp": GCPAuthScanner,
    }
    cls = scanners.get(cloud_env)
    if cls:
        return cls(auth_context)
    return None
