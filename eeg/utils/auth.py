"""
EEG - Multi-Cloud Authentication Handler
Discovers and loads credentials from ~/.aws, ~/.azure, ~/.config/gcloud for authenticated scanning.
"""

import os
import configparser
import json
from typing import Optional, Dict


class CloudAuthenticator:
    """Discovers cloud credentials for authenticated testing."""

    def __init__(self, cloud_env: str):
        self.cloud_env = cloud_env.lower()

    def authenticate(self) -> Optional[Dict]:
        dispatch = {
            "aws": self._auth_aws,
            "azure": self._auth_azure,
            "gcp": self._auth_gcp,
        }
        handler = dispatch.get(self.cloud_env)
        if handler:
            return handler()
        return None

    # --- AWS ---
    def _auth_aws(self) -> Optional[Dict]:
        aws_dir = os.path.expanduser("~/.aws")
        creds_file = os.path.join(aws_dir, "credentials")
        config_file = os.path.join(aws_dir, "config")

        if not os.path.isfile(creds_file):
            # Check environment variables
            if os.environ.get("AWS_ACCESS_KEY_ID"):
                return {
                    "provider": "aws",
                    "source": "environment",
                    "identity": os.environ.get("AWS_ACCESS_KEY_ID", "")[:8] + "****",
                    "region": os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
                }
            return None

        parser = configparser.ConfigParser()
        parser.read(creds_file)
        profile = os.environ.get("AWS_PROFILE", "default")

        if profile not in parser:
            return None

        access_key = parser[profile].get("aws_access_key_id", "")
        region = "us-east-1"

        config_parser = configparser.ConfigParser()
        if os.path.isfile(config_file):
            config_parser.read(config_file)
            section = f"profile {profile}" if profile != "default" else "default"
            if section in config_parser:
                region = config_parser[section].get("region", region)

        return {
            "provider": "aws",
            "source": "credentials_file",
            "identity": access_key[:8] + "****" if access_key else "unknown",
            "region": region,
            "profile": profile,
        }

    # --- Azure ---
    def _auth_azure(self) -> Optional[Dict]:
        azure_dir = os.path.expanduser("~/.azure")
        profile_path = os.path.join(azure_dir, "azureProfile.json")

        if os.environ.get("AZURE_CLIENT_ID"):
            return {
                "provider": "azure",
                "source": "environment",
                "identity": os.environ.get("AZURE_CLIENT_ID", "")[:8] + "****",
                "tenant": os.environ.get("AZURE_TENANT_ID", "unknown"),
            }

        if not os.path.isfile(profile_path):
            return None

        try:
            with open(profile_path, "r") as f:
                profile = json.load(f)
            subs = profile.get("subscriptions", [])
            if subs:
                sub = subs[0]
                return {
                    "provider": "azure",
                    "source": "azure_cli",
                    "identity": sub.get("user", {}).get("name", "unknown"),
                    "subscription": sub.get("name", "unknown"),
                    "tenant": sub.get("tenantId", "unknown"),
                }
        except (json.JSONDecodeError, KeyError):
            pass
        return None

    # --- GCP ---
    def _auth_gcp(self) -> Optional[Dict]:
        if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            cred_path = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
            try:
                with open(cred_path, "r") as f:
                    cred = json.load(f)
                return {
                    "provider": "gcp",
                    "source": "service_account",
                    "identity": cred.get("client_email", "unknown"),
                    "project": cred.get("project_id", "unknown"),
                }
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        adc_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
        if os.path.isfile(adc_path):
            try:
                with open(adc_path, "r") as f:
                    cred = json.load(f)
                return {
                    "provider": "gcp",
                    "source": "application_default",
                    "identity": cred.get("client_id", "unknown")[:12] + "****",
                    "project": os.environ.get("GCLOUD_PROJECT", "unknown"),
                }
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        props_path = os.path.expanduser("~/.config/gcloud/properties")
        if os.path.isfile(props_path):
            parser = configparser.ConfigParser()
            parser.read(props_path)
            project = parser.get("core", "project", fallback="unknown")
            account = parser.get("core", "account", fallback="unknown")
            return {
                "provider": "gcp",
                "source": "gcloud_cli",
                "identity": account,
                "project": project,
            }

        return None
