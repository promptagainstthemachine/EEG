"""
Tests for utility modules.
"""

import os
import pytest

from eeg.utils.cloud_console import CloudConsoleDetector, LocalConsoleAuthenticator
from eeg.utils.repocrawler import RepoCrawler


class TestCloudConsoleDetector:
    """Tests for cloud console detection."""

    def test_local_detection(self, monkeypatch):
        """When not in cloud shell, should detect as local."""
        # Clear any cloud shell env vars
        monkeypatch.delenv("ACC_CLOUD", raising=False)
        monkeypatch.delenv("AWS_EXECUTION_ENV", raising=False)
        monkeypatch.delenv("CLOUD_SHELL", raising=False)
        monkeypatch.delenv("AWS_CLOUDSHELL_USER_ID", raising=False)
        
        detector = CloudConsoleDetector()
        is_cloud, console_type, context = detector.detect()
        
        assert is_cloud is False
        assert console_type is None

    def test_azure_cloud_shell_detection(self, monkeypatch):
        """Should detect Azure Cloud Shell via ACC_CLOUD."""
        monkeypatch.setenv("ACC_CLOUD", "AzureCloud")
        
        detector = CloudConsoleDetector()
        is_azure = detector._is_azure_cloud_shell()
        
        assert is_azure is True

    def test_aws_cloudshell_detection(self, monkeypatch):
        """Should detect AWS CloudShell via AWS_EXECUTION_ENV."""
        monkeypatch.setenv("AWS_EXECUTION_ENV", "CloudShell")
        
        detector = CloudConsoleDetector()
        is_aws = detector._is_aws_cloudshell()
        
        assert is_aws is True

    def test_gcp_cloud_shell_detection(self, monkeypatch):
        """Should detect GCP Cloud Shell via CLOUD_SHELL."""
        monkeypatch.setenv("CLOUD_SHELL", "true")
        
        detector = CloudConsoleDetector()
        is_gcp = detector._is_gcp_cloud_shell()
        
        assert is_gcp is True


class TestLocalConsoleAuthenticator:
    """Tests for local CLI authentication checking."""

    def test_azure_authenticator_init(self):
        auth = LocalConsoleAuthenticator("azure")
        assert auth.cloud_env == "azure"

    def test_aws_authenticator_init(self):
        auth = LocalConsoleAuthenticator("aws")
        assert auth.cloud_env == "aws"

    def test_gcp_authenticator_init(self):
        auth = LocalConsoleAuthenticator("gcp")
        assert auth.cloud_env == "gcp"


class TestRepoCrawler:
    """Tests for repository file crawling."""

    def test_crawl_temp_repo(self, temp_repo, sample_py_file):
        crawler = RepoCrawler(temp_repo)
        files = crawler.crawl()
        
        assert len(files) >= 1
        py_files = [f for f in files if f["extension"] == ".py"]
        assert len(py_files) >= 1

    def test_includes_hidden_dirs_by_default(self, temp_repo):
        # Create hidden directory with file
        hidden_dir = os.path.join(temp_repo, ".hidden")
        os.makedirs(hidden_dir)
        with open(os.path.join(hidden_dir, "secret.py"), "w") as f:
            f.write("secret = 'password'")
        
        crawler = RepoCrawler(temp_repo)
        files = crawler.crawl()
        
        # RepoCrawler includes hidden directories (useful for scanning .github, etc.)
        hidden_files = [f for f in files if ".hidden" in f["file_path"]]
        assert len(hidden_files) >= 1

    def test_ignores_venv(self, temp_repo):
        # Create venv directory
        venv_dir = os.path.join(temp_repo, ".venv", "lib")
        os.makedirs(venv_dir)
        with open(os.path.join(venv_dir, "package.py"), "w") as f:
            f.write("# venv package")
        
        crawler = RepoCrawler(temp_repo)
        files = crawler.crawl()
        
        venv_files = [f for f in files if ".venv" in f["file_path"]]
        assert len(venv_files) == 0
