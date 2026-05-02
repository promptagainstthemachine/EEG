"""
Tests for CLI module.
"""

import pytest
import sys
from unittest.mock import patch

from eeg.cli import parse_args


class TestCLIArguments:
    """Tests for CLI argument parsing."""

    def test_env_required(self):
        """--env is required."""
        with pytest.raises(SystemExit):
            with patch.object(sys, 'argv', ['eeg']):
                parse_args()

    def test_valid_env_aws(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.']):
            args = parse_args()
            assert args.env == "aws"

    def test_valid_env_azure(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'azure', '--path', '.']):
            args = parse_args()
            assert args.env == "azure"

    def test_valid_env_gcp(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'gcp', '--path', '.']):
            args = parse_args()
            assert args.env == "gcp"

    def test_invalid_env_rejected(self):
        with pytest.raises(SystemExit):
            with patch.object(sys, 'argv', ['eeg', '--env', 'invalid', '--path', '.']):
                parse_args()

    def test_auth_default_false(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.']):
            args = parse_args()
            assert args.auth == "false"

    def test_auth_true(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--auth', 'true', '--path', '.']):
            args = parse_args()
            assert args.auth == "true"

    def test_vm_default_true(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.']):
            args = parse_args()
            assert args.vm == "true"

    def test_report_formats(self):
        for fmt in ["json", "html", "csv"]:
            with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.', '--report', fmt]):
                args = parse_args()
                assert args.report == fmt

    def test_thread_levels(self):
        for level in ["med", "max"]:
            with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.', '--thread', level]):
                args = parse_args()
                assert args.thread == level

    def test_avoid_categories(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.', '--avoid', 'iam,network,iac']):
            args = parse_args()
            assert args.avoid == "iam,network,iac"

    def test_console_mode_options(self):
        for mode in ["auto", "local", "cloud"]:
            with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.', '--console-mode', mode]):
                args = parse_args()
                assert args.console_mode == mode

    def test_output_file(self):
        with patch.object(sys, 'argv', ['eeg', '--env', 'aws', '--path', '.', '--output-file', '/tmp/report.json']):
            args = parse_args()
            assert args.output_file == "/tmp/report.json"
