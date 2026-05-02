"""
EEG Test Configuration
Shared fixtures for all test modules.
"""

import os
import tempfile
import pytest

from eeg.collector import Collector


@pytest.fixture
def collector():
    """Fresh Collector instance for each test."""
    return Collector()


@pytest.fixture
def temp_repo():
    """Create a temporary directory to simulate a repository."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_py_file(temp_repo):
    """Create a sample Python file with common patterns."""
    filepath = os.path.join(temp_repo, "app.py")
    content = '''
import boto3

def invoke_model():
    client = boto3.client("bedrock-runtime")
    prompt = f"User said: {user_input}"  # Prompt injection risk
    return client.invoke_model(modelId="anthropic.claude-v2", body=prompt)
'''
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


@pytest.fixture
def sample_iam_policy(temp_repo):
    """Create a sample IAM policy with overly broad permissions."""
    filepath = os.path.join(temp_repo, "policy.json")
    content = '''{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "bedrock:*",
        "Resource": "*"
    }]
}'''
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


@pytest.fixture
def sample_terraform(temp_repo):
    """Create a sample Terraform file."""
    filepath = os.path.join(temp_repo, "main.tf")
    content = '''
resource "aws_iam_role_policy" "bedrock_policy" {
  name = "bedrock-policy"
  role = aws_iam_role.bedrock_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "bedrock:*"
      Resource = "*"
    }]
  })
}
'''
    with open(filepath, "w") as f:
        f.write(content)
    return filepath
