"""
EEG - Dependency Parser
Extracts AI-specific dependencies from requirements.txt, pyproject.toml, setup.py, package.json, etc.
Maps detected packages to the AI framework registry for CVE scanning.
"""

import os
import re
import json
from typing import Dict, Optional

# AI-specific packages to monitor — maps package name to canonical keyword for NVD search
AI_PACKAGE_REGISTRY = {
    # ML / DL Frameworks
    "torch": "pytorch",
    "pytorch": "pytorch",
    "tensorflow": "tensorflow",
    "jax": "jax",
    "flax": "flax",
    "keras": "keras",
    # LLM Frameworks
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-community": "langchain",
    "langchain-openai": "langchain",
    "langchain-aws": "langchain",
    "langchain-google-vertexai": "langchain",
    "llama-index": "llamaindex",
    "llama_index": "llamaindex",
    "llamaindex": "llamaindex",
    "transformers": "huggingface transformers",
    "huggingface-hub": "huggingface",
    "tokenizers": "huggingface tokenizers",
    "sentence-transformers": "sentence-transformers",
    "openai": "openai python",
    "anthropic": "anthropic python",
    # Model Serving
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "vllm": "vllm",
    "triton": "nvidia triton",
    "tritonclient": "nvidia triton",
    "ray": "ray",
    "mlflow": "mlflow",
    "bentoml": "bentoml",
    "litellm": "litellm",
    # Vector DBs
    "chromadb": "chromadb",
    "pinecone-client": "pinecone",
    "weaviate-client": "weaviate",
    "qdrant-client": "qdrant",
    "milvus": "milvus",
    "pymilvus": "milvus",
    "pgvector": "pgvector",
    "faiss-cpu": "faiss",
    "faiss-gpu": "faiss",
    # Cloud AI SDKs
    "boto3": "boto3",
    "botocore": "botocore",
    "azure-ai-ml": "azure ai ml",
    "azure-identity": "azure identity",
    "azure-cognitiveservices-speech": "azure cognitive services",
    "google-cloud-aiplatform": "google cloud aiplatform",
    "google-generativeai": "google generativeai",
    "vertexai": "google vertex ai",
    # Runtime / GPU
    "cuda-python": "nvidia cuda",
    "nvidia-cuda-runtime-cu12": "nvidia cuda",
    "nvidia-nccl-cu12": "nvidia nccl",
    "cupy": "cupy",
    "onnxruntime": "onnxruntime",
    "onnxruntime-gpu": "onnxruntime",
    "tensorrt": "nvidia tensorrt",
    # Agent Frameworks
    "autogen": "autogen",
    "crewai": "crewai",
    "strands-agents": "strands agents",
    "bedrock-agentcore": "bedrock agentcore",
    "mcp": "model context protocol",
    # Data Processing
    "datasets": "huggingface datasets",
    "safetensors": "safetensors",
    "accelerate": "huggingface accelerate",
    "peft": "huggingface peft",
    "trl": "huggingface trl",
}


class DependencyParser:
    """Parse project dependency files and identify AI-specific packages."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def parse(self) -> Dict[str, str]:
        """Returns dict mapping package_name -> version (or 'unknown')."""
        deps: Dict[str, str] = {}

        # Walk the repo for dependency files
        for dirpath, _, filenames in os.walk(self.repo_path):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                if fname == "requirements.txt":
                    deps.update(self._parse_requirements_txt(full))
                elif fname == "pyproject.toml":
                    deps.update(self._parse_pyproject_toml(full))
                elif fname == "setup.py":
                    deps.update(self._parse_setup_py(full))
                elif fname == "Pipfile":
                    deps.update(self._parse_pipfile(full))
                elif fname == "package.json":
                    deps.update(self._parse_package_json(full))

        # Filter to AI-specific packages only
        ai_deps = {}
        for pkg, version in deps.items():
            normalized = pkg.lower().replace("_", "-")
            if normalized in AI_PACKAGE_REGISTRY:
                ai_deps[normalized] = version

        return ai_deps

    def _parse_requirements_txt(self, path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(r'^([A-Za-z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+)?', line)
                    if match:
                        name = match.group(1).lower().replace("_", "-")
                        version = match.group(2).strip() if match.group(2) else "unknown"
                        deps[name] = version
        except Exception:
            pass
        return deps

    def _parse_pyproject_toml(self, path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            # Simple regex extraction from dependencies list
            dep_section = re.findall(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            for section in dep_section:
                for match in re.finditer(r'["\']([A-Za-z0-9_.-]+)\s*([><=!~]*[\d.*]*)["\']', section):
                    name = match.group(1).lower().replace("_", "-")
                    version = match.group(2) or "unknown"
                    deps[name] = version
        except Exception:
            pass
        return deps

    def _parse_setup_py(self, path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            for match in re.finditer(r'["\']([A-Za-z0-9_.-]+)\s*([><=!~]*[\d.*]*)["\']', content):
                name = match.group(1).lower().replace("_", "-")
                version = match.group(2) or "unknown"
                deps[name] = version
        except Exception:
            pass
        return deps

    def _parse_pipfile(self, path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", errors="ignore") as f:
                in_packages = False
                for line in f:
                    line = line.strip()
                    if line == "[packages]":
                        in_packages = True
                        continue
                    if line.startswith("[") and in_packages:
                        break
                    if in_packages and "=" in line:
                        parts = line.split("=", 1)
                        name = parts[0].strip().strip('"').lower().replace("_", "-")
                        version = parts[1].strip().strip('"')
                        deps[name] = version
        except Exception:
            pass
        return deps

    def _parse_package_json(self, path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", errors="ignore") as f:
                data = json.load(f)
            for key in ("dependencies", "devDependencies"):
                for pkg, ver in data.get(key, {}).items():
                    deps[pkg.lower()] = ver
        except Exception:
            pass
        return deps
