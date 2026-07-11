"""
EEG - Dependency Parser
Parses dependency manifests across Python, JavaScript, Go, .NET, Ruby, Rust, and Java.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

# AI-specific packages — used for optional NVD keyword enrichment (PyPI).
AI_PACKAGE_REGISTRY = {
    "torch": "pytorch",
    "pytorch": "pytorch",
    "tensorflow": "tensorflow",
    "jax": "jax",
    "flax": "flax",
    "keras": "keras",
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
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "vllm": "vllm",
    "triton": "nvidia triton",
    "tritonclient": "nvidia triton",
    "ray": "ray",
    "mlflow": "mlflow",
    "bentoml": "bentoml",
    "litellm": "litellm",
    "chromadb": "chromadb",
    "pinecone-client": "pinecone",
    "weaviate-client": "weaviate",
    "qdrant-client": "qdrant",
    "milvus": "milvus",
    "pymilvus": "milvus",
    "pgvector": "pgvector",
    "faiss-cpu": "faiss",
    "faiss-gpu": "faiss",
    "boto3": "boto3",
    "botocore": "botocore",
    "azure-ai-ml": "azure ai ml",
    "azure-identity": "azure identity",
    "azure-cognitiveservices-speech": "azure cognitive services",
    "google-cloud-aiplatform": "google cloud aiplatform",
    "google-generativeai": "google generativeai",
    "vertexai": "google vertex ai",
    "cuda-python": "nvidia cuda",
    "nvidia-cuda-runtime-cu12": "nvidia cuda",
    "nvidia-nccl-cu12": "nvidia nccl",
    "cupy": "cupy",
    "onnxruntime": "onnxruntime",
    "onnxruntime-gpu": "onnxruntime",
    "tensorrt": "nvidia tensorrt",
    "autogen": "autogen",
    "crewai": "crewai",
    "strands-agents": "strands agents",
    "bedrock-agentcore": "bedrock agentcore",
    "mcp": "model context protocol",
    "datasets": "huggingface datasets",
    "safetensors": "safetensors",
    "accelerate": "huggingface accelerate",
    "peft": "huggingface peft",
    "trl": "huggingface trl",
}

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    "dist",
    "build",
    "target",
    ".gradle",
    "bin",
    "obj",
    "packages",
    ".next",
    "coverage",
}

MANIFEST_FILES = frozenset({
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "pyproject.toml",
    "setup.py",
    "Pipfile",
    "poetry.lock",
    "package.json",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Cargo.toml",
    "pom.xml",
    "packages.config",
    "Directory.Packages.props",
})

CSPROJ_SUFFIX = ".csproj"


@dataclass(frozen=True)
class ParsedDependency:
    """One dependency coordinate for OSV / threat-intel lookup."""

    name: str
    version: str
    ecosystem: str
    source_file: str = ""

    def normalized_version(self) -> str:
        ver = (self.version or "unknown").strip()
        if ver in ("", "unknown", "*"):
            return ""
        ver = ver.split(",")[0].strip()
        for prefix in ("==", "^", "~", ">=", "<=", ">", "<", "!="):
            if ver.startswith(prefix):
                ver = ver[len(prefix) :].strip()
        if self.ecosystem.lower() in ("go",) and ver.startswith("v") and ver[1:2].isdigit():
            ver = ver[1:]
        return ver


class DependencyParser:
    """Parse project dependency files across common language ecosystems."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def parse_all(self, *, max_packages: int = 400) -> List[ParsedDependency]:
        """Return deduplicated dependencies from all supported manifest types."""
        seen: Set[Tuple[str, str, str]] = set()
        out: List[ParsedDependency] = []

        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIR_NAMES and not d.startswith(".")
            ]
            for fname in filenames:
                if len(out) >= max_packages:
                    return out
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, self.repo_path)
                parsed: List[ParsedDependency] = []

                if fname in MANIFEST_FILES:
                    if fname == "requirements.txt" or fname.startswith("requirements"):
                        parsed = self._parse_requirements_txt(full, rel)
                    elif fname == "pyproject.toml":
                        parsed = self._parse_pyproject_toml(full, rel)
                    elif fname == "setup.py":
                        parsed = self._parse_setup_py(full, rel)
                    elif fname == "Pipfile":
                        parsed = self._parse_pipfile(full, rel)
                    elif fname == "package.json":
                        parsed = self._parse_package_json(full, rel)
                    elif fname == "go.mod":
                        parsed = self._parse_go_mod(full, rel)
                    elif fname == "Gemfile":
                        parsed = self._parse_gemfile(full, rel)
                    elif fname == "Cargo.toml":
                        parsed = self._parse_cargo_toml(full, rel)
                    elif fname == "pom.xml":
                        parsed = self._parse_pom_xml(full, rel)
                    elif fname == "packages.config":
                        parsed = self._parse_packages_config(full, rel)
                    elif fname == "Directory.Packages.props":
                        parsed = self._parse_directory_packages_props(full, rel)
                elif fname.endswith(CSPROJ_SUFFIX):
                    parsed = self._parse_csproj(full, rel)

                for dep in parsed:
                    key = (dep.ecosystem.lower(), dep.name.lower(), dep.normalized_version())
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(dep)
                    if len(out) >= max_packages:
                        return out
        return out

    def parse_ai_all(self, max_packages: int = 400) -> List[ParsedDependency]:
        """All ecosystems, limited to packages in AI_PACKAGE_REGISTRY."""
        out: List[ParsedDependency] = []
        for dep in self.parse_all(max_packages=max_packages):
            if dep.name.lower().replace("_", "-") in AI_PACKAGE_REGISTRY:
                out.append(dep)
        return out

    def parse(self) -> Dict[str, str]:
        """Backward-compatible: AI-registry PyPI-style packages only."""
        ai_deps: Dict[str, str] = {}
        for dep in self.parse_all():
            if dep.ecosystem.lower() not in ("pip", "pypi"):
                continue
            normalized = dep.name.lower().replace("_", "-")
            if normalized in AI_PACKAGE_REGISTRY:
                ai_deps[normalized] = dep.version
        return ai_deps

    def parse_ai_versions(self) -> Dict[str, str]:
        """Name→version map for every detected AI-registry package (any ecosystem)."""
        versions: Dict[str, str] = {}
        for dep in self.parse_ai_all():
            key = dep.name.lower().replace("_", "-")
            versions[key] = dep.version
        return versions

    def _add(
        self,
        deps: List[ParsedDependency],
        name: str,
        version: str,
        ecosystem: str,
        source: str,
    ) -> None:
        name = (name or "").strip()
        if not name or name.lower() in ("python", "node", "go"):
            return
        version = (version or "unknown").strip() or "unknown"
        deps.append(
            ParsedDependency(
                name=name,
                version=version,
                ecosystem=ecosystem,
                source_file=source,
            )
        )

    def _parse_requirements_txt(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(
                        r"^([A-Za-z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+)?",
                        line,
                    )
                    if match:
                        self._add(
                            deps,
                            match.group(1),
                            match.group(2).strip() if match.group(2) else "unknown",
                            "pip",
                            source,
                        )
        except OSError:
            pass
        return deps

    def _parse_pyproject_toml(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            for section in re.findall(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL):
                for match in re.finditer(
                    r'["\']([A-Za-z0-9_.-]+)\s*([><=!~]*[\d.*]*)["\']',
                    section,
                ):
                    self._add(
                        deps,
                        match.group(1),
                        match.group(2) or "unknown",
                        "pip",
                        source,
                    )
        except OSError:
            pass
        return deps

    def _parse_setup_py(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            for match in re.finditer(
                r'["\']([A-Za-z0-9_.-]+)\s*([><=!~]*[\d.*]*)["\']',
                content,
            ):
                self._add(deps, match.group(1), match.group(2) or "unknown", "pip", source)
        except OSError:
            pass
        return deps

    def _parse_pipfile(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
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
                        name = parts[0].strip().strip('"')
                        version = parts[1].strip().strip('"')
                        self._add(deps, name, version, "pip", source)
        except OSError:
            pass
        return deps

    def _parse_package_json(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        if path.endswith("package-lock.json") or path.endswith("pnpm-lock.yaml"):
            return deps
        try:
            with open(path, "r", errors="ignore") as f:
                data = json.load(f)
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                section = data.get(key) or {}
                if isinstance(section, dict):
                    for pkg, ver in section.items():
                        self._add(deps, pkg, str(ver), "npm", source)
        except (OSError, json.JSONDecodeError):
            pass
        return deps

    def _parse_go_mod(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return deps

        in_block = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_block = True
                continue
            if in_block and stripped == ")":
                in_block = False
                continue
            if stripped.startswith("require ") and not in_block:
                parts = stripped[len("require ") :].split()
                if len(parts) >= 2:
                    self._add(deps, parts[0], parts[1], "go", source)
                continue
            if in_block and stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2:
                    self._add(deps, parts[0], parts[1], "go", source)
        return deps

    def _parse_csproj(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except OSError:
            return deps

        patterns = [
            re.compile(
                r'<PackageReference\s+Include="([^"]+)"[^>]*Version="([^"]+)"',
                re.I,
            ),
            re.compile(
                r'<PackageReference\s+Version="([^"]+)"[^>]*Include="([^"]+)"',
                re.I,
            ),
        ]
        for pat in patterns:
            for match in pat.finditer(content):
                if pat.pattern.startswith("<PackageReference\\s+Include"):
                    self._add(deps, match.group(1), match.group(2), "nuget", source)
                else:
                    self._add(deps, match.group(2), match.group(1), "nuget", source)
        return deps

    def _parse_packages_config(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            for match in re.finditer(
                r'<package\s+id="([^"]+)"\s+version="([^"]+)"',
                content,
                re.I,
            ):
                self._add(deps, match.group(1), match.group(2), "nuget", source)
        except OSError:
            pass
        return deps

    def _parse_directory_packages_props(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            for match in re.finditer(
                r'<PackageVersion\s+Include="([^"]+)"\s+Version="([^"]+)"',
                content,
                re.I,
            ):
                self._add(deps, match.group(1), match.group(2), "nuget", source)
        except OSError:
            pass
        return deps

    def _parse_gemfile(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    match = re.match(
                        r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""",
                        line.strip(),
                    )
                    if match:
                        self._add(
                            deps,
                            match.group(1),
                            match.group(2) or "unknown",
                            "rubygems",
                            source,
                        )
        except OSError:
            pass
        return deps

    def _parse_cargo_toml(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except OSError:
            return deps

        section = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[dependencies]", "[dev-dependencies]"):
                section = stripped
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = None
                continue
            if section and "=" in stripped and not stripped.startswith("#"):
                key, _, val = stripped.partition("=")
                name = key.strip()
                version = val.strip().strip('"').strip("'")
                if "{" in version:
                    ver_match = re.search(r'version\s*=\s*"([^"]+)"', version)
                    version = ver_match.group(1) if ver_match else "unknown"
                self._add(deps, name, version, "cargo", source)
        return deps

    def _parse_pom_xml(self, path: str, source: str) -> List[ParsedDependency]:
        deps: List[ParsedDependency] = []
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except OSError:
            return deps

        for match in re.finditer(
            r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            content,
            re.I,
        ):
            self._add(deps, match.group(1), match.group(2), "maven", source)
        for match in re.finditer(
            r"<version>([^<]+)</version>\s*<artifactId>([^<]+)</artifactId>",
            content,
            re.I,
        ):
            self._add(deps, match.group(2), match.group(1), "maven", source)
        return deps


def group_dependencies_by_ecosystem(
    deps: Iterable[ParsedDependency],
) -> Dict[str, List[ParsedDependency]]:
    grouped: Dict[str, List[ParsedDependency]] = {}
    for dep in deps:
        eco = dep.ecosystem.lower()
        grouped.setdefault(eco, []).append(dep)
    return grouped
