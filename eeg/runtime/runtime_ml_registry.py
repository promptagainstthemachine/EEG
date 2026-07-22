"""Auditable runtime ML model registry.

Resolves model URIs from YAML config + env overrides:
  - HuggingFace hub id:  org/name
  - Local path:          /abs/path, ./rel/path, file:///abs/path
  - HTTPS:               huggingface.co/... → hub id; other URLs → cached download

Config file:
  default: eeg/runtime/runtime_ml_models.yaml
  override: EEG_RUNTIME_ML_CONFIG=/path/to/custom.yaml

Per-model override:
  EEG_RUNTIME_ML_<PROVIDER_ID>_MODEL=<uri>
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_HF_HOSTS = {"huggingface.co", "www.huggingface.co", "hf.co"}
_DEFAULT_CONFIG_NAME = "runtime_ml_models.yaml"
_LOCK = threading.Lock()
_CACHED: "RuntimeMLRegistry | None" = None


@dataclass(frozen=True)
class ResolvedModel:
    provider_id: str
    category: str
    display_name: str
    configured_uri: str
    resolved_uri: str
    source_type: str  # hub | local | https_hub | https_download
    score_floor: float
    max_length: int
    truncate_chars: int
    positive_labels: tuple[str, ...]
    override_env: str
    config_path: str
    task: str = "text-classification"
    enabled: bool = True
    platform: str = "hf"
    inference: str = "transformers"

    def audit_dict(self, *, ready: bool = False, error: str | None = None) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "category": self.category,
            "display_name": self.display_name,
            "platform": self.platform,
            "inference": self.inference,
            "configured_uri": self.configured_uri,
            "resolved_uri": self.resolved_uri,
            "source_type": self.source_type,
            "score_floor": self.score_floor,
            "max_length": self.max_length,
            "truncate_chars": self.truncate_chars,
            "positive_labels": list(self.positive_labels),
            "override_env": self.override_env,
            "config_path": self.config_path,
            "task": self.task,
            "enabled": self.enabled,
            "ready": ready,
            "error": error,
            "uri_fingerprint": _fingerprint(self.resolved_uri),
            "edition": "oss",
        }


@dataclass
class RuntimeMLRegistry:
    version: int = 1
    enabled: bool = True
    edition: str = "oss"
    task: str = "text-classification"
    config_path: str = ""
    models: list[ResolvedModel] = field(default_factory=list)

    def by_provider(self, provider_id: str) -> ResolvedModel | None:
        for m in self.models:
            if m.provider_id == provider_id:
                return m
        return None

    def audit_dict(self, readiness: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
        readiness = readiness or {}
        return {
            "engine": "runtime_ml_registry",
            "edition": self.edition,
            "version": self.version,
            "enabled": self.enabled and runtime_ml_enabled(),
            "config_path": self.config_path,
            "model_count": len(self.models),
            "allowed_platforms": ["hf", "local"],
            "allowed_inference": ["transformers"],
            "models": [
                {
                    **m.audit_dict(
                        ready=bool((readiness.get(m.provider_id) or {}).get("ready")),
                        error=(readiness.get(m.provider_id) or {}).get("error"),
                    )
                }
                for m in self.models
            ],
        }


def runtime_ml_enabled() -> bool:
    if _env_disabled("EEG_RUNTIME_ML"):
        return False
    if _env_disabled("EEG_AURORA_NEURAL"):
        return False
    return True


def _env_disabled(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return raw in {"0", "false", "no", "off"}


def _fingerprint(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _default_config_path() -> Path:
    return Path(__file__).resolve().parent / _DEFAULT_CONFIG_NAME


def _config_path() -> Path:
    override = os.environ.get("EEG_RUNTIME_ML_CONFIG", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return _default_config_path()


def _load_raw_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        log.warning("Runtime ML config missing at %s — using built-in defaults", path)
        return _builtin_defaults()
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"PyYAML required to load {path}: {exc}") from exc
        data = yaml.safe_load(text) or {}
    elif suffix == ".json":
        data = json.loads(text)
    else:
        # Try YAML first, then JSON
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text) or {}
        except Exception:
            data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Runtime ML config must be a mapping: {path}")
    return data


def _builtin_defaults() -> dict[str, Any]:
    return {
        "version": 1,
        "enabled": True,
        "task": "text-classification",
        "models": [
            {
                "provider_id": "deberta_pi_v2",
                "category": "prompt_injection",
                "display_name": "ProtectAI DeBERTa PI v2",
                "model": "protectai/deberta-v3-base-prompt-injection-v2",
                "score_floor": 0.55,
                "positive_labels": ["INJECTION", "LABEL_1", "PROMPT_INJECTION"],
            },
            {
                "provider_id": "toxic_bert",
                "category": "toxicity",
                "display_name": "Unitary Toxic-BERT",
                "model": "unitary/toxic-bert",
                "score_floor": 0.50,
                "positive_labels": ["toxic", "TOXIC", "LABEL_1"],
            },
            {
                "provider_id": "ai4privacy_pii",
                "category": "pii",
                "display_name": "DistilBERT AI4Privacy PII",
                "model": "Isotonic/distilbert_finetuned_ai4privacy_v2",
                "score_floor": 0.50,
                "positive_labels": ["PII", "LABEL_1", "I-PER", "I-ORG", "I-LOC", "B-PER", "B-ORG"],
            },
        ],
    }


def _provider_env_key(provider_id: str) -> str:
    return f"EEG_RUNTIME_ML_{provider_id.upper()}_MODEL"


def _classify_and_resolve(uri: str) -> tuple[str, str]:
    """Return (resolved_uri, source_type)."""
    raw = (uri or "").strip()
    if not raw:
        raise ValueError("empty model URI")

    if raw.startswith("file://"):
        path = Path(urlparse(raw).path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"local model path not found: {path}")
        return str(path), "local"

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        if host in _HF_HOSTS:
            # https://huggingface.co/{org}/{repo}[/...]
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}", "https_hub"
            raise ValueError(f"cannot parse HF hub id from URL: {raw}")
        # Generic HTTPS — download into HF cache via huggingface_hub if available,
        # otherwise pass URL through (transformers may reject; surfaced in audit error).
        try:
            from huggingface_hub import hf_hub_download  # type: ignore

            # Treat as a single-file URL download into a deterministic cache key.
            cache_dir = Path.home() / ".cache" / "eeg" / "runtime_ml_urls"
            cache_dir.mkdir(parents=True, exist_ok=True)
            name = hashlib.sha256(raw.encode()).hexdigest()[:24]
            dest = cache_dir / name
            if not dest.exists():
                import urllib.request

                tmp = dest.with_suffix(".partial")
                urllib.request.urlretrieve(raw, tmp)  # noqa: S310 — intentional operator-configured URL
                tmp.rename(dest)
            return str(dest), "https_download"
        except Exception as exc:
            log.warning("HTTPS model resolve failed for %s: %s", raw, exc)
            return raw, "https_download"

    # Absolute or relative filesystem path
    path_candidate = Path(raw).expanduser()
    if raw.startswith(("/", "./", "../")) or path_candidate.exists():
        resolved = path_candidate.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"local model path not found: {resolved}")
        return str(resolved), "local"

    # HuggingFace hub id (org/name or org/name@rev)
    if re.match(r"^[\w.-]+/[\w.-]+", raw):
        return raw, "hub"

    # Bare local directory name that exists next to CWD
    if path_candidate.exists():
        return str(path_candidate.resolve()), "local"

    return raw, "hub"


def _row_to_resolved(row: dict[str, Any], *, config_path: str, default_task: str) -> ResolvedModel:
    provider_id = str(row.get("provider_id") or "").strip()
    if not provider_id:
        raise ValueError("model entry missing provider_id")

    platform = str(row.get("platform") or "hf").strip().lower()
    inference = str(row.get("inference") or "transformers").strip().lower().replace("-", "_")
    if inference in {"llama.cpp", "llamacpp"}:
        inference = "llama_cpp"

    # OSS gate: BERT / transformers only
    if platform not in {"hf", "local"}:
        raise ValueError(
            f"OSS runtime ML rejects platform={platform}; allowed: hf|local "
            "(use EEG-SAAS for uri/ollama/llama_cpp)"
        )
    if inference != "transformers":
        raise ValueError(
            f"OSS runtime ML rejects inference={inference}; allowed: transformers "
            "(use EEG-SAAS for ollama/llama_cpp)"
        )

    env_key = _provider_env_key(provider_id)
    # Prefer model_path for local; else model (hub id)
    model_path = str(row.get("model_path") or "").strip()
    configured = (
        os.environ.get(env_key, "").strip()
        or model_path
        or str(row.get("model") or "").strip()
    )
    if not configured:
        raise ValueError(f"model URI missing for provider {provider_id}")
    resolved, source_type = _classify_and_resolve(configured)
    labels = row.get("positive_labels") or []
    return ResolvedModel(
        provider_id=provider_id,
        category=str(row.get("category") or provider_id),
        display_name=str(row.get("display_name") or provider_id),
        configured_uri=configured,
        resolved_uri=resolved,
        source_type=source_type,
        score_floor=float(row.get("score_floor", 0.55)),
        max_length=int(row.get("max_length", 512)),
        truncate_chars=int(row.get("truncate_chars", 4000)),
        positive_labels=tuple(str(x) for x in labels),
        override_env=env_key if os.environ.get(env_key, "").strip() else "",
        config_path=config_path,
        task=str(row.get("task") or default_task),
        enabled=not _env_disabled(f"EEG_RUNTIME_ML_{provider_id.upper()}"),
        platform=platform,
        inference=inference,
    )


def load_registry(*, force: bool = False) -> RuntimeMLRegistry:
    global _CACHED
    with _LOCK:
        if _CACHED is not None and not force:
            return _CACHED
        path = _config_path()
        raw = _load_raw_config(path)
        models: list[ResolvedModel] = []
        for row in raw.get("models") or []:
            if not isinstance(row, dict):
                continue
            try:
                models.append(
                    _row_to_resolved(
                        row,
                        config_path=str(path),
                        default_task=str(raw.get("task") or "text-classification"),
                    )
                )
            except Exception as exc:
                log.warning("Skipping runtime ML model row %s: %s", row.get("provider_id"), exc)
        reg = RuntimeMLRegistry(
            version=int(raw.get("version") or 1),
            enabled=bool(raw.get("enabled", True)),
            edition=str(raw.get("edition") or "oss"),
            task=str(raw.get("task") or "text-classification"),
            config_path=str(path),
            models=models,
        )
        _CACHED = reg
        return reg


def reload_registry() -> RuntimeMLRegistry:
    return load_registry(force=True)


def registry_as_dict() -> dict[str, Any]:
    return asdict(load_registry())
