"""Runtime ML guard — multi-model wrap before agent dispatch (no regex scoring).

Model URIs come from the auditable registry (`runtime_ml_models.yaml`):
  hub id | local path | https URL
  Override file: EEG_RUNTIME_ML_CONFIG
  Override one:  EEG_RUNTIME_ML_<PROVIDER>_MODEL

Static code analysis (Semgrep, etc.) is separate and unchanged.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.runtime_ml_registry import (
    ResolvedModel,
    _fingerprint,
    load_registry,
    reload_registry,
    runtime_ml_enabled,
)

log = logging.getLogger(__name__)

JAILBREAK_SCORE_FLOOR = 0.65

# PI / jailbreak classifiers are trained on user prompts. Scoring assistant
# generations with them causes false blocks on benign instructional text.
_REQUEST_ONLY_CATEGORIES = frozenset({"prompt_injection", "jailbreak", "injection"})
# Content-safety models may share category but are valid on outputs.
_RESPONSE_ALLOWED_PROVIDERS = frozenset({"llama_guard3", "llama_guard3_ollama"})


@dataclass
class RuntimeMLHit:
    category: str
    score: float
    label: str
    model_id: str
    provider_id: str
    triggered: bool = False
    ready: bool = False
    raw_label: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "score": round(self.score, 4),
            "label": self.label,
            "model_id": self.model_id,
            "provider_id": self.provider_id,
            "triggered": self.triggered,
            "ready": self.ready,
            "raw_label": self.raw_label,
            "details": dict(self.details),
        }


@dataclass
class RuntimeMLAssessment:
    score: float = 0.0
    triggered: bool = False
    ready: bool = False
    enabled: bool = False
    hits: list[RuntimeMLHit] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    layer_scores: dict[str, float] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "triggered": self.triggered,
            "ready": self.ready,
            "enabled": self.enabled,
            "engine": "runtime_ml_guard",
            "categories": list(self.categories),
            "layer_scores": {k: round(v, 4) for k, v in self.layer_scores.items()},
            "hits": [h.to_dict() for h in self.hits],
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class RuntimeModelSpec:
    """Back-compat view of a registry model (used by check scripts)."""

    provider_id: str
    model_id: str
    category: str
    display_name: str
    positive_labels: tuple[str, ...]
    score_floor: float = 0.55
    max_length: int = 512
    truncate_chars: int = 4000


class _RuntimeModelsProxy:
    def _specs(self) -> tuple[RuntimeModelSpec, ...]:
        reg = load_registry()
        return tuple(
            RuntimeModelSpec(
                provider_id=m.provider_id,
                model_id=m.resolved_uri,
                category=m.category,
                display_name=m.display_name,
                positive_labels=m.positive_labels,
                score_floor=m.score_floor,
                max_length=m.max_length,
                truncate_chars=m.truncate_chars,
            )
            for m in reg.models
            if m.enabled
        )

    def __iter__(self):
        return iter(self._specs())

    def __len__(self):
        return len(self._specs())

    def __getitem__(self, idx):
        return self._specs()[idx]


RUNTIME_MODELS = _RuntimeModelsProxy()


def _resolved(provider_id: str) -> ResolvedModel | None:
    return load_registry().by_provider(provider_id)


class _RuntimeClassifier:
    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id
        self._pipeline = None
        self._ready = False
        self._error: str | None = None
        self._loaded_uri: str | None = None
        self._lock = threading.Lock()

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def last_error(self) -> str | None:
        return self._error

    def _spec(self) -> ResolvedModel | None:
        return _resolved(self.provider_id)

    def _ensure_loaded(self) -> bool:
        spec = self._spec()
        if spec is None or not spec.enabled:
            self._error = "provider_disabled_or_missing"
            return False
        if self._ready and self._pipeline is not None and self._loaded_uri == spec.resolved_uri:
            return True
        with self._lock:
            spec = self._spec()
            if spec is None or not spec.enabled:
                self._error = "provider_disabled_or_missing"
                return False
            if self._ready and self._pipeline is not None and self._loaded_uri == spec.resolved_uri:
                return True
            if not runtime_ml_enabled():
                return False
            try:
                from transformers import pipeline as hf_pipeline  # type: ignore
            except Exception as exc:
                self._error = f"transformers_unavailable: {exc}"
                log.warning("Runtime ML %s: transformers missing", self.provider_id)
                return False
            try:
                self._pipeline = hf_pipeline(
                    spec.task or "text-classification",
                    model=spec.resolved_uri,
                    truncation=True,
                    max_length=spec.max_length,
                    device=-1,
                )
                self._ready = True
                self._error = None
                self._loaded_uri = spec.resolved_uri
                log.info(
                    "Runtime ML ready provider=%s source=%s model=%s",
                    self.provider_id,
                    spec.source_type,
                    spec.resolved_uri,
                )
                return True
            except Exception as exc:
                self._pipeline = None
                self._ready = False
                self._error = str(exc)
                self._loaded_uri = None
                log.warning("Runtime ML %s load failed: %s", self.provider_id, exc)
                return False

    def classify(self, text: str) -> RuntimeMLHit:
        spec = self._spec()
        model_id = spec.resolved_uri if spec else self.provider_id
        category = spec.category if spec else self.provider_id
        empty = RuntimeMLHit(
            category=category,
            score=0.0,
            label="benign",
            model_id=model_id,
            provider_id=self.provider_id,
            triggered=False,
            ready=False,
        )
        if not text or not str(text).strip():
            empty.ready = True
            return empty
        if not self._ensure_loaded() or self._pipeline is None or spec is None:
            empty.details = {
                "error": self._error or "not_ready",
                "source_type": getattr(spec, "source_type", None),
                "configured_uri": getattr(spec, "configured_uri", None),
            }
            return empty
        try:
            clipped = str(text)[: spec.truncate_chars]
            result = self._pipeline(clipped)
            row = result[0] if isinstance(result, list) and result else result
            raw_label = str((row or {}).get("label") or "")
            score = float((row or {}).get("score") or 0.0)
            upper = raw_label.upper()
            positive = any(tok.upper() in upper for tok in spec.positive_labels)
            if self.provider_id == "toxic_bert" and "toxic" in raw_label.lower():
                positive = True
            if self.provider_id == "ai4privacy_pii" and not positive:
                positive = (
                    upper not in {"O", "NON-PII", "LABEL_0", "SAFE", "BENIGN", ""}
                    and score >= spec.score_floor
                )
            triggered = positive and score >= spec.score_floor
            return RuntimeMLHit(
                category=category,
                score=round(score, 4) if triggered else 0.0,
                label=category if triggered else "benign",
                model_id=spec.resolved_uri,
                provider_id=self.provider_id,
                triggered=triggered,
                ready=True,
                raw_label=raw_label,
                details={
                    "raw_score": round(score, 4),
                    "score_floor": spec.score_floor,
                    "source_type": spec.source_type,
                    "configured_uri": spec.configured_uri,
                    "resolved_uri": spec.resolved_uri,
                    "uri_fingerprint": _fingerprint(spec.resolved_uri),
                },
            )
        except Exception as exc:
            log.warning("Runtime ML %s inference failed: %s", self.provider_id, exc)
            return RuntimeMLHit(
                category=category,
                score=0.0,
                label="benign",
                model_id=model_id,
                provider_id=self.provider_id,
                triggered=False,
                ready=False,
                details={"error": str(exc)},
            )


_CLASSIFIERS: dict[str, _RuntimeClassifier] = {}
_CLASSIFIER_LOCK = threading.Lock()


def _provider_id(spec_or_id: Any) -> str:
    if isinstance(spec_or_id, str):
        return spec_or_id
    pid = getattr(spec_or_id, "provider_id", None)
    return str(pid or spec_or_id)


def _get_classifier(spec_or_id: Any) -> _RuntimeClassifier:
    provider_id = _provider_id(spec_or_id)
    with _CLASSIFIER_LOCK:
        if provider_id not in _CLASSIFIERS:
            _CLASSIFIERS[provider_id] = _RuntimeClassifier(provider_id)
        return _CLASSIFIERS[provider_id]


def _jailbreak_from_pi(hit: RuntimeMLHit) -> RuntimeMLHit | None:
    if not hit.triggered or hit.provider_id != "deberta_pi_v2":
        return None
    raw = float((hit.details or {}).get("raw_score") or hit.score or 0.0)
    if raw < JAILBREAK_SCORE_FLOOR:
        return None
    return RuntimeMLHit(
        category="jailbreak",
        score=round(raw, 4),
        label="jailbreak",
        model_id=hit.model_id,
        provider_id=hit.provider_id,
        triggered=True,
        ready=hit.ready,
        raw_label=hit.raw_label,
        details={"derived_from": "deberta_pi_v2", "raw_score": raw},
    )


def assess_runtime_text(text: str, *, phase: str = "request") -> RuntimeMLAssessment:
    """Run all runtime ML classifiers; return fused assessment."""
    enabled = runtime_ml_enabled()
    reg = load_registry()
    if not enabled or not reg.enabled:
        return RuntimeMLAssessment(enabled=False, ready=False, details={"phase": phase})

    if not text or not str(text).strip():
        return RuntimeMLAssessment(enabled=enabled, ready=enabled, details={"phase": phase})

    hits: list[RuntimeMLHit] = []
    layer_scores: dict[str, float] = {}
    categories: set[str] = set()
    any_ready = False

    skipped: list[str] = []
    for model in reg.models:
        if not model.enabled:
            continue
        if (
            phase == "response"
            and model.category in _REQUEST_ONLY_CATEGORIES
            and model.provider_id not in _RESPONSE_ALLOWED_PROVIDERS
        ):
            skipped.append(model.provider_id)
            continue
        hit = _get_classifier(model.provider_id).classify(text)
        if hit.ready:
            any_ready = True
        hits.append(hit)
        if hit.triggered:
            categories.add(hit.category)
            layer_scores[hit.category] = max(layer_scores.get(hit.category, 0.0), hit.score)
            jb = _jailbreak_from_pi(hit)
            if jb:
                hits.append(jb)
                categories.add(jb.category)
                layer_scores[jb.category] = max(layer_scores.get(jb.category, 0.0), jb.score)

    fused = max(layer_scores.values()) if layer_scores else 0.0
    return RuntimeMLAssessment(
        score=fused,
        triggered=fused > 0,
        ready=any_ready,
        enabled=enabled,
        hits=hits,
        categories=sorted(categories),
        layer_scores=layer_scores,
        details={
            "phase": phase,
            "model_count": len(reg.models),
            "skipped_providers": skipped,
            "config_path": reg.config_path,
        },
    )


def assess_tool_runtime(text: str) -> RuntimeMLAssessment:
    """ML wrap for tool name + arguments."""
    base = assess_runtime_text(text, phase="request")
    if not base.triggered:
        return base
    pi_model = load_registry().by_provider("deberta_pi_v2")
    model_id = pi_model.resolved_uri if pi_model else "runtime_ml_guard"
    tool_hit = RuntimeMLHit(
        category="tool_abuse",
        score=base.score,
        label="tool_abuse",
        model_id=model_id,
        provider_id="runtime_tool_wrap",
        triggered=True,
        ready=base.ready,
        details={
            "derived_from": "runtime_ml_guard",
            "source_hits": [h.category for h in base.hits if h.triggered],
        },
    )
    hits = list(base.hits) + [tool_hit]
    categories = sorted(set(base.categories) | {"tool_abuse"})
    layer_scores = dict(base.layer_scores)
    layer_scores["tool_abuse"] = max(layer_scores.get("tool_abuse", 0.0), base.score)
    return RuntimeMLAssessment(
        score=max(base.score, layer_scores["tool_abuse"]),
        triggered=True,
        ready=base.ready,
        enabled=base.enabled,
        hits=hits,
        categories=categories,
        layer_scores=layer_scores,
        details={**base.details, "tool_wrap": True},
    )


def runtime_ml_status() -> dict[str, Any]:
    reg = load_registry()
    readiness: dict[str, dict[str, Any]] = {}
    for model in reg.models:
        clf = _get_classifier(model.provider_id)
        readiness[model.provider_id] = {"ready": clf.is_ready, "error": clf.last_error}
    return reg.audit_dict(readiness)


def reload_runtime_ml() -> dict[str, Any]:
    """Reload YAML/env registry and drop loaded pipelines (next call reloads models)."""
    with _CLASSIFIER_LOCK:
        _CLASSIFIERS.clear()
    reload_registry()
    return runtime_ml_status()


PI_SIGIL_CATEGORIES = frozenset({"prompt_injection", "injection", "jailbreak"})
PI_EMBER_LABELS = PI_SIGIL_CATEGORIES


@dataclass
class PINeuralAssessment:
    score: float = 0.0
    label: str = "benign"
    triggered: bool = False
    ready: bool = False
    enabled: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "label": self.label,
            "triggered": self.triggered,
            "ready": self.ready,
            "enabled": self.enabled,
            "engine": "runtime_ml_guard",
            "details": dict(self.details),
        }


def assess_prompt_injection(text: str) -> PINeuralAssessment:
    result = assess_runtime_text(text, phase="request")
    pi_hit = next((h for h in result.hits if h.category == "prompt_injection" and h.triggered), None)
    if pi_hit:
        return PINeuralAssessment(
            score=pi_hit.score,
            label="prompt_injection",
            triggered=True,
            ready=pi_hit.ready,
            enabled=result.enabled,
            details=pi_hit.to_dict(),
        )
    return PINeuralAssessment(
        ready=result.ready,
        enabled=result.enabled,
        details=result.to_layer_dict(),
    )


def pi_engine_status() -> dict[str, Any]:
    return runtime_ml_status()
