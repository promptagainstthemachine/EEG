from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_SCORE_FLOOR = 0.55


@dataclass
class AuroraAssessment:
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
            "details": dict(self.details),
        }


def _neural_enabled() -> bool:
    return os.environ.get("EEG_AURORA_NEURAL", os.environ.get("EEG_SPECTRAL_NEURAL", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _model_id() -> str:
    return (
        os.environ.get("EEG_AURORA_MODEL")
        or os.environ.get("EEG_SPECTRAL_MODEL")
        or _DEFAULT_MODEL
    )


class AuroraVeil:
    def __init__(self) -> None:
        self.enabled = _neural_enabled()
        self.ready = False
        self._pipeline = None
        self._model_id = _model_id()
        if self.enabled:
            self._boot()

    def _boot(self) -> None:
        try:
            from transformers import pipeline as hf_pipeline  # type: ignore
        except Exception:
            self.ready = False
            return
        try:
            self._pipeline = hf_pipeline(
                "text-classification",
                model=self._model_id,
                truncation=True,
                max_length=512,
                device=-1,
            )
            self.ready = True
        except Exception:
            self._pipeline = None
            self.ready = False

    def score_text(self, text: str) -> AuroraAssessment:
        if not self.enabled:
            return AuroraAssessment(enabled=False, ready=False, details={"engine": "aurora_veil"})
        if not self.ready or self._pipeline is None:
            return AuroraAssessment(
                enabled=True,
                ready=False,
                details={"engine": "aurora_veil", "model": self._model_id},
            )
        try:
            result = self._pipeline((text or "")[:4000])
            row = result[0] if isinstance(result, list) and result else result
            raw_label = str((row or {}).get("label") or "").upper()
            score = float((row or {}).get("score") or 0.0)
            if "INJECTION" in raw_label and score >= _SCORE_FLOOR:
                return AuroraAssessment(
                    score=round(score, 4),
                    label="prompt_injection",
                    triggered=True,
                    ready=True,
                    enabled=True,
                    details={
                        "engine": "aurora_veil",
                        "model": self._model_id,
                        "raw_label": raw_label,
                    },
                )
            return AuroraAssessment(
                score=0.0,
                label="benign",
                triggered=False,
                ready=True,
                enabled=True,
                details={
                    "engine": "aurora_veil",
                    "model": self._model_id,
                    "raw_label": raw_label,
                },
            )
        except Exception:
            return AuroraAssessment(
                enabled=True,
                ready=False,
                details={"engine": "aurora_veil", "model": self._model_id},
            )


_VEIL: AuroraVeil | None = None
_LOCK = threading.Lock()


def get_aurora_veil() -> AuroraVeil:
    global _VEIL
    if _VEIL is None:
        with _LOCK:
            if _VEIL is None:
                _VEIL = AuroraVeil()
    return _VEIL


def aurora_score(text: str) -> AuroraAssessment:
    if not text or not str(text).strip():
        return AuroraAssessment(enabled=_neural_enabled(), ready=True)
    return get_aurora_veil().score_text(str(text))


def aurora_status() -> dict[str, Any]:
    veil = get_aurora_veil()
    return {
        "engine": "aurora_veil",
        "enabled": bool(veil.enabled),
        "ready": bool(veil.ready),
        "model": veil._model_id,
    }
