"""Aurora veil — ML-only runtime classifier (legacy name).

Delegates to `runtime_ml_guard` (auditable registry). Prefer importing
from `runtime_ml_guard` directly in new code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.runtime_ml_guard import assess_prompt_injection, runtime_ml_status
from eeg.runtime.runtime_ml_registry import load_registry, runtime_ml_enabled


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


def aurora_score(text: str) -> AuroraAssessment:
    enabled = runtime_ml_enabled()
    if not text or not str(text).strip():
        return AuroraAssessment(enabled=enabled, ready=True)
    pi = assess_prompt_injection(str(text))
    model = load_registry().by_provider("deberta_pi_v2")
    return AuroraAssessment(
        score=pi.score,
        label=pi.label,
        triggered=pi.triggered,
        ready=pi.ready,
        enabled=pi.enabled,
        details={
            "engine": "runtime_ml_guard",
            "model": model.resolved_uri if model else None,
            "source_type": model.source_type if model else None,
            **(pi.details if isinstance(pi.details, dict) else {}),
        },
    )


def aurora_status() -> dict[str, Any]:
    status = runtime_ml_status()
    status["engine"] = "aurora_veil"
    return status


class AuroraVeil:
    def __init__(self) -> None:
        self.enabled = runtime_ml_enabled()
        self.ready = True
        model = load_registry().by_provider("deberta_pi_v2")
        self._model_id = model.resolved_uri if model else ""

    def score_text(self, text: str) -> AuroraAssessment:
        return aurora_score(text)


def get_aurora_veil() -> AuroraVeil:
    return AuroraVeil()
