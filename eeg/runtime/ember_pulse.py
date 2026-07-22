"""Ember pulse — ML-only runtime classifier (legacy name).

Hardcoded hashed-ngram logistic weights were removed; this module now
delegates to `runtime_ml_guard` so detection cannot be bypassed by
pattern obfuscation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.runtime_ml_guard import assess_runtime_text, runtime_ml_status


@dataclass
class EmberAssessment:
    score: float = 0.0
    label: str = "benign"
    triggered: bool = False
    ready: bool = False
    class_probs: dict[str, float] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "label": self.label,
            "triggered": self.triggered,
            "ready": self.ready,
            "class_probs": {k: round(v, 4) for k, v in self.class_probs.items()},
            "details": dict(self.details),
        }


def pulse_classify(text: str) -> EmberAssessment:
    if not text or not str(text).strip():
        return EmberAssessment(ready=True)
    ml = assess_runtime_text(str(text), phase="request")
    label = "benign"
    if ml.triggered and ml.categories:
        # Prefer highest layer score category
        if ml.layer_scores:
            label = max(ml.layer_scores.items(), key=lambda kv: kv[1])[0]
        else:
            label = ml.categories[0]
    probs = {k: float(v) for k, v in ml.layer_scores.items()}
    if label == "benign" or not ml.triggered:
        probs.setdefault("benign", 1.0)
    return EmberAssessment(
        score=ml.score if ml.triggered else 0.0,
        label=label if ml.triggered else "benign",
        triggered=ml.triggered,
        ready=ml.ready,
        class_probs=probs,
        details={"engine": "runtime_ml_guard", "runtime_ml": ml.to_layer_dict()},
    )


def ember_status() -> dict[str, Any]:
    status = runtime_ml_status()
    status["engine"] = "ember_pulse"
    status["backend"] = "runtime_ml_guard"
    return status


# Legacy no-op model accessor kept for import compatibility
class EmberPulseModel:
    ready = True

    def score_text(self, text: str) -> EmberAssessment:
        return pulse_classify(text)


def get_ember_model() -> EmberPulseModel:
    return EmberPulseModel()
