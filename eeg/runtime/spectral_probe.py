"""Spectral probe — delegates to runtime ML guard (legacy API surface)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.runtime_ml_guard import assess_runtime_text, runtime_ml_status
from eeg.runtime.script_unmask import unmask_script


@dataclass
class SpectralHit:
    label: str
    score: float
    evidence: list[str] = field(default_factory=list)
    source: str = "runtime_ml_guard"


@dataclass
class SpectralAssessment:
    score: float = 0.0
    label: str = "benign"
    hits: list[SpectralHit] = field(default_factory=list)
    neural_assist: bool = False
    ember_assist: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "label": self.label,
            "neural_assist": self.neural_assist,
            "ember_assist": self.ember_assist,
            "hits": [
                {"label": h.label, "score": round(h.score, 4), "source": h.source}
                for h in self.hits
            ],
            "details": dict(self.details),
        }


def probe_spectrum(text: str) -> SpectralAssessment:
    if not text or not str(text).strip():
        return SpectralAssessment(details={"engines": runtime_ml_status()})
    normalized = unmask_script(str(text))
    ml = assess_runtime_text(normalized)
    details = {"normalized_len": len(normalized), "runtime_ml": ml.to_layer_dict(), "engines": runtime_ml_status()}
    if not ml.triggered:
        return SpectralAssessment(details=details)
    hits = [
        SpectralHit(
            label=h.category,
            score=h.score,
            evidence=[f"{h.provider_id}:{h.category}"],
            source="runtime_ml_guard",
        )
        for h in ml.hits
        if h.triggered
    ]
    top = hits[0] if hits else SpectralHit(label="benign", score=0.0)
    return SpectralAssessment(
        score=ml.score,
        label=top.label,
        hits=hits,
        neural_assist=True,
        ember_assist=False,
        details=details,
    )


def spectral_engine_status() -> dict[str, Any]:
    return runtime_ml_status()
