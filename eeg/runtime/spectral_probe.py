from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.aurora_veil import aurora_score, aurora_status
from eeg.runtime.ember_pulse import ember_status, pulse_classify
from eeg.runtime.script_unmask import unmask_script

_SEED_WEIGHTS: dict[str, dict[str, float]] = {
    "prompt_injection": {
        "ignore previous": 0.88,
        "ignore all previous": 0.9,
        "ignore all prior": 0.88,
        "system prompt": 0.72,
        "override safety": 0.86,
        "developer mode": 0.7,
        "new instructions": 0.68,
        "disregard your": 0.8,
        "disregard the system": 0.84,
    },
    "jailbreak": {
        "do anything now": 0.92,
        "jailbreak": 0.85,
        "no restrictions": 0.78,
        "you are now dan": 0.93,
        "you are now dude": 0.9,
        "without restrictions": 0.8,
        "unrestricted mode": 0.78,
    },
    "exfiltration": {
        "exfiltrate": 0.86,
        "steal secrets": 0.88,
        "send credentials": 0.84,
        "pastebin.com": 0.8,
        "169.254.169.254": 0.92,
        "metadata.google.internal": 0.9,
    },
    "tool_abuse": {
        "rm -rf /": 0.92,
        "os.system(": 0.84,
        "subprocess.popen": 0.8,
        "../..": 0.75,
        "eval(": 0.7,
        "curl http://169.254": 0.9,
    },
    "toxicity": {
        "kill yourself": 0.9,
        "make a bomb": 0.92,
        "make bomb": 0.92,
        "how to make a bomb": 0.93,
        "how to make bomb": 0.93,
        "build a bomb": 0.92,
        "build bomb": 0.91,
        "pipe bomb": 0.9,
        "molotov cocktail": 0.88,
    },
}


@dataclass
class SpectralHit:
    label: str
    score: float
    evidence: list[str] = field(default_factory=list)
    source: str = "lexicon"


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
                {
                    "label": h.label,
                    "score": round(h.score, 4),
                    "source": h.source,
                }
                for h in self.hits
            ],
            "details": dict(self.details),
        }


def _literal_scores(text: str) -> list[SpectralHit]:
    lower = text.lower()
    hits: list[SpectralHit] = []
    for label, phrases in _SEED_WEIGHTS.items():
        evidence: list[str] = []
        score = 0.0
        for phrase, weight in phrases.items():
            if phrase in lower:
                evidence.append(phrase)
                score = max(score, weight)
                if len(evidence) > 1:
                    score = min(0.98, score + 0.03 * (len(evidence) - 1))
        if evidence:
            hits.append(
                SpectralHit(
                    label=label,
                    score=score,
                    evidence=evidence[:5],
                    source="lexicon",
                )
            )
    hits.sort(key=lambda h: h.score, reverse=True)
    return hits


def probe_spectrum(text: str) -> SpectralAssessment:
    if not text or not str(text).strip():
        return SpectralAssessment()
    normalized = unmask_script(str(text))
    hits = _literal_scores(normalized)

    ember = pulse_classify(normalized)
    ember_assist = False
    if ember.triggered and ember.score > 0:
        ember_assist = True
        hits.append(
            SpectralHit(
                label=ember.label,
                score=ember.score,
                evidence=[f"ember:{ember.label}"],
                source="ember_pulse",
            )
        )

    aurora = aurora_score(normalized)
    neural_assist = False
    if aurora.triggered and aurora.score > 0:
        neural_assist = True
        hits.append(
            SpectralHit(
                label=aurora.label,
                score=aurora.score,
                evidence=[f"aurora:{aurora.label}"],
                source="aurora_veil",
            )
        )

    hits.sort(key=lambda h: h.score, reverse=True)
    details = {
        "normalized_len": len(normalized),
        "ember": ember.to_layer_dict(),
        "aurora": aurora.to_layer_dict(),
        "engines": {
            "ember_pulse": ember_status(),
            "aurora_veil": aurora_status(),
        },
    }
    if not hits:
        return SpectralAssessment(details=details)

    top = hits[0]
    return SpectralAssessment(
        score=top.score,
        label=top.label,
        hits=hits[:8],
        neural_assist=neural_assist,
        ember_assist=ember_assist,
        details=details,
    )


def spectral_engine_status() -> dict[str, Any]:
    return {
        "ember_pulse": ember_status(),
        "aurora_veil": aurora_status(),
    }
