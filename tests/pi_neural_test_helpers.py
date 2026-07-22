"""Shared runtime ML mock for tests (no transformers required)."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from eeg.runtime.runtime_ml_guard import RuntimeMLAssessment, RuntimeMLHit


def mock_runtime_ml(text: str, *, phase: str = "request") -> RuntimeMLAssessment:
    lower = (text or "").lower()
    hits: list[RuntimeMLHit] = []
    layer_scores: dict[str, float] = {}
    categories: list[str] = []

    if "ignore" in lower and "previous" in lower:
        hits.append(
            RuntimeMLHit(
                category="prompt_injection",
                score=0.92,
                label="prompt_injection",
                model_id="protectai/deberta-v3-base-prompt-injection-v2",
                provider_id="deberta_pi_v2",
                triggered=True,
                ready=True,
                details={"raw_score": 0.92},
            )
        )
        hits.append(
            RuntimeMLHit(
                category="jailbreak",
                score=0.92,
                label="jailbreak",
                model_id="protectai/deberta-v3-base-prompt-injection-v2",
                provider_id="deberta_pi_v2",
                triggered=True,
                ready=True,
                details={"derived_from": "deberta_pi_v2", "raw_score": 0.92},
            )
        )
        layer_scores.update({"prompt_injection": 0.92, "jailbreak": 0.92})
        categories.extend(["prompt_injection", "jailbreak"])

    if "kill yourself" in lower or "hate you" in lower:
        hits.append(
            RuntimeMLHit(
                category="toxicity",
                score=0.88,
                label="toxicity",
                model_id="unitary/toxic-bert",
                provider_id="toxic_bert",
                triggered=True,
                ready=True,
                details={"raw_score": 0.88},
            )
        )
        layer_scores["toxicity"] = 0.88
        categories.append("toxicity")

    if "@" in text and ".com" in lower:
        hits.append(
            RuntimeMLHit(
                category="pii",
                score=0.55,
                label="pii",
                model_id="Isotonic/distilbert_finetuned_ai4privacy_v2",
                provider_id="ai4privacy_pii",
                triggered=True,
                ready=True,
                details={"raw_score": 0.55},
            )
        )
        layer_scores["pii"] = 0.55
        categories.append("pii")

    if "rm -rf" in lower or "eval(" in lower:
        hits.append(
            RuntimeMLHit(
                category="tool_abuse",
                score=0.90,
                label="tool_abuse",
                model_id="protectai/deberta-v3-base-prompt-injection-v2",
                provider_id="runtime_tool_wrap",
                triggered=True,
                ready=True,
            )
        )
        layer_scores["tool_abuse"] = 0.90
        categories.append("tool_abuse")

    fused = max(layer_scores.values()) if layer_scores else 0.0
    return RuntimeMLAssessment(
        score=fused,
        triggered=fused > 0,
        ready=True,
        enabled=True,
        hits=hits,
        categories=sorted(set(categories)),
        layer_scores=layer_scores,
        details={"phase": phase, "mock": True},
    )


def mock_tool_runtime(text: str) -> RuntimeMLAssessment:
    base = mock_runtime_ml(text)
    if "rm -rf" in (text or "").lower() or "eval(" in (text or "").lower():
        if "tool_abuse" not in base.categories:
            base.categories.append("tool_abuse")
            base.layer_scores["tool_abuse"] = 0.90
            base.score = max(base.score, 0.90)
            base.triggered = True
    return base


# Legacy alias
mock_pi_assessment = mock_runtime_ml


@contextmanager
def mock_deberta_pi():
    with patch("eeg.runtime.runtime_ml_guard.assess_runtime_text", side_effect=mock_runtime_ml), patch(
        "eeg.runtime.runtime_ml_guard.assess_tool_runtime", side_effect=mock_tool_runtime
    ), patch("eeg.runtime.risk_scorer.assess_runtime_text", side_effect=mock_runtime_ml), patch(
        "eeg.runtime.lattice_pipeline.assess_runtime_text", side_effect=mock_runtime_ml
    ), patch(
        "eeg.runtime.lattice_pipeline.assess_tool_runtime", side_effect=mock_tool_runtime
    ), patch(
        "eeg.runtime.spectral_probe.assess_runtime_text", side_effect=mock_runtime_ml
    ), patch(
        "eeg.runtime.shard_buffer.assess_runtime_text", side_effect=mock_runtime_ml
    ), patch(
        "eeg.runtime.ember_pulse.assess_runtime_text", side_effect=mock_runtime_ml
    ):
        yield
