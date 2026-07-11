"""Code analysis utilities for semantic security scanning."""

from eeg.analysis.code_context import match_span_is_non_executable
from eeg.analysis.semantic_trace import AiPracticeSemanticEngine

__all__ = [
    "match_span_is_non_executable",
    "AiPracticeSemanticEngine",
]
