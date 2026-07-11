"""Normalize LLM text before runtime scoring (evasion resistance)."""

from __future__ import annotations

from eeg.runtime.script_unmask import unmask_script


def strip_zero_width(text: str) -> str:
    from eeg.runtime.script_unmask import strip_invisible

    return strip_invisible(text)


def unicode_nfkc(text: str) -> str:
    import unicodedata

    return unicodedata.normalize("NFKC", text)


def normalize_for_scoring(text: str) -> str:
    """Full script unmask for scoring: NFKC, invisibles, confusables, obfuscation expand."""
    if not text:
        return ""
    return unmask_script(str(text))
