"""Extract the user-facing prompt from gateway message payloads."""

from __future__ import annotations

import re
from typing import Any

# Apps like AI Goat embed system rules in a single user blob:
#   Instruction: … Question: <user prompt> Answer:
_QUESTION_RE = re.compile(
    r"(?is)\bQuestion:\s*(.*?)\s*(?:Answer:|$)",
)
_INSTRUCTION_PREFIX_RE = re.compile(r"(?is)^\s*Instruction\s*:")
_SYSTEM_RULES_RE = re.compile(r"(?is)\bSet System Rules\b|\bSystem Rules\b")


def looks_like_system_instruction_blob(text: str) -> bool:
    """True when text is an Instruction/Question wrapper, not a bare user prompt."""
    raw = (text or "").strip()
    if not raw:
        return False
    if _INSTRUCTION_PREFIX_RE.match(raw):
        return True
    if _SYSTEM_RULES_RE.search(raw) and re.search(r"(?is)\bQuestion\s*:", raw):
        return True
    return False


def extract_user_prompt_text(text: str) -> str:
    """
    Return the user prompt suitable for traces UI.

    When content is ``Instruction: … Question: <q> Answer:``, return ``<q>``
    (even if empty — never return the Instruction/system-rules blob).
    Otherwise return the original text (stripped).
    """
    raw = (text or "").strip()
    if not raw:
        return ""

    match = _QUESTION_RE.search(raw)
    if match:
        question = (match.group(1) or "").strip()
        question = re.sub(r"(?is)\s*Answer:\s*$", "", question).strip()
        # Matched the Question wrapper — never fall through to Instruction text.
        return question

    # Instruction-only blobs with no Question — not a user prompt.
    if looks_like_system_instruction_blob(raw):
        return ""

    return raw


def display_prompt_preview(text: str, *, empty_label: str = "(empty prompt)") -> str:
    """UI-safe preview: user question only, never system-instruction wrappers."""
    raw = (text or "").strip()
    if not raw:
        return empty_label
    extracted = extract_user_prompt_text(raw)
    if extracted:
        return extracted
    if looks_like_system_instruction_blob(raw):
        return empty_label
    return raw


def _message_content_as_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return ""


def user_text_from_messages(messages: list[Any] | None) -> str:
    """
    Collect user-role content for gateway ingest / display.

    Prefers the last user turn (the active prompt). Strips embedded
    Instruction/Question wrappers when present.
    """
    if not isinstance(messages, list):
        return ""

    user_chunks: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        if (message.get("role") or "").strip().lower() != "user":
            continue
        chunk = _message_content_as_text(message.get("content")).strip()
        if chunk:
            user_chunks.append(chunk)

    if not user_chunks:
        return ""

    # Last user turn is the active prompt; earlier turns are chat history.
    return extract_user_prompt_text(user_chunks[-1])
