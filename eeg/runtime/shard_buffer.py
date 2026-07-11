"""Shard buffer — rolling fragment reassembly for split-payload detection."""

from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from eeg.runtime.sigil_weave import weave_sigils
from eeg.runtime.spectral_probe import probe_spectrum


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def looks_like_fragment(text: str) -> bool:
    """True when a piece is more shard-like than a complete utterance."""
    stripped = (text or "").strip()
    if not stripped:
        return False

    words = stripped.split()
    dens = shannon_entropy(stripped)
    spaces = stripped.count(" ")
    ends_sentence = stripped[-1] in ".?!"

    # Complete, low-entropy utterances are never treated as shards.
    if ends_sentence and len(words) >= 4 and dens < 4.0:
        return False
    if len(words) >= 8 and dens < 4.0 and spaces >= 5:
        return False

    if len(stripped) < 28:
        return True
    if len(words) <= 4 and dens >= 3.8:
        return True
    if dens >= 4.2 and spaces < max(3, len(stripped) // 14):
        return True
    if dens >= 4.8 and len(words) <= 14 and not ends_sentence:
        return True
    # Incomplete mid-length clauses (no terminal punctuation) can be shards.
    if not ends_sentence and len(stripped) < 72 and len(words) <= 8:
        return True
    return False


@dataclass
class ShardAssessment:
    score: float = 0.0
    entropy: float = 0.0
    reassembled_len: int = 0
    triggered: bool = False
    categories: list[str] = field(default_factory=list)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "entropy": round(self.entropy, 4),
            "reassembled_len": self.reassembled_len,
            "triggered": self.triggered,
            "categories": list(self.categories),
        }


class ShardBuffer:
    """
    Per-session rolling concatenation of short fragments.
    Detects payloads split across messages that individually look benign.
    Full, well-formed utterances do not pollute the buffer.
    """

    def __init__(
        self,
        *,
        max_sessions: int = 256,
        max_chars: int = 8000,
        min_piece: int = 8,
        entropy_budget: float = 180.0,
        min_fragments_for_budget: int = 3,
    ):
        self.max_sessions = max_sessions
        self.max_chars = max_chars
        self.min_piece = min_piece
        self.entropy_budget = entropy_budget
        self.min_fragments_for_budget = min_fragments_for_budget
        self._buffers: OrderedDict[str, str] = OrderedDict()
        self._entropy_spent: dict[str, float] = {}
        self._fragment_counts: dict[str, int] = {}
        self._touched: dict[str, float] = {}

    def _touch(self, session_id: str) -> None:
        self._touched[session_id] = time.time()
        if session_id in self._buffers:
            self._buffers.move_to_end(session_id)
        while len(self._buffers) > self.max_sessions:
            old, _ = self._buffers.popitem(last=False)
            self._entropy_spent.pop(old, None)
            self._fragment_counts.pop(old, None)
            self._touched.pop(old, None)

    def clear(self, session_id: str) -> None:
        sid = (session_id or "default").strip() or "default"
        self._buffers.pop(sid, None)
        self._entropy_spent.pop(sid, None)
        self._fragment_counts.pop(sid, None)
        self._touched.pop(sid, None)

    def ingest(self, session_id: str, piece: str) -> ShardAssessment:
        sid = (session_id or "default").strip() or "default"
        text = (piece or "").strip()
        if len(text) < self.min_piece:
            return ShardAssessment()

        if not looks_like_fragment(text):
            self.clear(sid)
            return ShardAssessment()

        self._touch(sid)
        prev = self._buffers.get(sid, "")
        merged = (prev + "\n" + text)[-self.max_chars :]
        self._buffers[sid] = merged
        self._fragment_counts[sid] = self._fragment_counts.get(sid, 0) + 1

        ent = shannon_entropy(text)
        spent = self._entropy_spent.get(sid, 0.0) + ent * min(len(text), 64)
        self._entropy_spent[sid] = spent
        fragments = self._fragment_counts[sid]

        sigils = weave_sigils(merged)
        spectral = probe_spectrum(merged)
        score = max(sigils.score, spectral.score)
        categories = sorted(
            set(sigils.categories + ([spectral.label] if spectral.score >= 0.4 else []))
        )

        budget_hit = (
            fragments >= self.min_fragments_for_budget
            and spent > self.entropy_budget
            and len(merged) >= 64
            and score >= 0.28
        )
        if budget_hit:
            score = max(score, 0.72)
            categories = sorted(set(categories + ["shard_entropy_budget"]))

        triggered = (sigils.score >= 0.55 or spectral.score >= 0.55) or budget_hit
        return ShardAssessment(
            score=score if triggered else 0.0,
            entropy=ent,
            reassembled_len=len(merged),
            triggered=triggered,
            categories=categories if triggered else [],
        )

    def session_fingerprint(self, session_id: str) -> str:
        blob = self._buffers.get(session_id, "")
        return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()[:16]
