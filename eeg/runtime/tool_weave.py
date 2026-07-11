"""Tool weave — argument surface scanning and call-chain subsequence detection."""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Iterable

from eeg.runtime.script_unmask import decode_shell_evasions, unmask_script
from eeg.runtime.sigil_weave import weave_sigils

_TOOL_CATEGORY_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("env", re.compile(r"(?i)(^|[^a-z])(env|secret|credential|token|keychain)([^a-z]|$)")),
    ("network", re.compile(r"(?i)(^|[^a-z])(http|curl|wget|request|browse|web_?fetch|fetch_?url)([^a-z]|$)")),
    ("persist", re.compile(r"(?i)(^|[^a-z])(cron|launchd|systemd|startup|autorun)([^a-z]|$)")),
    ("exec", re.compile(r"(?i)(^|[^a-z])(exec|bash|shell|command|terminal|run_?cmd)([^a-z]|$)")),
    ("write", re.compile(r"(?i)(^|[^a-z])(write|put|save|create|edit|patch)([^a-z]|$)")),
    ("read", re.compile(r"(?i)(^|[^a-z])(read|cat|load|open|list_?dir)([^a-z]|$)")),
]

_CHAIN_PATTERNS: list[tuple[str, tuple[str, ...], float]] = [
    ("read_then_exec", ("read", "exec"), 0.78),
    ("env_then_network", ("env", "network"), 0.88),
    ("write_then_persist", ("write", "persist"), 0.84),
    ("read_env_network", ("read", "env", "network"), 0.92),
    ("exec_burst", ("exec", "exec", "exec"), 0.7),
]


@dataclass
class ToolWeaveHit:
    kind: str
    score: float
    detail: str
    categories: list[str] = field(default_factory=list)


@dataclass
class ToolWeaveAssessment:
    score: float = 0.0
    hits: list[ToolWeaveHit] = field(default_factory=list)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "hits": [
                {
                    "kind": h.kind,
                    "score": h.score,
                    "detail": h.detail,
                    "categories": h.categories,
                }
                for h in self.hits
            ],
        }


def classify_tool_name(name: str) -> str:
    for category, rx in _TOOL_CATEGORY_HINTS:
        if rx.search(name or ""):
            return category
    return "other"


def _flatten_args(args: Any) -> str:
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(args)


def scan_tool_call(name: str, arguments: Any = None) -> ToolWeaveAssessment:
    """Scan a single tool invocation name+args through sigils after shell unmask."""
    blob = f"{name} {_flatten_args(arguments)}"
    decoded = decode_shell_evasions(unmask_script(blob))
    sigils = weave_sigils(decoded, packs=("tool_surface", "intent_override"))
    hits: list[ToolWeaveHit] = []
    if sigils.score > 0:
        hits.append(
            ToolWeaveHit(
                kind="arg_sigil",
                score=sigils.score,
                detail=f"tool={name}",
                categories=list(sigils.categories),
            )
        )
    score = max((h.score for h in hits), default=0.0)
    return ToolWeaveAssessment(score=score, hits=hits)


class ToolChainTracker:
    """Sliding history of tool categories; detect dangerous subsequences."""

    def __init__(self, *, maxlen: int = 32, max_gap: int = 3):
        self._history: Deque[str] = deque(maxlen=maxlen)
        self.max_gap = max_gap

    def reset(self) -> None:
        self._history.clear()

    def observe(self, tool_name: str) -> ToolWeaveAssessment:
        category = classify_tool_name(tool_name)
        self._history.append(category)
        hits: list[ToolWeaveHit] = []
        hist = list(self._history)
        for name, sequence, score in _CHAIN_PATTERNS:
            if _subsequence_within_gap(hist, sequence, self.max_gap):
                hits.append(
                    ToolWeaveHit(
                        kind="chain",
                        score=score,
                        detail=name,
                        categories=list(sequence),
                    )
                )
        return ToolWeaveAssessment(
            score=max((h.score for h in hits), default=0.0),
            hits=hits,
        )


def _subsequence_within_gap(history: list[str], sequence: tuple[str, ...], max_gap: int) -> bool:
    if not sequence:
        return False
    start_positions = [i for i, c in enumerate(history) if c == sequence[0]]
    for start in start_positions:
        idx = start
        ok = True
        for expected in sequence[1:]:
            found = None
            for j in range(idx + 1, min(len(history), idx + 1 + max_gap + 1)):
                if history[j] == expected:
                    found = j
                    break
            if found is None:
                ok = False
                break
            idx = found
        if ok:
            return True
    return False


def weave_tools(
    *,
    tool_name: str = "",
    arguments: Any = None,
    tracker: ToolChainTracker | None = None,
) -> ToolWeaveAssessment:
    arg_result = scan_tool_call(tool_name, arguments) if tool_name or arguments else ToolWeaveAssessment()
    chain_result = tracker.observe(tool_name) if tracker and tool_name else ToolWeaveAssessment()
    hits = list(arg_result.hits) + list(chain_result.hits)
    score = max((h.score for h in hits), default=0.0)
    return ToolWeaveAssessment(score=score, hits=hits)
