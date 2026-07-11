"""Determine whether a source span is inside comments, docstrings, or string literals."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from typing import List, Set, Tuple


def line_starts_for_source(source: str) -> List[int]:
    """Map 1-based line number to character offset."""
    starts = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def offset_from_line_col(source: str, line: int, col: int) -> int:
    starts = line_starts_for_source(source)
    if line < 1:
        return 0
    if line > len(starts):
        return len(source)
    return min(len(source), starts[line - 1] + col)


def match_span_is_non_executable(source: str, start: int, end: int) -> bool:
    """Return True when [start, end) lies inside a comment or string token."""
    if start < 0 or end <= start:
        return False
    try:
        readline = io.StringIO(source).readline
        for tok in tokenize.generate_tokens(readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                ts = offset_from_line_col(source, tok.start[0], tok.start[1])
                te = offset_from_line_col(source, tok.end[0], tok.end[1])
                if start >= ts and end <= te:
                    return True
    except tokenize.TokenError:
        pass
    return False


def python_docstring_lines(tree: ast.AST) -> Set[int]:
    """Line numbers occupied by module/class/function docstrings."""
    lines: Set[int] = set()

    def _add_doc(node: ast.AST) -> None:
        doc = ast.get_docstring(node, clean=False)
        if not doc or not hasattr(node, "lineno"):
            return
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start) or start
        for ln in range(start, end + 1):
            lines.add(ln)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _add_doc(node)
    return lines


def line_is_comment_only(source: str, line_num: int) -> bool:
    """True if the line is empty or only whitespace/comments."""
    lines = source.splitlines()
    if line_num < 1 or line_num > len(lines):
        return False
    line = lines[line_num - 1].strip()
    return not line or line.startswith("#")


def bash_line_is_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def bash_eval_is_real_command(line: str) -> bool:
    """True if ``eval`` appears as a shell command word, not inside quotes."""
    if bash_line_is_comment(line):
        return False
    # Strip single-quoted segments, then double-quoted (no escape handling for speed)
    stripped = re.sub(r"'[^']*'", "''", line)
    stripped = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', stripped)
    return bool(re.search(r"(?:^|[\s|;|&])(eval|exec)\s+", stripped))
