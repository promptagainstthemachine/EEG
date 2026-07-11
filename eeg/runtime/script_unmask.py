"""Script unmask — Unicode and obfuscation unfolding before scoring."""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from functools import lru_cache
from typing import Iterable
from urllib.parse import unquote

_INVISIBLE = re.compile(
    "["
    "\u200b\u200c\u200d\u2060\ufeff\u00ad"
    "\u180e\u200e\u200f\u202a-\u202e\u2066-\u2069"
    "]"
)
_VARIATION = re.compile("[\ufe00-\ufe0f]")
_COMBINING = re.compile("[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff]")
_BASE64_BLOCK = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
_HEX_BLOCK = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}\s*){8,}")
_URL_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_OCTAL_ESC = re.compile(r"\\([0-7]{3})")
_SHELL_IFS = re.compile(r"\$\{IFS\}|\$IFS")


def _slice(text: str, match: re.Match[str]) -> str:
    start, end = match.span()
    return text[start:end]


def strip_invisible(text: str) -> str:
    cleaned = _INVISIBLE.sub(" ", text)
    cleaned = _VARIATION.sub("", cleaned)
    return re.sub(r"\s+", " ", cleaned)


def fold_confusables(text: str) -> str:
    """Map common lookalike Latin letters after NFKC."""
    mapping = {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u0410": "A",
        "\u0415": "E",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a7": "X",
    }
    return text.translate(str.maketrans(mapping))


def strip_combining(text: str) -> str:
    return _COMBINING.sub("", text)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(32 <= ord(c) < 127 or c in "\n\r\t" for c in s)
    return ok / len(s)


def _expand_base64(text: str) -> list[str]:
    out: list[str] = []
    for match in _BASE64_BLOCK.finditer(text):
        token = _slice(text, match)
        if len(token) < 16:
            continue
        try:
            raw = base64.b64decode(token, validate=False)
            decoded = raw.decode("utf-8", errors="ignore")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.85 and len(decoded) >= 8:
            out.append(decoded)
    return out


def _expand_hex(text: str) -> list[str]:
    out: list[str] = []
    for match in _HEX_BLOCK.finditer(text):
        token = re.sub(r"[\\x\s]", "", _slice(text, match))
        if len(token) < 8 or len(token) % 2:
            continue
        try:
            raw = bytes.fromhex(token)
            decoded = raw.decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.85 and len(decoded) >= 4:
            out.append(decoded)
    return out


def _expand_url(text: str) -> list[str]:
    out: list[str] = []
    for match in _URL_PCT.finditer(text):
        token = _slice(text, match)
        try:
            decoded = unquote(token)
        except Exception:
            continue
        if decoded != token and _printable_ratio(decoded) > 0.8:
            out.append(decoded)
    return out


def decode_shell_evasions(text: str) -> str:
    """Unfold common shell obfuscations used in tool arguments."""
    s = _SHELL_IFS.sub(" ", text)
    s = _OCTAL_ESC.sub(lambda m: chr(int(m.group(1), 8)), s)

    def _hex_byte(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(1) and ("\\" + "x" + m.group(1)) or m.group(0)

    s = re.sub(r"\\x([0-9a-fA-F]{2})", _hex_byte, s)
    s = re.sub(r"\$\{?\d+\}?", "", s)
    return s


def vowel_fold(text: str) -> str:
    return re.sub(r"[aeiouAEIOU]", "", text)


def space_collapse_pattern(pattern: str) -> str:
    return re.sub(r"\s+", r"\\s*", pattern)


@lru_cache(maxsize=4096)
def unmask_script(text: str) -> str:
    """
    Produce a scoring-ready string: NFKC, invisibles stripped, confusables folded,
    and decoded obfuscation payloads appended for secondary matching.
    """
    if not text:
        return ""
    base = unicodedata.normalize("NFKC", str(text))
    base = strip_invisible(base)
    base = fold_confusables(base)
    base = strip_combining(base)
    base = html.unescape(base)
    base = decode_shell_evasions(base)

    extras: list[str] = []
    extras.extend(_expand_base64(base))
    extras.extend(_expand_hex(base))
    extras.extend(_expand_url(base))

    if not extras:
        return base
    return base + "\n" + "\n".join(dict.fromkeys(extras))


def unmask_variants(text: str) -> Iterable[str]:
    """Yield primary unmasked text plus compact evasion variants."""
    primary = unmask_script(text)
    yield primary
    collapsed = re.sub(r"\s+", " ", primary)
    if collapsed != primary:
        yield collapsed
    folded = vowel_fold(collapsed)
    if folded and folded != collapsed:
        yield folded
