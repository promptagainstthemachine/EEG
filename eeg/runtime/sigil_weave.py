"""Sigil weave — compiled pattern packs with any/all match modes."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable, Literal

import yaml

from eeg.runtime.script_unmask import unmask_variants

MatchMode = Literal["any", "all"]


@dataclass(frozen=True)
class SigilHit:
    sigil_id: str
    category: str
    severity: str
    score: float
    matched: str
    pack: str


@dataclass(frozen=True)
class _CompiledSigil:
    sigil_id: str
    category: str
    severity: str
    score: float
    pack: str
    match_mode: MatchMode
    regexes: tuple[re.Pattern[str], ...]
    keywords: tuple[str, ...]
    excludes: tuple[re.Pattern[str], ...]


_SEVERITY_SCORE = {
    "critical": 0.92,
    "high": 0.85,
    "medium": 0.62,
    "low": 0.35,
    "info": 0.15,
}

_FLAGS = re.IGNORECASE | re.DOTALL


def _packs_root() -> str:
    return os.path.join(os.path.dirname(__file__), "packs")


def _compile_patterns(entries: Any) -> tuple[list[re.Pattern[str]], list[str]]:
    regexes: list[re.Pattern[str]] = []
    keywords: list[str] = []
    if isinstance(entries, str):
        entries = [entries]
    for entry in entries or []:
        if isinstance(entry, str):
            try:
                regexes.append(re.compile(entry, _FLAGS))
            except re.error:
                keywords.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type") or "regex").lower()
        val = entry.get("value") or entry.get("match") or entry.get("pattern")
        if not val:
            continue
        if kind == "keyword":
            keywords.append(str(val))
        else:
            try:
                regexes.append(re.compile(str(val), _FLAGS))
            except re.error:
                continue
    return regexes, keywords


def _compile_excludes(rule: dict[str, Any]) -> tuple[re.Pattern[str], ...]:
    out: list[re.Pattern[str]] = []
    for entry in rule.get("exclude_patterns") or []:
        raw = entry if isinstance(entry, str) else (entry or {}).get("value")
        if not raw:
            continue
        try:
            out.append(re.compile(str(raw), _FLAGS))
        except re.error:
            continue
    return tuple(out)


def _load_yaml_docs(path: str) -> list[dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            docs = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError):
        return []
    rows: list[dict[str, Any]] = []
    for doc in docs:
        if isinstance(doc, dict) and ("id" in doc or "sigil_id" in doc or "patterns" in doc):
            rows.append(doc)
        elif isinstance(doc, dict) and isinstance(doc.get("rules"), list):
            rows.extend(r for r in doc["rules"] if isinstance(r, dict))
    return rows


def _compile_rule(rule: dict[str, Any], pack: str) -> _CompiledSigil | None:
    if rule.get("enabled") is False:
        return None
    sid = str(rule.get("sigil_id") or rule.get("id") or f"{pack}:unknown")
    severity = str(rule.get("severity") or "medium").lower()
    score = float(rule.get("score") or _SEVERITY_SCORE.get(severity, 0.55))
    regexes, keywords = _compile_patterns(rule.get("patterns"))
    if not regexes and not keywords:
        single = rule.get("pattern")
        if isinstance(single, str):
            try:
                regexes = [re.compile(single, _FLAGS)]
            except re.error:
                return None
    if not regexes and not keywords:
        return None
    mode = str(rule.get("match_mode") or "any").lower()
    return _CompiledSigil(
        sigil_id=sid,
        category=str(rule.get("category") or pack),
        severity=severity,
        score=score,
        pack=pack,
        match_mode="all" if mode == "all" else "any",
        regexes=tuple(regexes),
        keywords=tuple(keywords),
        excludes=_compile_excludes(rule),
    )


@lru_cache(maxsize=8)
def compiled_packs(pack_names: tuple[str, ...] | None = None) -> tuple[_CompiledSigil, ...]:
    root = _packs_root()
    names = list(pack_names) if pack_names else []
    if not names:
        try:
            names = [
                os.path.splitext(f)[0]
                for f in os.listdir(root)
                if f.endswith((".yaml", ".yml"))
            ]
        except OSError:
            names = []
    compiled: list[_CompiledSigil] = []
    for name in sorted(set(names)):
        for ext in (".yaml", ".yml"):
            path = os.path.join(root, f"{name}{ext}")
            if not os.path.isfile(path):
                continue
            for rule in _load_yaml_docs(path):
                item = _compile_rule(rule, name)
                if item:
                    compiled.append(item)
            break
    return tuple(compiled)


def clear_sigil_caches() -> None:
    compiled_packs.cache_clear()


def list_pack_catalog() -> list[dict[str, Any]]:
    """Return metadata for each sigil pack on disk."""
    root = _packs_root()
    catalog: list[dict[str, Any]] = []
    try:
        files = sorted(f for f in os.listdir(root) if f.endswith((".yaml", ".yml")))
    except OSError:
        return catalog
    for filename in files:
        name = os.path.splitext(filename)[0]
        path = os.path.join(root, filename)
        rules = _load_yaml_docs(path)
        rule_ids: list[str] = []
        categories: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rid = str(rule.get("id") or rule.get("sigil_id") or "")
            if rid:
                rule_ids.append(rid)
            cat = str(rule.get("category") or "")
            if cat:
                categories.add(cat)
        catalog.append(
            {
                "id": name,
                "file": filename,
                "rule_count": len(rule_ids),
                "rule_ids": rule_ids,
                "categories": sorted(categories),
            }
        )
    return catalog


def _match_one(text: str, sigil: _CompiledSigil) -> SigilHit | None:
    lower = text.lower()
    hits: list[str] = []

    kw_hits = 0
    for kw in sigil.keywords:
        if kw.lower() in lower:
            hits.append(kw[:120])
            kw_hits += 1
            if sigil.match_mode != "all":
                break
    if sigil.match_mode == "all" and sigil.keywords and kw_hits < len(sigil.keywords):
        return None

    rx_hits = 0
    for rx in sigil.regexes:
        m = rx.search(text)
        if not m:
            if sigil.match_mode == "all":
                return None
            continue
        snippet = m.group(0)[:120]
        if sigil.excludes and any(ex.search(snippet) or ex.search(text) for ex in sigil.excludes):
            continue
        hits.append(snippet)
        rx_hits += 1
        if sigil.match_mode != "all":
            break
    if sigil.match_mode == "all" and sigil.regexes and rx_hits < len(sigil.regexes):
        return None
    if not hits:
        return None
    return SigilHit(
        sigil_id=sigil.sigil_id,
        category=sigil.category,
        severity=sigil.severity,
        score=sigil.score,
        matched=hits[0],
        pack=sigil.pack,
    )


@dataclass
class SigilAssessment:
    score: float = 0.0
    hits: list[SigilHit] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    def to_layer_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "categories": list(self.categories),
            "hits": [
                {
                    "id": h.sigil_id,
                    "category": h.category,
                    "severity": h.severity,
                    "score": h.score,
                    "matched": h.matched,
                    "pack": h.pack,
                }
                for h in self.hits
            ],
        }


def weave_sigils(
    text: str,
    *,
    packs: Iterable[str] | None = None,
) -> SigilAssessment:
    """Match text (and unmasked variants) against sigil packs; score = max hit."""
    if not text or not str(text).strip():
        return SigilAssessment()
    pack_tuple = tuple(packs) if packs else None
    sigils = compiled_packs(pack_tuple)
    hits: list[SigilHit] = []
    seen: set[str] = set()
    for variant in unmask_variants(str(text)):
        for sigil in sigils:
            if sigil.sigil_id in seen:
                continue
            hit = _match_one(variant, sigil)
            if hit:
                hits.append(hit)
                seen.add(sigil.sigil_id)
    if not hits:
        return SigilAssessment()
    score = max(h.score for h in hits)
    categories = sorted({h.category for h in hits})
    return SigilAssessment(score=score, hits=hits, categories=categories)
