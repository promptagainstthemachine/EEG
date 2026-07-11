"""
Build a language-aware semantic index from arbitrary project source trees.

Used by the vulnerability relationship graph to link findings via symbols,
imports, and modules — works for any future repo layout under managed storage
or local project paths.
"""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from apps.security.finding_context import _resolve_repo_root, _safe_file_under_root

_SKIP_DIR_NAMES = frozenset({
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
    "staticfiles",
    "media",
})

_SOURCE_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".sh": "shell",
}

_IMPORT_RE_JS = re.compile(
    r"""(?:import\s+.*?from\s+['"]([^'"]+)['"]|"""
    r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)|"""
    r"""from\s+['"]([^'"]+)['"]\s+import)""",
    re.MULTILINE,
)

_IMPORT_RE_PY = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))",
    re.MULTILINE,
)


@dataclass
class SymbolDef:
    """A function, class, or module-level region in source."""

    symbol_id: str
    name: str
    kind: str  # function | class | module
    file_path: str
    start_line: int
    end_line: int
    module_id: str


@dataclass
class ModuleDef:
    module_id: str
    file_path: str
    language: str
    imports: List[str] = field(default_factory=list)


@dataclass
class CodeSemanticIndex:
    """In-memory semantic graph over one or more repository roots."""

    roots: List[str] = field(default_factory=list)
    modules: Dict[str, ModuleDef] = field(default_factory=dict)
    symbols: Dict[str, SymbolDef] = field(default_factory=dict)
    imports: List[Tuple[str, str]] = field(default_factory=list)
    files_indexed: int = 0
    files_skipped: int = 0

    def symbol_at(self, file_path: str, line: Optional[int]) -> Optional[SymbolDef]:
        if line is None or line < 1:
            return None
        rel = _normalize_rel(file_path)
        best: Optional[SymbolDef] = None
        for sym in self.symbols.values():
            if sym.file_path != rel:
                continue
            if sym.start_line <= line <= sym.end_line:
                if best is None or (sym.end_line - sym.start_line) < (best.end_line - best.start_line):
                    best = sym
        return best

    def module_for_file(self, file_path: str) -> Optional[ModuleDef]:
        return self.modules.get(f"module:{_normalize_rel(file_path)}")

    def related_modules(self, file_path: str) -> List[str]:
        mid = f"module:{_normalize_rel(file_path)}"
        related: Set[str] = set()
        for src, tgt in self.imports:
            if src == mid:
                related.add(tgt)
            elif tgt == mid:
                related.add(src)
        return sorted(related)


def _normalize_rel(path: str) -> str:
    return (path or "").strip().replace("\\", "/").lstrip("/")


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIR_NAMES or name.startswith(".")


def _iter_source_files(root: str, *, max_files: int = 800) -> List[Tuple[str, str]]:
    """Yield (abs_path, rel_path) under root up to max_files."""
    root_abs = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root_abs):
        return []

    collected: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root_abs):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for fname in filenames:
            if len(collected) >= max_files:
                return collected
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _SOURCE_EXTENSIONS:
                continue
            abs_path = os.path.join(dirpath, fname)
            rel = os.path.relpath(abs_path, root_abs).replace("\\", "/")
            collected.append((abs_path, rel))
    return collected


def _parse_python_file(abs_path: str, rel_path: str, index: CodeSemanticIndex) -> None:
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
    except OSError:
        index.files_skipped += 1
        return

    index.files_indexed += 1
    module_id = f"module:{rel_path}"
    index.modules[module_id] = ModuleDef(
        module_id=module_id,
        file_path=rel_path,
        language="python",
    )

    for m in _IMPORT_RE_PY.finditer(source):
        target = (m.group(1) or m.group(2) or "").split(".")[0]
        if target:
            index.modules[module_id].imports.append(target)

    try:
        tree = ast.parse(source, filename=abs_path)
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            sid = f"symbol:{rel_path}:{node.name}:{node.lineno}"
            index.symbols[sid] = SymbolDef(
                symbol_id=sid,
                name=node.name,
                kind="function",
                file_path=rel_path,
                start_line=node.lineno,
                end_line=end,
                module_id=module_id,
            )
        elif isinstance(node, ast.ClassDef):
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            sid = f"symbol:{rel_path}:{node.name}:{node.lineno}"
            index.symbols[sid] = SymbolDef(
                symbol_id=sid,
                name=node.name,
                kind="class",
                file_path=rel_path,
                start_line=node.lineno,
                end_line=end,
                module_id=module_id,
            )

    for imp_mod in index.modules[module_id].imports:
        target_rel = _resolve_import_to_path(rel_path, imp_mod)
        if target_rel:
            tgt_id = f"module:{target_rel}"
            index.imports.append((module_id, tgt_id))


def _parse_js_like_file(abs_path: str, rel_path: str, language: str, index: CodeSemanticIndex) -> None:
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
    except OSError:
        index.files_skipped += 1
        return

    index.files_indexed += 1
    module_id = f"module:{rel_path}"
    index.modules[module_id] = ModuleDef(module_id=module_id, file_path=rel_path, language=language)

    for m in _IMPORT_RE_JS.finditer(source):
        raw = m.group(1) or m.group(2) or m.group(3) or ""
        if not raw or raw.startswith("."):
            continue
        index.modules[module_id].imports.append(raw.split("/")[0])

    for m in re.finditer(r"(?:function|const|let|var)\s+(\w+)\s*[=(]", source):
        name = m.group(1)
        line = source[: m.start()].count("\n") + 1
        sid = f"symbol:{rel_path}:{name}:{line}"
        index.symbols[sid] = SymbolDef(
            symbol_id=sid,
            name=name,
            kind="function",
            file_path=rel_path,
            start_line=line,
            end_line=line + 40,
            module_id=module_id,
        )


def _resolve_import_to_path(from_rel: str, import_name: str) -> Optional[str]:
    """Best-effort resolve Python import to a project-relative path."""
    base_dir = os.path.dirname(from_rel.replace("\\", "/"))
    parts = import_name.split(".")
    candidates = [
        os.path.join(base_dir, *parts) + ".py",
        os.path.join(base_dir, parts[0], "__init__.py") if parts else "",
        "/".join(parts) + ".py",
        "/".join(parts[:-1] + ["__init__.py"]) if len(parts) > 1 else "",
    ]
    for cand in candidates:
        c = cand.replace("\\", "/").lstrip("/")
        if c:
            return c
    return None


def build_semantic_index_for_roots(
    roots: List[str],
    *,
    max_files_per_root: int = 800,
) -> CodeSemanticIndex:
    """Index all source under the given repository roots."""
    index = CodeSemanticIndex(roots=list(roots))
    seen_roots: Set[str] = set()

    for root in roots:
        root_abs = os.path.abspath(os.path.expanduser(root))
        if root_abs in seen_roots or not os.path.isdir(root_abs):
            continue
        seen_roots.add(root_abs)

        for abs_path, rel_path in _iter_source_files(root_abs, max_files=max_files_per_root):
            ext = os.path.splitext(abs_path)[1].lower()
            lang = _SOURCE_EXTENSIONS.get(ext, "")
            if lang == "python":
                _parse_python_file(abs_path, rel_path, index)
            elif lang in ("javascript", "typescript"):
                _parse_js_like_file(abs_path, rel_path, lang, index)

    return index


def build_semantic_index_for_findings(findings, *, max_files_per_root: int = 800) -> CodeSemanticIndex:
    """
    Discover repo roots from open findings (project storage + scan_root metadata)
    and build a unified semantic index.
    """
    roots: List[str] = []
    seen: Set[str] = set()

    def add_root(path: Optional[str]) -> None:
        if not path:
            return
        abs_path = os.path.abspath(os.path.expanduser(path))
        if os.path.isdir(abs_path) and abs_path not in seen:
            seen.add(abs_path)
            roots.append(abs_path)

    for finding in findings:
        if finding.project_id and finding.project:
            add_root(_resolve_repo_root(finding.project))
        meta = finding.metadata if isinstance(finding.metadata, dict) else {}
        add_root(meta.get("scan_root"))

        fpath = (finding.file_path or "").strip()
        if fpath and finding.project:
            repo = _resolve_repo_root(finding.project)
            if repo:
                resolved = _safe_file_under_root(repo, fpath)
                if resolved:
                    add_root(repo)

    return build_semantic_index_for_roots(roots, max_files_per_root=max_files_per_root)
