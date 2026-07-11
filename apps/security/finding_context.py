"""Build expanded code workflow views for security finding detail panels."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from apps.projects.models import Project
from apps.projects.repo_storage import project_repo_path
from apps.security.models import SecurityFinding


_CONTEXT_BEFORE = 14
_CONTEXT_AFTER = 14


def _rel_path_variants(rel_path: str, *, root: Optional[str] = None) -> List[str]:
    """Path variants relative to a scan/repo root."""
    raw = (rel_path or "").strip().replace("\\", "/")
    if not raw:
        return []

    rel = raw.lstrip("/")
    if root:
        root_abs = os.path.abspath(os.path.expanduser(root))
        if os.path.isabs(raw):
            try:
                rel = os.path.relpath(os.path.normpath(raw), root_abs).replace("\\", "/")
            except ValueError:
                rel = os.path.basename(raw)

    variants: List[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        v = v.strip().lstrip("/")
        if v and v not in seen:
            seen.add(v)
            variants.append(v)

    add(rel)
    base = os.path.basename(rel)
    if base:
        add(base)
    if rel.startswith("code/"):
        add(rel[5:])
    if root:
        root_abs = os.path.abspath(os.path.expanduser(root))
        if os.path.basename(root_abs) == "code" and rel.startswith("code/"):
            add(rel[5:])
    parts = rel.split("/")
    for i in range(1, len(parts)):
        add("/".join(parts[i:]))
    return variants


def _safe_file_under_root(root: str, rel_path: str) -> Optional[str]:
    """Resolve a file path that must stay under root."""
    root_abs = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root_abs):
        return None

    for variant in _rel_path_variants(rel_path, root=root_abs):
        candidate = os.path.normpath(os.path.join(root_abs, variant))
        try:
            common = os.path.commonpath([root_abs, candidate])
        except ValueError:
            continue
        if common != root_abs:
            continue
        if os.path.isfile(candidate):
            return candidate
    return None


def _resolve_repo_root(project: Optional[Project]) -> Optional[str]:
    """Filesystem root for reading source (managed storage or project.local_path)."""
    from apps.projects.path_utils import is_under_allowed_roots

    if not project:
        return None
    managed = project_repo_path(project)
    if managed.is_dir():
        return str(managed.resolve())
    if project.local_path:
        path = os.path.abspath(os.path.expanduser(project.local_path))
        if os.path.isdir(path) and is_under_allowed_roots(path):
            return path
    return None


def _read_roots_for_finding(finding: SecurityFinding) -> List[str]:
    """Candidate directories to resolve finding.file_path (newest scan root first)."""
    from apps.projects.path_utils import is_under_allowed_roots

    roots: List[str] = []
    seen: set[str] = set()

    def add(root: Optional[str]) -> None:
        if not root:
            return
        abs_root = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(abs_root) or abs_root in seen:
            return
        # Reject attacker-controlled scan_root outside allowlisted trees (LFI).
        if not is_under_allowed_roots(abs_root):
            return
        seen.add(abs_root)
        roots.append(abs_root)

    meta = finding.metadata if isinstance(finding.metadata, dict) else {}
    add(meta.get("scan_root"))

    project = finding.project
    add(_resolve_repo_root(project))
    return roots


def _load_workflow_from_roots(
    roots: List[str],
    rel_path: str,
    highlight_line: Optional[int],
) -> List[Dict[str, Any]]:
    for root in roots:
        abs_path = _safe_file_under_root(root, rel_path)
        if abs_path:
            rows = _read_workflow_lines(abs_path, highlight_line=highlight_line)
            if rows:
                return rows
    return []


def _is_misleading_snippet(snippet: str) -> bool:
    """Single-token matches (e.g. exec) are not a useful workflow view."""
    text = (snippet or "").strip()
    if not text:
        return True
    lines = text.splitlines()
    return len(lines) == 1 and len(text) < 80


def _snippet_as_lines(
    snippet: str,
    *,
    highlight_line: Optional[int],
) -> List[Dict[str, Any]]:
    """Turn stored scan snippet into display lines (expand panel fallback)."""
    text = (snippet or "").strip()
    if not text:
        return []
    base = highlight_line or 1
    rows: List[Dict[str, Any]] = []
    for offset, line in enumerate(text.splitlines()):
        rows.append(
            {
                "number": base + offset,
                "text": line,
                "highlight": highlight_line is not None and (base + offset) == highlight_line,
            }
        )
    return rows


def _maybe_persist_workflow(
    finding: SecurityFinding,
    *,
    workflow_lines: List[Dict[str, Any]],
    scan_root: Optional[str],
) -> None:
    """Backfill stored workflow for legacy findings (matched token only)."""
    if not workflow_lines:
        return
    meta = dict(finding.metadata) if isinstance(finding.metadata, dict) else {}
    if meta.get("workflow_lines"):
        return

    meta["workflow_lines"] = workflow_lines
    if scan_root:
        meta["scan_root"] = scan_root

    snippet = "\n".join(row["text"] for row in workflow_lines)[:1000]
    finding.metadata = meta
    update_kwargs: Dict[str, Any] = {"metadata": meta}
    if _is_misleading_snippet(finding.code_snippet) and snippet:
        finding.code_snippet = snippet
        update_kwargs["code_snippet"] = snippet

    SecurityFinding.objects.filter(pk=finding.pk).update(**update_kwargs)


def _read_workflow_lines(
    abs_path: str,
    *,
    highlight_line: Optional[int],
) -> List[Dict[str, Any]]:
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            all_lines = handle.readlines()
    except OSError:
        return []

    total = len(all_lines)
    if highlight_line is None or highlight_line < 1:
        start = 1
        end = min(total, _CONTEXT_BEFORE + _CONTEXT_AFTER + 1)
        hi: Optional[int] = None
    else:
        hi = highlight_line
        start = max(1, highlight_line - _CONTEXT_BEFORE)
        end = min(total, highlight_line + _CONTEXT_AFTER)

    rows: List[Dict[str, Any]] = []
    for num in range(start, end + 1):
        text = all_lines[num - 1].rstrip("\n\r")
        rows.append(
            {
                "number": num,
                "text": text,
                "highlight": hi is not None and num == hi,
            }
        )
    return rows


def build_workflow_metadata(
    scan_root: str,
    file_path: str,
    line_number: Optional[int],
) -> Dict[str, Any]:
    """Capture workflow lines at scan time (stored on SecurityFinding.metadata)."""
    workflow_lines = _load_workflow_from_roots([scan_root], file_path, line_number)
    if not workflow_lines:
        return {}

    return {
        "workflow_lines": workflow_lines,
        "scan_root": os.path.abspath(os.path.expanduser(scan_root)),
    }


def build_workflow_snippet(
    scan_root: str,
    file_path: str,
    line_number: Optional[int],
    *,
    max_chars: int = 1000,
) -> str:
    """Multi-line snippet for code_snippet column fallback."""
    abs_path = _safe_file_under_root(scan_root, file_path)
    if not abs_path:
        return ""
    lines = _read_workflow_lines(abs_path, highlight_line=line_number)
    if not lines:
        return ""
    return "\n".join(row["text"] for row in lines)[:max_chars]


def build_finding_code_context(
    finding: SecurityFinding,
    *,
    persist_backfill: bool = True,
) -> Dict[str, Any]:
    """Return structured workflow context for templates (not a single-line snippet)."""
    meta = finding.metadata if isinstance(finding.metadata, dict) else {}
    workflow_steps = meta.get("workflow_steps") or meta.get("trace") or []

    highlight = finding.line_number
    rel_path = (finding.file_path or "").strip()

    workflow_lines: List[Dict[str, Any]] = []
    used_scan_root: Optional[str] = None
    full_from_disk = False

    stored = meta.get("workflow_lines")
    if isinstance(stored, list) and stored:
        workflow_lines = stored
        full_from_disk = len(stored) > 1
    else:
        read_roots = _read_roots_for_finding(finding)
        for root in read_roots:
            abs_path = _safe_file_under_root(root, rel_path)
            if not abs_path:
                continue
            workflow_lines = _read_workflow_lines(abs_path, highlight_line=highlight)
            if workflow_lines:
                used_scan_root = root
                full_from_disk = True
                break

        if workflow_lines and persist_backfill:
            _maybe_persist_workflow(
                finding,
                workflow_lines=workflow_lines,
                scan_root=used_scan_root or meta.get("scan_root"),
            )

    matched_lines: List[Dict[str, Any]] = []
    if finding.code_snippet:
        matched_lines = _snippet_as_lines(
            finding.code_snippet, highlight_line=highlight
        )

    if (
        not workflow_lines
        and matched_lines
        and not _is_misleading_snippet(finding.code_snippet)
    ):
        workflow_lines = matched_lines
        matched_lines = []

    read_roots = _read_roots_for_finding(finding)
    has_full_workflow = full_from_disk and bool(workflow_lines)
    return {
        "workflow_lines": workflow_lines,
        "matched_lines": matched_lines,
        "workflow_steps": workflow_steps,
        "has_workflow": bool(workflow_lines or workflow_steps or matched_lines),
        "has_full_workflow": has_full_workflow,
        "has_matched_snippet": bool(matched_lines),
        "file_path": rel_path,
        "line_number": highlight,
        "needs_source_sync": bool(
            rel_path and not has_full_workflow and not read_roots
        ),
    }


def attach_code_context(findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
    """Pair each finding model with its display context for templates."""
    out: List[Dict[str, Any]] = []
    for finding in findings:
        out.append(
            {
                "finding": finding,
                "code_context": build_finding_code_context(finding),
            }
        )
    return out
