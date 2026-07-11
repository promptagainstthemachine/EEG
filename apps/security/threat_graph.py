"""Build a rich 3D force-graph of code vulnerability relationships."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from apps.security.code_semantic_index import CodeSemanticIndex, build_semantic_index_for_findings
from apps.security.finding_filters import exclude_vuln_intel_findings
from apps.security.models import SecurityFinding
from apps.security.threat_categories import THREAT_BUCKETS, bucket_for_finding
from apps.security.threat_graph_analysis import FindingGraphIndexes

SEVERITY_VAL = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

LINK_STRENGTH = {
    "contains": 1.2,
    "file": 1.0,
    "rule": 0.85,
    "bucket": 0.95,
    "project": 0.8,
    "directory": 0.7,
    "severity": 0.65,
    "same_rule": 0.5,
    "co-occur": 0.35,
    "path": 0.45,
    "semantic": 0.72,
    "defines": 0.55,
    "imports": 0.48,
    "same_line": 0.62,
    "snippet_match": 0.58,
    "fp_cluster": 0.4,
    "pattern": 0.52,
}


def _ring(index: int, total: int, radius: float, y: float = 0.0) -> Tuple[float, float, float]:
    if total <= 0:
        return 0.0, y, 0.0
    angle = (2 * math.pi * index) / total
    return radius * math.cos(angle), y, radius * math.sin(angle)


def _path_parts(file_path: str) -> List[str]:
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    dirs = []
    for i in range(1, len(parts)):
        dirs.append("/".join(parts[:i]))
    return dirs


def build_vulnerability_graph(organization, *, limit: int = 150) -> Dict[str, Any]:
    """
    Multi-layer relationship graph for code findings.

    Node groups: hub, severity, bucket (EEG threat buckets only), project, directory,
    file, module, symbol, rule, pattern, finding. Raw category / CWE / OWASP nodes are
    omitted — bucket_for_finding + THREAT_BUCKETS is the supported taxonomy.

    Semantic edges are built from whatever source trees are available for scanned
    projects (managed repos, local paths, scan_root metadata) — not hardcoded paths.
    """
    qs = list(
        exclude_vuln_intel_findings(
            SecurityFinding.objects.filter(
                organization=organization,
                status__in=[
                    SecurityFinding.Status.OPEN,
                    SecurityFinding.Status.ACKNOWLEDGED,
                    SecurityFinding.Status.IN_PROGRESS,
                ],
            ).select_related("project")
        ).order_by("-severity", "-first_seen_at")[:limit]
    )

    graph_indexes = FindingGraphIndexes(qs)
    try:
        semantic_index = build_semantic_index_for_findings(qs, max_files_per_root=600)
    except OSError:
        semantic_index = CodeSemanticIndex()

    buckets_present: Set[str] = set()
    for finding in qs:
        bid = bucket_for_finding(finding)
        if bid:
            buckets_present.add(bid)

    nodes: Dict[str, Dict[str, Any]] = {}
    links: List[Dict[str, Any]] = []
    link_keys: Set[Tuple[str, str, str]] = set()

    def add_node(node_id: str, name: str, group: str, **extra: Any) -> None:
        val_inc = extra.pop("val_inc", extra.pop("val", 1))
        if node_id in nodes:
            nodes[node_id]["val"] = nodes[node_id].get("val", 1) + val_inc
            for key, val in extra.items():
                if key not in nodes[node_id] or nodes[node_id][key] in (None, "", 0):
                    nodes[node_id][key] = val
        else:
            nodes[node_id] = {
                "id": node_id,
                "name": name,
                "group": group,
                "val": val_inc,
                **extra,
            }

    def add_link(source: str, target: str, link_type: str = "relates", **extra: Any) -> None:
        if source == target or source not in nodes or target not in nodes:
            return
        key = (min(source, target), max(source, target), link_type)
        if key in link_keys:
            return
        link_keys.add(key)
        links.append(
            {
                "source": source,
                "target": target,
                "type": link_type,
                "strength": extra.get("strength", LINK_STRENGTH.get(link_type, 0.5)),
            }
        )

    # --- Structural hub ---
    hub_id = f"hub:{organization.pk}"
    add_node(
        hub_id,
        organization.name[:40] if organization else "Codebase",
        "hub",
        val_inc=8,
        subtitle="Security graph root",
    )

    # Severity layer
    sev_counts: Dict[str, int] = defaultdict(int)
    for f in qs:
        sev_counts[f.severity or "medium"] += 1
    active_sevs = [s for s in SEVERITY_ORDER if sev_counts.get(s)]
    for i, sev in enumerate(active_sevs):
        sid = f"severity:{sev}"
        x, y, z = _ring(i, len(active_sevs), 55, y=12)
        add_node(
            sid,
            sev.title(),
            "severity",
            val_inc=4 + sev_counts[sev],
            severity=sev,
            count=sev_counts[sev],
            fx=x,
            fy=y,
            fz=z,
        )
        add_link(hub_id, sid, "contains")

    # Threat buckets — only EEG radar buckets that appear in this finding set (no empty spokes)
    bucket_ids_ordered = [bid for bid in THREAT_BUCKETS if bid in buckets_present]
    bucket_idx = 0
    bucket_total = len(bucket_ids_ordered)
    for bucket_id in bucket_ids_ordered:
        spec = THREAT_BUCKETS[bucket_id]
        bid = f"bucket:{bucket_id}"
        x, y, z = _ring(bucket_idx, bucket_total, 95, y=-8)
        add_node(
            bid,
            spec["label"],
            "bucket",
            val_inc=5,
            bucket_id=bucket_id,
            fx=x,
            fy=y,
            fz=z,
        )
        add_link(hub_id, bid, "contains")
        bucket_idx += 1

    file_to_findings: Dict[str, List[str]] = defaultdict(list)
    file_to_buckets: Dict[str, Set[str]] = defaultdict(set)
    rule_to_findings: Dict[str, List[str]] = defaultdict(list)
    modules_in_graph: Set[str] = set()
    fp_high_ids: List[str] = []
    projects_seen: Dict[int, str] = {}

    for idx, finding in enumerate(qs):
        fid = f"finding:{finding.pk}"
        sev = finding.severity or "medium"
        bucket_id = bucket_for_finding(finding)
        bucket_label = THREAT_BUCKETS[bucket_id]["label"] if bucket_id else ""

        fx, fy, fz = _ring(idx, max(len(qs), 1), 200, y=(SEVERITY_VAL.get(sev, 2) - 3) * 8)
        fp_score, fp_signals = graph_indexes.fp_assessment(finding)
        if fp_score >= 55:
            fp_high_ids.append(fid)

        add_node(
            fid,
            (finding.title or finding.rule_id)[:56],
            "finding",
            severity=sev,
            val_inc=2 + SEVERITY_VAL.get(sev, 1),
            rule_id=finding.rule_id,
            category=finding.category,
            file_path=finding.file_path,
            line_number=finding.line_number,
            bucket_id=bucket_id or "",
            bucket_label=bucket_label,
            project_id=finding.project_id,
            project_name=finding.project.name if finding.project else "",
            cwe=finding.cwe or "",
            owasp_llm=finding.owasp_llm or "",
            snippet=(finding.code_snippet or "")[:200],
            fp_score=fp_score,
            fp_signals=fp_signals,
            fx=fx,
            fy=fy,
            fz=fz,
        )

        sid = f"severity:{sev}"
        if sid in nodes:
            add_link(fid, sid, "severity")

        if bucket_id:
            add_link(fid, f"bucket:{bucket_id}", "bucket")

        rule_nid = f"rule:{finding.rule_id}"
        add_node(rule_nid, finding.rule_id[:44], "rule", val_inc=2, rule_id=finding.rule_id)
        add_link(fid, rule_nid, "rule")
        rule_to_findings[finding.rule_id].append(fid)

        if finding.project_id:
            projects_seen[finding.project_id] = (
                finding.project.name if finding.project else f"Project {finding.project_id}"
            )
            pid = f"project:{finding.project_id}"
            add_node(pid, projects_seen[finding.project_id][:36], "project", val_inc=3)
            add_link(fid, pid, "project")

        if finding.file_path:
            fpath = finding.file_path.strip()
            file_nid = f"file:{fpath}"
            fname = fpath.split("/")[-1] or fpath
            add_node(
                file_nid,
                fname[:40],
                "file",
                val_inc=3,
                path=fpath,
                finding_count=0,
            )
            nodes[file_nid]["finding_count"] = nodes[file_nid].get("finding_count", 0) + 1
            add_link(fid, file_nid, "file")
            file_to_findings[fpath].append(fid)
            if bucket_id:
                file_to_buckets[fpath].add(bucket_id)

            for dir_path in _path_parts(fpath)[:-1]:
                did = f"dir:{dir_path}"
                dname = dir_path.split("/")[-1] or dir_path
                add_node(did, dname[:36], "directory", val_inc=2, path=dir_path)
                add_link(file_nid, did, "directory")
                if finding.project_id:
                    add_link(did, f"project:{finding.project_id}", "path")

            sym = semantic_index.symbol_at(fpath, finding.line_number)
            if sym:
                sym_label = f"{sym.name}()" if sym.kind == "function" else sym.name
                add_node(
                    sym.symbol_id,
                    sym_label[:40],
                    "symbol",
                    val_inc=2,
                    symbol_kind=sym.kind,
                    file_path=sym.file_path,
                    start_line=sym.start_line,
                )
                add_link(fid, sym.symbol_id, "semantic")
                mod = semantic_index.module_for_file(fpath)
                if mod:
                    modules_in_graph.add(mod.module_id)
                    mod_name = mod.file_path.split("/")[-1] or mod.file_path
                    add_node(
                        mod.module_id,
                        mod_name[:40],
                        "module",
                        val_inc=2,
                        path=mod.file_path,
                        language=mod.language,
                    )
                    add_link(sym.symbol_id, mod.module_id, "defines")
                    add_link(file_nid, mod.module_id, "semantic")

    # Project nodes positioned in ring
    for i, (proj_id, pname) in enumerate(projects_seen.items()):
        pid = f"project:{proj_id}"
        if pid not in nodes:
            add_node(pid, pname[:36], "project", val_inc=3)
        x, y, z = _ring(i, len(projects_seen), 130, y=20)
        nodes[pid]["fx"], nodes[pid]["fy"], nodes[pid]["fz"] = x, y, z

    # Same rule → related findings
    for rule_key, finding_ids in rule_to_findings.items():
        if len(finding_ids) < 2:
            continue
        anchor = finding_ids[0]
        for other in finding_ids[1:6]:
            add_link(anchor, other, "same_rule")

    # Multiple findings in same file
    for fpath, finding_ids in file_to_findings.items():
        if len(finding_ids) < 2:
            continue
        file_nid = f"file:{fpath}"
        for i in range(1, min(len(finding_ids), 8)):
            add_link(finding_ids[0], finding_ids[i], "co-occur")

    # Threat categories co-occurring on a file
    for buckets in file_to_buckets.values():
        blist = sorted(buckets)
        for i, b1 in enumerate(blist):
            for b2 in blist[i + 1 :]:
                add_link(f"bucket:{b1}", f"bucket:{b2}", "co-occur")

    # Directory siblings
    dir_files: Dict[str, List[str]] = defaultdict(list)
    for fpath in file_to_findings:
        parts = fpath.rsplit("/", 1)
        directory = parts[0] if len(parts) > 1 else ""
        dir_files[directory].append(f"file:{fpath}")

    for paths in dir_files.values():
        if len(paths) < 2:
            continue
        for i in range(len(paths) - 1):
            add_link(paths[i], paths[i + 1], "path")

    # Same source line — often duplicate or conflicting rules (FP triage)
    for loc_key, finding_ids in graph_indexes.by_location.items():
        if len(finding_ids) < 2:
            continue
        anchor = finding_ids[0]
        for other in finding_ids[1:8]:
            add_link(anchor, other, "same_line")

    # Repeated code patterns across files
    for sig, finding_ids in graph_indexes.by_snippet.items():
        if len(finding_ids) < 2:
            continue
        pattern_id = f"pattern:{sig}"
        add_node(pattern_id, f"Pattern {sig[:8]}", "pattern", val_inc=len(finding_ids))
        anchor = finding_ids[0]
        add_link(anchor, pattern_id, "pattern")
        for other in finding_ids[1:10]:
            add_link(anchor, other, "snippet_match")
            add_link(other, pattern_id, "pattern")

    # Cross-module import relationships (only for modules already in the graph)
    for src_mod, tgt_mod in semantic_index.imports:
        if src_mod in modules_in_graph and tgt_mod in modules_in_graph:
            add_link(src_mod, tgt_mod, "imports")

    # High false-positive risk findings in the same file
    fp_by_file: Dict[str, List[str]] = defaultdict(list)
    for finding in qs:
        fp_score, _ = graph_indexes.fp_assessment(finding)
        if fp_score < 55:
            continue
        fpath = (finding.file_path or "").strip()
        if fpath:
            fp_by_file[fpath].append(f"finding:{finding.pk}")
    for finding_ids in fp_by_file.values():
        if len(finding_ids) < 2:
            continue
        anchor = finding_ids[0]
        for other in finding_ids[1:6]:
            add_link(anchor, other, "fp_cluster")

    node_list = list(nodes.values())
    return {
        "nodes": node_list,
        "links": links,
        "meta": {
            "finding_count": len(qs),
            "node_count": len(node_list),
            "link_count": len(links),
            "severity_counts": dict(sev_counts),
            "project_count": len(projects_seen),
            "file_count": len(file_to_findings),
            "rule_count": len(rule_to_findings),
            "fp_high_count": len(fp_high_ids),
            "semantic_files_indexed": semantic_index.files_indexed,
            "semantic_roots": len(semantic_index.roots),
            "groups": sorted({n["group"] for n in node_list}),
        },
    }


def build_runtime_interaction_graph(organization, *, limit: int = 150) -> Dict[str, Any]:
    """Agentic interaction graph from AI traces (agent → tool/MCP → model → event)."""
    from apps.security.models import AITrace, ManagedAgent

    traces = list(
        AITrace.objects.filter(organization=organization).order_by("-started_at")[:limit]
    )
    agents_by_key = {
        a.agent_key: a
        for a in ManagedAgent.objects.filter(organization=organization)
    }

    nodes: Dict[str, Dict[str, Any]] = {}
    links: List[Dict[str, Any]] = []
    link_keys: Set[Tuple[str, str, str]] = set()
    sev_counts: Dict[str, int] = defaultdict(int)
    blocked = 0
    surface_counts: Dict[str, int] = defaultdict(int)
    tool_counts: Dict[str, int] = defaultdict(int)

    def add_node(node_id: str, name: str, group: str, **extra: Any) -> None:
        val_inc = int(extra.pop("val_inc", extra.pop("val", 1)) or 1)
        if node_id in nodes:
            nodes[node_id]["val"] = nodes[node_id].get("val", 1) + val_inc
            for key, val in extra.items():
                if key not in nodes[node_id] or nodes[node_id][key] in (None, "", 0):
                    nodes[node_id][key] = val
            return
        nodes[node_id] = {
            "id": node_id,
            "name": name,
            "group": group,
            "val": val_inc,
            **extra,
        }

    def add_link(source: str, target: str, link_type: str = "relates", **extra: Any) -> None:
        if source == target or source not in nodes or target not in nodes:
            return
        key = (min(source, target), max(source, target), link_type)
        if key in link_keys:
            return
        link_keys.add(key)
        links.append(
            {
                "source": source,
                "target": target,
                "type": link_type,
                "strength": extra.get(
                    "strength",
                    {
                        "contains": 1.1,
                        "invokes": 1.0,
                        "uses": 0.9,
                        "calls": 1.0,
                        "mcp": 1.0,
                        "emits": 0.85,
                        "severity": 0.7,
                        "detection": 0.65,
                        "session": 0.5,
                    }.get(link_type, 0.5),
                ),
            }
        )

    hub_id = f"hub:runtime:{organization.pk}"
    add_node(
        hub_id,
        "Agentic runtime",
        "hub",
        val_inc=10,
        subtitle="Gateway interactions",
    )

    surface_map = {
        "llm_call": "Prompt",
        "tool_call": "Tool call",
        "retrieval": "RAG",
        "embedding": "Embedding",
        "mcp_tool": "MCP",
        "agent_control": "Control",
        "agent_action": "Agent action",
    }

    for t in traces:
        meta = t.metadata if isinstance(t.metadata, dict) else {}
        is_blocked = bool(meta.get("blocked_by_policy") or t.status == "blocked")
        if is_blocked:
            blocked += 1
        risk = float(t.risk_score or 0)
        if is_blocked or risk >= 0.85:
            sev = "critical"
        elif risk >= 0.7:
            sev = "high"
        elif risk >= 0.4:
            sev = "medium"
        else:
            sev = "low"
        sev_counts[sev] += 1
        surface_counts[t.trace_type] += 1

        agent_key = (
            str(meta.get("agent_key") or meta.get("agent_id") or "").strip()
            or (
                t.session_id
                if t.session_id and not str(t.session_id).startswith("org-")
                else ""
            )
            or "unattributed"
        )
        managed = agents_by_key.get(agent_key)
        agent_name = (
            (managed.name if managed and managed.name else "")
            or str(meta.get("agent_name") or "")
            or agent_key
        )[:48]
        agent_id = f"agent:{agent_key}"
        add_node(
            agent_id,
            agent_name,
            "agent",
            val_inc=4,
            agent_key=agent_key,
            control_status=getattr(managed, "control_status", "") if managed else "",
            subtitle="Managed agent" if managed else "Observed agent",
        )
        add_link(hub_id, agent_id, "contains")

        model_label = (t.model or t.provider or "unknown-model").strip() or "unknown-model"
        model_id = f"model:{model_label}"
        add_node(
            model_id,
            model_label[:48],
            "model",
            val_inc=3,
            provider=t.provider or "",
        )
        add_link(agent_id, model_id, "uses")

        surface = surface_map.get(t.trace_type, t.trace_type or "event")
        surface_id = f"surface:{t.trace_type or 'unknown'}"
        add_node(surface_id, surface, "surface", val_inc=2)
        add_link(agent_id, surface_id, "emits")

        tool_name = str(meta.get("tool_name") or meta.get("mcp_tool") or "").strip()
        mcp_server = str(meta.get("mcp_server") or "").strip()
        if t.trace_type == "mcp_tool" or mcp_server or (
            tool_name and ("mcp" in tool_name.lower() or tool_name.startswith("mcp_"))
        ):
            server_label = mcp_server or "MCP server"
            server_id = f"mcp:{server_label}"
            add_node(server_id, server_label[:48], "mcp", val_inc=4, subtitle="MCP server")
            add_link(agent_id, server_id, "mcp")
            if tool_name:
                tool_id = f"tool:{tool_name}"
                tool_counts[tool_name] += 1
                add_node(
                    tool_id,
                    tool_name[:48],
                    "tool",
                    val_inc=3,
                    subtitle="MCP tool",
                )
                add_link(server_id, tool_id, "calls")
                add_link(agent_id, tool_id, "invokes")
        elif tool_name or t.trace_type == "tool_call":
            label = tool_name or "tool"
            tool_id = f"tool:{label}"
            tool_counts[label] += 1
            add_node(tool_id, label[:48], "tool", val_inc=3, subtitle="Tool")
            add_link(agent_id, tool_id, "invokes")
            add_link(tool_id, model_id, "uses")

        if t.trace_type == "retrieval" or t.trace_type == "embedding":
            rag_id = "tool:rag-retrieval"
            add_node(rag_id, "RAG / retrieval", "tool", val_inc=3, subtitle="Retrieval")
            add_link(agent_id, rag_id, "invokes")
            add_link(rag_id, model_id, "uses")

        sev_id = f"severity:{sev}"
        add_node(sev_id, sev.title(), "severity", val_inc=2, severity=sev)
        add_link(surface_id, sev_id, "severity")

        # Event node (finding-like) so the graph has concrete interaction leaves
        preview = (t.input_text or t.output_text or "").strip().replace("\n", " ")
        if len(preview) > 72:
            preview = preview[:69] + "…"
        event_name = preview or f"{surface} · {t.trace_id[:8]}"
        event_id = f"event:{t.pk}"
        add_node(
            event_id,
            event_name[:56],
            "finding",
            val_inc=5 if is_blocked or risk >= 0.7 else 2,
            severity=sev,
            file_path=f"{t.trace_type}:{t.trace_id[:12]}",
            rule_id=f"runtime.{t.trace_type}",
            risk_score=risk,
            status=t.status,
            subtitle=f"{surface} · risk {risk:.2f}",
        )
        add_link(agent_id, event_id, "emits")
        add_link(event_id, sev_id, "severity")
        if tool_name:
            add_link(f"tool:{tool_name}", event_id, "calls")
        elif t.trace_type in ("retrieval", "embedding"):
            add_link("tool:rag-retrieval", event_id, "calls")
        add_link(model_id, event_id, "uses")

        tags = meta.get("detection_tags") or t.risk_signals or []
        for tag in list(tags)[:3]:
            tag_s = str(tag).strip()
            if not tag_s:
                continue
            tid = f"tag:{tag_s}"
            add_node(tid, tag_s[:40], "detection", val_inc=1)
            add_link(event_id, tid, "detection")

        if t.session_id:
            sid = f"session:{t.session_id}"
            add_node(sid, f"Session {str(t.session_id)[:20]}", "session", val_inc=1)
            add_link(agent_id, sid, "session")

    # Ensure agents from registry appear even without recent traces
    for key, agent in agents_by_key.items():
        aid = f"agent:{key}"
        if aid not in nodes:
            add_node(
                aid,
                (agent.name or key)[:48],
                "agent",
                val_inc=3,
                agent_key=key,
                control_status=agent.control_status,
                subtitle="Registered (no recent traffic)",
            )
            add_link(hub_id, aid, "contains")

    node_list = list(nodes.values())
    # Hub-only graph is not useful — return empty so the UI can show guidance.
    if len(node_list) <= 1 and not traces and not agents_by_key:
        return {
            "nodes": [],
            "links": [],
            "meta": {
                "interaction_count": 0,
                "blocked": 0,
                "node_count": 0,
                "link_count": 0,
                "severity_counts": {},
                "surface_counts": {},
                "tool_count": 0,
                "agent_count": 0,
                "source": "runtime",
                "groups": [],
            },
        }

    return {
        "nodes": node_list,
        "links": links,
        "meta": {
            "interaction_count": len(traces),
            "blocked": blocked,
            "node_count": len(node_list),
            "link_count": len(links),
            "severity_counts": dict(sev_counts),
            "surface_counts": dict(surface_counts),
            "tool_count": len(tool_counts),
            "agent_count": sum(1 for n in node_list if n.get("group") == "agent"),
            "source": "runtime",
            "groups": sorted({n["group"] for n in node_list}),
        },
    }
