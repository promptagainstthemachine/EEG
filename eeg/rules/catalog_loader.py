"""Load and validate ``eeg/rules/catalog.yaml`` for runtime introspection."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

import yaml

from eeg.rules.bundle_loader import load_aegis_rules, load_eeg_import_bundle

CATALOG_PATH = os.path.join(os.path.dirname(__file__), "catalog.yaml")

# Map catalog bundle names → EEG-import loader bundle dirs
EEG_IMPORT_BUNDLE_NAMES = frozenset({
    "prompt_guard",
    "ssrf_patterns",
    "external_download",
    "third_party_content",
})

# Catalog scan_id aliases → registered ``eeg.scans`` scan_id
SCAN_ID_ALIASES: Dict[str, str] = {
    "eeg_agent_audit": "ainspect_pack",
    "memshield_memory": "memoryguard_surface",
    "llm_guard_unicode": "textguard_unicode",
    "plexiglass_signatures": "redteam_marker_surface",
}

PROBE_ID_ALIASES: Dict[str, str] = {
    "nexus_gateway": "gateway_surface",
    "agentic_security_surface": "aisec_http_surface",
}


@lru_cache(maxsize=1)
def load_catalog() -> Dict[str, Any]:
    if not os.path.isfile(CATALOG_PATH):
        return {}
    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return {}


def resolve_scan_id(catalog_scan_id: str) -> str:
    return SCAN_ID_ALIASES.get(catalog_scan_id, catalog_scan_id)


def resolve_probe_id(catalog_probe_id: str) -> str:
    return PROBE_ID_ALIASES.get(catalog_probe_id, catalog_probe_id)


def get_bundle_manifest() -> List[Dict[str, Any]]:
    """Return bundle entries with on-disk rule counts."""
    catalog = load_catalog()
    bundles_cfg = catalog.get("bundles") or {}
    manifest: List[Dict[str, Any]] = []

    for name, meta in bundles_cfg.items():
        if not isinstance(meta, dict):
            continue
        rel_path = meta.get("path", f"bundles/{name}")
        bundle_dir = os.path.normpath(
            os.path.join(os.path.dirname(__file__), rel_path)
        )
        exists = os.path.isdir(bundle_dir)
        rule_count = _count_bundle_rules(name, bundle_dir) if exists else 0
        manifest.append(
            {
                "name": name,
                "path": rel_path,
                "exists": exists,
                "catalog_rule_count": meta.get("rule_count"),
                "loaded_rule_count": rule_count,
                "scanner": meta.get("scanner"),
                "categories": meta.get("categories") or [],
            }
        )
    return manifest


def _count_bundle_rules(bundle_name: str, bundle_dir: str) -> int:
    if bundle_name in EEG_IMPORT_BUNDLE_NAMES:
        return len(load_eeg_import_bundle(bundle_name))
    if bundle_name == "aegis_rules":
        return len(load_aegis_rules())
    if bundle_name == "ai_practice_patterns":
        from eeg.detectors.boundary_policy_pack import _parse_pack_rules

        return len(_parse_pack_rules(bundle_dir))
    yaml_count = sum(
        1
        for f in os.listdir(bundle_dir)
        if f.endswith((".yaml", ".yml"))
    ) if os.path.isdir(bundle_dir) else 0
    return yaml_count


def get_catalog_scan_ids() -> List[str]:
    catalog = load_catalog()
    scans = catalog.get("scans") or {}
    return [resolve_scan_id(sid) for sid in scans.keys()]


def get_catalog_probe_ids() -> List[str]:
    catalog = load_catalog()
    probes = catalog.get("probes") or {}
    return [resolve_probe_id(pid) for pid in probes.keys()]


def get_bundles_for_scan(scan_id: str) -> List[str]:
    """Return bundle directory names assigned to a scan in catalog."""
    catalog = load_catalog()
    bundles_cfg = catalog.get("bundles") or {}
    resolved = resolve_scan_id(scan_id)
    names: List[str] = []
    for name, meta in bundles_cfg.items():
        if not isinstance(meta, dict):
            continue
        assigned = meta.get("scan_id")
        if assigned == scan_id or assigned == resolved:
            names.append(name)
        elif meta.get("scanner") == scan_id:
            names.append(name)
    return names


def get_full_scan_ids(
    *,
    include_model: bool = False,
    cloud_project_type: Optional[str] = None,
) -> List[str]:
    """Filesystem scans for a full profile (from catalog scan_profiles.full)."""
    return get_scan_ids_for_profile(
        "full",
        include_model=include_model,
        cloud_project_type=cloud_project_type,
    )


def get_scan_ids_for_profile(
    profile_name: str,
    *,
    include_model: bool = False,
    cloud_project_type: Optional[str] = None,
) -> List[str]:
    """Resolve scan IDs from catalog ``scan_profiles``."""
    catalog = load_catalog()
    profiles = catalog.get("scan_profiles") or {}
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        return _default_scan_ids_for_profile(profile_name, include_model=include_model)

    scan_ids = [resolve_scan_id(s) for s in (profile.get("scans") or [])]

    include_cloud = profile.get("include_cloud_static_when")
    if include_cloud and cloud_project_type:
        allowed = {x.strip().lower() for x in str(include_cloud).split(",")}
        if cloud_project_type.lower() in allowed:
            if "cloud_static_rules" not in scan_ids:
                scan_ids.append("cloud_static_rules")

    if include_model and "model_artifact" not in scan_ids:
        scan_ids.append("model_artifact")

    return sorted(set(scan_ids))


def _default_scan_ids_for_profile(
    profile_name: str,
    *,
    include_model: bool = False,
) -> List[str]:
    """Fallback when catalog has no scan_profiles."""
    defaults: Dict[str, List[str]] = {
        "full": [
            "code_security",
            "ainspect_pack",
            "agent_forensics",
            "a2a_agent_surface",
            "mcp_client_config",
            "mcp_tool_response_leak",
            "textguard_unicode",
            "memoryguard_surface",
            "redteam_marker_surface",
        ],
        "code": ["code_security", "ainspect_pack", "agent_forensics"],
        "agent": [
            "agent_forensics",
            "a2a_agent_surface",
            "mcp_client_config",
            "mcp_tool_response_leak",
            "memoryguard_surface",
        ],
        "model": ["model_artifact"],
        "dependency": ["dependency_vuln"],
    }
    ids = list(defaults.get(profile_name, defaults["code"]))
    if include_model and "model_artifact" not in ids:
        ids.append("model_artifact")
    return sorted(ids)


def get_probe_ids_for_api_endpoint() -> List[str]:
    """Probe IDs for API endpoint projects (from catalog probe_profiles)."""
    catalog = load_catalog()
    profiles = catalog.get("probe_profiles") or {}
    api = profiles.get("api_endpoint")
    if isinstance(api, dict) and api.get("probes"):
        return [resolve_probe_id(p) for p in api["probes"]]
    return [
        resolve_probe_id("gateway_surface"),
        resolve_probe_id("mcp_transport"),
        resolve_probe_id("aisec_http_surface"),
        resolve_probe_id("mcp_jsonrpc_handshake"),
    ]


def validate_catalog() -> Dict[str, Any]:
    """Check catalog paths and rule counts; used by health endpoint."""
    from eeg.scans import get_all_scans
    from eeg.probes import get_all_probes

    registered_scans = set(get_all_scans().keys())
    registered_probes = set(get_all_probes().keys())

    bundles = get_bundle_manifest()
    missing_dirs = [b["name"] for b in bundles if not b["exists"]]

    catalog = load_catalog()
    scan_mismatches: List[str] = []
    for catalog_id in (catalog.get("scans") or {}):
        resolved = resolve_scan_id(catalog_id)
        if resolved not in registered_scans:
            scan_mismatches.append(f"{catalog_id} -> {resolved}")

    probe_mismatches: List[str] = []
    for catalog_id in (catalog.get("probes") or {}):
        resolved = resolve_probe_id(catalog_id)
        if resolved not in registered_probes:
            probe_mismatches.append(f"{catalog_id} -> {resolved}")

    return {
        "bundles": bundles,
        "missing_bundle_dirs": missing_dirs,
        "unregistered_scans": scan_mismatches,
        "unregistered_probes": probe_mismatches,
        "catalog_scan_ids": get_catalog_scan_ids(),
        "catalog_probe_ids": get_catalog_probe_ids(),
    }
