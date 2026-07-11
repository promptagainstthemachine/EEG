"""Runtime catalog API (re-exports from catalog_loader)."""

from eeg.rules.catalog_loader import (  # noqa: F401
    EEG_IMPORT_BUNDLE_NAMES,
    PROBE_ID_ALIASES,
    SCAN_ID_ALIASES,
    get_bundle_manifest,
    get_bundles_for_scan,
    get_catalog_probe_ids,
    get_catalog_scan_ids,
    get_full_scan_ids,
    get_probe_ids_for_api_endpoint,
    get_scan_ids_for_profile,
    load_catalog,
    resolve_probe_id,
    resolve_scan_id,
    validate_catalog,
)

__all__ = [
    "EEG_IMPORT_BUNDLE_NAMES",
    "PROBE_ID_ALIASES",
    "SCAN_ID_ALIASES",
    "get_bundle_manifest",
    "get_bundles_for_scan",
    "get_catalog_probe_ids",
    "get_catalog_scan_ids",
    "get_full_scan_ids",
    "get_probe_ids_for_api_endpoint",
    "get_scan_ids_for_profile",
    "load_catalog",
    "resolve_probe_id",
    "resolve_scan_id",
    "validate_catalog",
]
