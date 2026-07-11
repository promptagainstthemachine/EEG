"""Minimal policy document loader for gateway SSRF / host denylists."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import yaml

_POLICY_ROOT = os.path.join(os.path.dirname(__file__), "policy")
_BUNDLES_ROOT = os.path.join(os.path.dirname(__file__), "bundles")


@lru_cache(maxsize=16)
def load_policy_document(name: str) -> dict[str, Any]:
    """Load a policy YAML from rules/policy/ or rules/bundles/<name>/."""
    candidates = [
        os.path.join(_POLICY_ROOT, f"{name}.yaml"),
        os.path.join(_POLICY_ROOT, f"{name}.yml"),
        os.path.join(_BUNDLES_ROOT, name, f"{name}.yaml"),
        os.path.join(_BUNDLES_ROOT, name, "policy.yaml"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            if isinstance(data, dict):
                return data
        except (OSError, yaml.YAMLError):
            continue
    return {}
