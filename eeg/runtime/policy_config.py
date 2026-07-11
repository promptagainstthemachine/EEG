"""Per-organization runtime policy thresholds for gateway enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuntimePolicyConfig:
    """Thresholds and toggles used by the OSS runtime guard."""

    enforcement_enabled: bool = True
    runtime_protection_enabled: bool = True
    block_threshold: float = 0.75
    sanitize_threshold: float = 0.4
    pii_block_threshold: float = 0.7
    pii_sanitize_threshold: float = 0.4
    toxicity_block_threshold: float = 0.7
    toxicity_sanitize_threshold: float = 0.4
    enabled_policy_pack_ids: list[str] = field(default_factory=list)
    workspace_config: dict[str, Any] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return bool(self.enforcement_enabled or self.runtime_protection_enabled)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enforcement_enabled": self.enforcement_enabled,
            "runtime_protection_enabled": self.runtime_protection_enabled,
            "block_threshold": self.block_threshold,
            "sanitize_threshold": self.sanitize_threshold,
            "pii_block_threshold": self.pii_block_threshold,
            "pii_sanitize_threshold": self.pii_sanitize_threshold,
            "toxicity_block_threshold": self.toxicity_block_threshold,
            "toxicity_sanitize_threshold": self.toxicity_sanitize_threshold,
            "enabled_policy_pack_ids": list(self.enabled_policy_pack_ids),
        }

    @classmethod
    def from_workspace(
        cls,
        org: Any,
        workspace_config: dict[str, Any] | None = None,
        enabled_policy_pack_ids: list[str] | None = None,
    ) -> RuntimePolicyConfig:
        cfg = workspace_config or {}
        enforcement = bool(getattr(org, "policy_enforcement_enabled", True))
        runtime = bool(getattr(org, "runtime_protection_enabled", True)) or enforcement
        return cls(
            enforcement_enabled=enforcement,
            runtime_protection_enabled=runtime,
            block_threshold=float(cfg.get("block_threshold", 0.75)),
            sanitize_threshold=float(cfg.get("sanitize_threshold", 0.4)),
            pii_block_threshold=float(cfg.get("pii_block_threshold", 0.7)),
            pii_sanitize_threshold=float(cfg.get("pii_sanitize_threshold", 0.4)),
            toxicity_block_threshold=float(cfg.get("toxicity_block_threshold", 0.7)),
            toxicity_sanitize_threshold=float(cfg.get("toxicity_sanitize_threshold", 0.4)),
            enabled_policy_pack_ids=list(enabled_policy_pack_ids or []),
            workspace_config=dict(cfg),
        )
