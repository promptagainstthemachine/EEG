"""Optional cloud-native safety passthrough for gateway vendor plans."""
from __future__ import annotations

from typing import Any


def bedrock_guardrail_config(config: dict[str, Any]) -> dict[str, Any] | None:
    """Build Bedrock Converse guardrailConfig from connector settings."""
    safety = config.get("cloud_safety") or config
    identifier = (safety.get("guardrail_identifier") or safety.get("guardrailIdentifier") or "").strip()
    if not identifier:
        return None
    version = str(safety.get("guardrail_version") or safety.get("guardrailVersion") or "DRAFT")
    trace = safety.get("guardrail_trace")
    return {
        "guardrailIdentifier": identifier,
        "guardrailVersion": version,
        **({"trace": trace} if trace is not None else {}),
    }


def apply_bedrock_guardrail(converse_body: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    gr = bedrock_guardrail_config(config)
    if not gr:
        return converse_body
    out = dict(converse_body)
    out["guardrailConfig"] = gr
    return out


def azure_prompt_shield_config(config: dict[str, Any]) -> dict[str, Any] | None:
    """Azure AI Foundry Prompt Shields (chat completions extension)."""
    safety = config.get("cloud_safety") or config
    if not safety.get("prompt_shield_enabled", safety.get("enable_prompt_shield")):
        return None
    action = str(safety.get("prompt_shield_action") or "annotate").lower()
    if action not in ("annotate", "block"):
        action = "annotate"
    doc_action = str(safety.get("prompt_shield_documents_action") or action).lower()
    return {
        "prompt_shield": {
            "user_prompt": {"enabled": True, "action": action},
            "documents": {
                "enabled": bool(safety.get("prompt_shield_documents_enabled", True)),
                "action": doc_action,
                **(
                    {"spotlighting_enabled": True}
                    if safety.get("prompt_shield_spotlighting_enabled")
                    else {}
                ),
            },
        }
    }


def apply_azure_prompt_shield(payload: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    shield = azure_prompt_shield_config(config)
    if not shield:
        return payload
    out = dict(payload)
    out.update(shield)
    return out


def vertex_model_armor_config(config: dict[str, Any]) -> dict[str, Any] | None:
    """Vertex AI Model Armor template reference."""
    safety = config.get("cloud_safety") or config
    prompt_tpl = (safety.get("model_armor_prompt_template") or safety.get("model_armor_template") or "").strip()
    response_tpl = (safety.get("model_armor_response_template") or prompt_tpl).strip()
    if not prompt_tpl and not response_tpl:
        return None
    armor: dict[str, str] = {}
    if prompt_tpl:
        armor["promptTemplateName"] = prompt_tpl
    if response_tpl:
        armor["responseTemplateName"] = response_tpl
    return {"modelArmorConfig": armor}


def apply_vertex_model_armor(payload: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    armor = vertex_model_armor_config(config)
    if not armor:
        return payload
    out = dict(payload)
    out.update(armor)
    return out


def cloud_safety_summary(config: dict[str, Any]) -> dict[str, Any]:
    """Describe enabled cloud-native safety features for a connector."""
    backend = (config.get("backend") or "").strip().lower()
    features: list[str] = []
    detail: dict[str, Any] = {}

    if backend == "bedrock" and bedrock_guardrail_config(config):
        features.append("bedrock_guardrails")
        detail["bedrock"] = bedrock_guardrail_config(config)
    if backend == "azure_foundry" and azure_prompt_shield_config(config):
        features.append("azure_prompt_shield")
        detail["azure"] = azure_prompt_shield_config(config)
    if backend == "vertex" and vertex_model_armor_config(config):
        features.append("vertex_model_armor")
        detail["vertex"] = vertex_model_armor_config(config)

    return {"backend": backend, "enabled_features": features, "config": detail}
