"""OpenAPI 3 schema for EEG REST API (Swagger UI)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Shared response / schema fragments
_ERROR = {
    "type": "object",
    "properties": {
        "error": {"type": "string"},
        "code": {"type": "string"},
    },
}

_PROJECT = {
    "type": "object",
    "properties": {
        "id": {"type": "integer"},
        "uuid": {"type": "string", "format": "uuid"},
        "name": {"type": "string"},
        "slug": {"type": "string"},
        "description": {"type": "string"},
        "project_type": {
            "type": "string",
            "enum": [
                "repository",
                "aws",
                "gcp",
                "azure",
                "local",
                "api_endpoint",
                "gateway",
            ],
            "description": "gateway = auto-created from gateway agent traffic",
        },
        "status": {"type": "string", "enum": ["active", "paused", "error"]},
        "connection_status": {
            "type": "string",
            "enum": ["connected", "disconnected", "active", "paused", "error"],
            "description": (
                "For gateway apps: connected/disconnected from recent agent traffic. "
                "Otherwise mirrors project status."
            ),
        },
        "is_gateway_app": {"type": "boolean"},
        "gateway_agent_key": {
            "type": "string",
            "description": "Agent key when this project is a gateway-connected app",
        },
        "repository_url": {"type": "string"},
        "local_path": {"type": "string"},
        "api_endpoint": {"type": "string"},
        "cloud_resource_id": {"type": "string"},
        "auto_scan_enabled": {"type": "boolean"},
        "last_scan_at": {"type": "string", "format": "date-time", "nullable": True},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
    },
}

_TRACE_TYPES = [
    "llm_call",
    "tool_call",
    "agent_action",
    "retrieval",
    "embedding",
    "mcp_tool",
    "agent_control",
]

_AGENT = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "format": "uuid"},
        "agent_key": {"type": "string"},
        "name": {"type": "string"},
        "control_status": {
            "type": "string",
            "enum": ["active", "paused", "quarantined"],
        },
        "status_label": {"type": "string"},
        "framework": {"type": "string"},
        "last_seen_at": {"type": "string", "format": "date-time", "nullable": True},
        "last_seen_label": {"type": "string"},
        "is_live": {"type": "boolean"},
        "last_control_action": {"type": "string"},
        "metadata": {"type": "object"},
    },
}

_TRACE = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "format": "uuid"},
        "trace_id": {"type": "string"},
        "span_id": {"type": "string"},
        "parent_span_id": {"type": "string"},
        "trace_type": {
            "type": "string",
            "enum": _TRACE_TYPES,
        },
        "status": {
            "type": "string",
            "enum": ["success", "error", "blocked", "timeout"],
        },
        "provider": {"type": "string"},
        "model": {"type": "string"},
        "session_id": {"type": "string"},
        "user_id": {"type": "string"},
        "input_tokens": {"type": "integer"},
        "output_tokens": {"type": "integer"},
        "latency_ms": {"type": "integer"},
        "risk_score": {"type": "number"},
        "project_id": {"type": "integer", "nullable": True},
        "started_at": {"type": "string", "format": "date-time"},
        "completed_at": {"type": "string", "format": "date-time", "nullable": True},
    },
}

_TRACE_INGEST = {
    "type": "object",
    "required": ["trace_id", "span_id", "trace_type", "started_at"],
    "properties": {
        "trace_id": {"type": "string"},
        "span_id": {"type": "string"},
        "parent_span_id": {"type": "string"},
        "trace_type": {
            "type": "string",
            "enum": _TRACE_TYPES,
        },
        "status": {
            "type": "string",
            "enum": ["success", "error", "blocked", "timeout"],
        },
        "provider": {"type": "string"},
        "model": {"type": "string"},
        "session_id": {"type": "string"},
        "user_id": {"type": "string"},
        "input_text": {"type": "string"},
        "output_text": {"type": "string"},
        "input_tokens": {"type": "integer"},
        "output_tokens": {"type": "integer"},
        "latency_ms": {"type": "integer"},
        "cost_usd": {"type": "number"},
        "risk_score": {"type": "number"},
        "risk_signals": {"type": "array", "items": {"type": "object"}},
        "metadata": {"type": "object"},
        "project_id": {"type": "integer"},
        "started_at": {"type": "string", "format": "date-time"},
        "completed_at": {"type": "string", "format": "date-time", "nullable": True},
    },
}

_FINDING_SUMMARY = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "format": "uuid"},
        "rule_id": {"type": "string"},
        "title": {"type": "string"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
        "status": {
            "type": "string",
            "enum": ["open", "acknowledged", "in_progress", "resolved", "false_positive", "dismissed"],
        },
        "category": {"type": "string"},
        "file_path": {"type": "string"},
        "line_number": {"type": "integer", "nullable": True},
        "first_seen_at": {"type": "string", "format": "date-time"},
        "last_seen_at": {"type": "string", "format": "date-time"},
    },
}

_SCAN_TYPES = [
    "code",
    "full",
    "comprehensive",
    "agent",
    "model",
    "dependency",
    "vuln_intel",
    "cloud",
    "probe",
    "redteam",
    "code_security",
    "agent_forensics",
]


def _responses(
    success_desc: str = "OK",
    *,
    success_schema: Optional[Dict[str, Any]] = None,
    include_401: bool = True,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "200": {
            "description": success_desc,
            "content": {
                "application/json": {
                    "schema": success_schema or {"type": "object"},
                }
            },
        },
        "400": {"description": "Bad request", "content": {"application/json": {"schema": _ERROR}}},
        "404": {"description": "Not found", "content": {"application/json": {"schema": _ERROR}}},
    }
    if include_401:
        out["401"] = {
            "description": "Authentication required",
            "content": {"application/json": {"schema": _ERROR}},
        }
    return out


def _method(
    *,
    summary: str,
    tags: List[str],
    responses: Dict[str, Any],
    security: Optional[List[Dict[str, str]]] = None,
    parameters: Optional[List[Dict[str, Any]]] = None,
    request_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    op: Dict[str, Any] = {"summary": summary, "tags": tags, "responses": responses}
    if security is not None:
        op["security"] = security
    else:
        op["security"] = [{"bearerAuth": []}, {"apiKeyHeader": []}]
    if parameters:
        op["parameters"] = parameters
    if request_body:
        op["requestBody"] = request_body
    return op


def _prefix_api_v1_paths(paths: Dict[str, Any]) -> Dict[str, Any]:
    """Turn /schema/ into /api/v1/schema/ for a single site-origin server."""
    out: Dict[str, Any] = {}
    base = "/api/v1"
    for key, val in paths.items():
        path = key if key.startswith("/") else f"/{key}"
        out[f"{base}{path}"] = val
    return out


API_V1_ROUTE_OPERATIONS: Dict[str, Any] = {
        "schema": {
            "get": _method(
                summary="OpenAPI schema (this document)",
                tags=["System"],
                security=[],
                responses=_responses("OpenAPI 3 JSON document", include_401=False),
            ),
        },
        "health": {
            "get": _method(
                summary="Health check and engine status",
                tags=["System"],
                security=[],
                responses=_responses(
                    "Service healthy",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "status": {"type": "string"},
                            "service": {"type": "string"},
                            "engine": {"type": "object"},
                            "catalog": {"type": "object"},
                        },
                    },
                    include_401=False,
                ),
            ),
        },
        "organization": {
            "get": _method(
                summary="Get current organization",
                tags=["Organization"],
                responses=_responses(
                    "Organization profile",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "slug": {"type": "string"},
                            "settings": {"type": "object"},
                            "project_count": {"type": "integer"},
                            "can_add_project": {
                                "type": "boolean",
                                "description": (
                                    "False only when EEG_MAX_PROJECTS_PER_ORG > 0 and the org "
                                    "has reached that cap. Default 0 = unlimited."
                                ),
                            },
                        },
                    },
                ),
            ),
            "patch": _method(
                summary="Update organization settings",
                tags=["Organization"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "settings": {
                                        "type": "object",
                                        "properties": {
                                            "auto_redteam_enabled": {"type": "boolean"},
                                            "model_scanning_enabled": {"type": "boolean"},
                                            "realtime_telemetry_enabled": {"type": "boolean"},
                                            "realtime_monitoring_enabled": {"type": "boolean"},
                                            "policy_enforcement_enabled": {"type": "boolean"},
                                            "runtime_protection_enabled": {"type": "boolean"},
                                        },
                                    },
                                },
                            },
                        }
                    },
                },
                responses=_responses("Settings updated"),
            ),
        },
        "gateway_guard": {
            "post": _method(
                summary="Runtime guard — score messages without calling an LLM",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["messages"],
                                "properties": {
                                    "messages": {
                                        "type": "array",
                                        "items": {"type": "object"},
                                    },
                                    "phase": {
                                        "type": "string",
                                        "enum": ["request", "response"],
                                        "default": "request",
                                    },
                                },
                            },
                        }
                    },
                },
                responses=_responses(
                    "Guard decision",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "allowed": {"type": "boolean"},
                            "blocked": {"type": "boolean"},
                            "reason": {"type": "string"},
                            "risk_score": {"type": "number"},
                            "risk_signals": {"type": "array", "items": {"type": "object"}},
                            "tier": {"type": "string"},
                            "policy_action": {"type": "string"},
                            "primary_reason": {"type": "string"},
                            "confidence": {"type": "number"},
                            "confidence_band": {"type": "string"},
                            "layer_scores": {"type": "object"},
                            "detection_tags": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                    },
                ),
            ),
        },
        "gateway_lattice": {
            "post": _method(
                summary="Runtime lattice — multi-layer inspect (sigil/spectral/tool/shard)",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "text": {"type": "string"},
                                    "messages": {
                                        "type": "array",
                                        "items": {"type": "object"},
                                    },
                                    "phase": {
                                        "type": "string",
                                        "enum": ["request", "response"],
                                    },
                                    "session_id": {"type": "string"},
                                    "tool_name": {"type": "string"},
                                    "tool_arguments": {},
                                    "prior_prompt": {"type": "string"},
                                },
                            },
                        }
                    },
                },
                responses=_responses(
                    "Lattice inspection",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "blocked": {"type": "boolean"},
                            "action": {"type": "string"},
                            "layer_scores": {"type": "object"},
                            "layers": {"type": "object"},
                            "risk_score": {"type": "number"},
                            "threats": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                ),
            ),
        },
        "gateway_lattice_packs": {
            "get": _method(
                summary="List runtime sigil packs and lattice layers",
                tags=["Gateway"],
                responses=_responses(
                    "Pack catalog",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "packs": {"type": "array", "items": {"type": "object"}},
                            "count": {"type": "integer"},
                            "layers": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                ),
            ),
        },
        "gateway_conduit": {
            "post": _method(
                summary="Conduit gate — egress URL admission check",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["url"],
                                "properties": {
                                    "url": {"type": "string"},
                                    "allow_private": {"type": "boolean"},
                                },
                            },
                        }
                    },
                },
                responses=_responses(
                    "Conduit verdict",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "allowed": {"type": "boolean"},
                            "action": {"type": "string"},
                            "score": {"type": "number"},
                            "reasons": {"type": "array", "items": {"type": "string"}},
                            "result_class": {"type": "string"},
                        },
                    },
                ),
            ),
        },
        "gateway_chat_completions": {
            "post": _method(
                summary="Runtime gateway — OpenAI-compatible chat completions proxy",
                tags=["Gateway"],
                parameters=[
                    {
                        "name": "X-EEG-Upstream-URL",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "Upstream chat completions URL (or use upstream_url in body)",
                    },
                    {
                        "name": "X-EEG-Upstream-Authorization",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "Bearer token for the upstream LLM provider",
                    },
                    {
                        "name": "X-EEG-Provider",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "BYOK provider id (openai, anthropic, bedrock, ...)",
                    },
                    {
                        "name": "X-EEG-Provider-Key",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "BYOK provider API key / credentials",
                    },
                    {
                        "name": "X-EEG-Connector-Id",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "integer"},
                        "description": "Stored GatewayConnector id for this organization",
                    },
                    {
                        "name": "X-EEG-Agent",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": (
                            "Agent key for attribution. Auto-registers the agent and "
                            "gateway project on first traffic."
                        ),
                    },
                ],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["messages"],
                                "properties": {
                                    "model": {"type": "string"},
                                    "messages": {
                                        "type": "array",
                                        "items": {"type": "object"},
                                    },
                                    "upstream_url": {"type": "string"},
                                    "upstream_headers": {"type": "object"},
                                    "stream": {"type": "boolean"},
                                    "agent_id": {
                                        "type": "string",
                                        "description": "Agent key (same as X-EEG-Agent)",
                                    },
                                    "metadata": {
                                        "type": "object",
                                        "description": (
                                            "Optional; metadata.agent_id / agent_key also "
                                            "attribute and auto-register the agent"
                                        ),
                                        "properties": {
                                            "agent_id": {"type": "string"},
                                            "agent_key": {"type": "string"},
                                        },
                                    },
                                },
                            },
                        }
                    },
                },
                responses={
                    "200": {
                        "description": "Upstream completion (with optional eeg metadata) or SSE stream",
                        "content": {
                            "application/json": {"schema": {"type": "object"}},
                            "text/event-stream": {"schema": {"type": "string"}},
                        },
                    },
                    "403": {
                        "description": "Blocked by runtime policy",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                    "401": {
                        "description": "Unauthorized",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                },
            ),
        },
        "gateway_providers": {
            "get": _method(
                summary="List supported gateway providers and capabilities",
                tags=["Gateway"],
                responses=_responses(
                    "Provider catalog",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "count": {"type": "integer"},
                            "providers": {"type": "array", "items": {"type": "object"}},
                            "capabilities": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                ),
            ),
        },
        "gateway_embeddings": {
            "post": _method(
                summary="Gateway embeddings proxy (BYOK or connector)",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                responses=_responses("Embedding response"),
            ),
        },
        "gateway_images": {
            "post": _method(
                summary="Gateway image generation proxy (BYOK or connector)",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                responses=_responses("Image response"),
            ),
        },
        "gateway_speech": {
            "post": _method(
                summary="Gateway speech synthesis proxy (BYOK or connector)",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                responses=_responses("Speech response"),
            ),
        },
        "gateway_transcriptions": {
            "post": _method(
                summary="Gateway transcription proxy (BYOK or connector)",
                tags=["Gateway"],
                request_body={
                    "required": True,
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                responses=_responses("Transcription response"),
            ),
        },
        "projects": {
            "get": _method(
                summary="List projects",
                tags=["Projects"],
                responses=_responses(
                    "Project list",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "projects": {"type": "array", "items": _PROJECT},
                        },
                    },
                ),
            ),
            "post": _method(
                summary="Create project",
                tags=["Projects"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "slug": {"type": "string"},
                                    "description": {"type": "string"},
                                    "project_type": {"type": "string"},
                                    "repository_url": {"type": "string"},
                                    "local_path": {"type": "string"},
                                    "api_endpoint": {"type": "string"},
                                    "cloud_resource_id": {"type": "string"},
                                },
                            },
                        }
                    },
                },
                responses={
                    "201": {
                        "description": "Project created",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "name": {"type": "string"},
                                        "slug": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "400": {"description": "Bad request", "content": {"application/json": {"schema": _ERROR}}},
                    "401": {"description": "Unauthorized", "content": {"application/json": {"schema": _ERROR}}},
                },
            ),
        },
        "project_detail": {
            "get": _method(
                summary="Get project by ID",
                tags=["Projects"],
                parameters=[
                    {
                        "name": "project_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                responses=_responses("Project detail", success_schema=_PROJECT),
            ),
            "patch": _method(
                summary="Update project",
                tags=["Projects"],
                parameters=[
                    {
                        "name": "project_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                request_body={
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "additionalProperties": True},
                        }
                    },
                },
                responses=_responses("Project updated", success_schema=_PROJECT),
            ),
            "delete": _method(
                summary="Delete project",
                tags=["Projects"],
                parameters=[
                    {
                        "name": "project_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                responses={
                    "204": {"description": "Project deleted"},
                    "401": {"description": "Unauthorized", "content": {"application/json": {"schema": _ERROR}}},
                    "404": {"description": "Not found", "content": {"application/json": {"schema": _ERROR}}},
                },
            ),
        },
        "project_scans": {
            "get": _method(
                summary="List scan runs for a project",
                tags=["Scans"],
                parameters=[
                    {
                        "name": "project_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    },
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 25}},
                ],
                responses=_responses(
                    "Scan run history",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "scans": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                ),
            ),
        },
        "scan_types": {
            "get": _method(
                summary="List scan types, registered scanners, and probes",
                tags=["Scans"],
                responses=_responses(
                    "Catalog of scan and probe capabilities",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "scan_types": {"type": "array", "items": {"type": "string"}},
                            "scans": {"type": "array", "items": {"type": "object"}},
                            "probes": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                ),
            ),
        },
        "scan": {
            "post": _method(
                summary="Run security scan on one project",
                tags=["Scans"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["project_id"],
                                "properties": {
                                    "project_id": {
                                        "type": "integer",
                                        "description": "Use GET /api/v1/projects/ to list project IDs.",
                                    },
                                    "scan_type": {
                                        "type": "string",
                                        "enum": _SCAN_TYPES,
                                        "default": "code",
                                        "description": (
                                            "code, full/comprehensive, agent, model, "
                                            "dependency/vuln_intel, etc."
                                        ),
                                    },
                                },
                            },
                        }
                    },
                },
                responses={
                    **_responses(
                        "Scan completed or failed",
                        success_schema={
                            "type": "object",
                            "properties": {
                                "success": {"type": "boolean"},
                                "scan_run_id": {"type": "integer", "nullable": True},
                                "findings": {"type": "array", "items": {"type": "object"}},
                                "summary": {"type": "object"},
                                "errors": {"type": "array", "items": {"type": "string"}, "nullable": True},
                            },
                        },
                    ),
                    "409": {
                        "description": "A scan is already running or queued for this project",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                },
            ),
        },
        "probe": {
            "get": _method(
                summary="List available dynamic probes",
                tags=["Probes"],
                responses=_responses(
                    "Probe catalog",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "probes": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                ),
            ),
            "post": _method(
                summary="Run dynamic probe(s) against a project endpoint",
                tags=["Probes"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["project_id"],
                                "properties": {
                                    "project_id": {"type": "integer"},
                                    "probe_id": {
                                        "type": "string",
                                        "description": "Optional; omit to run all applicable probes",
                                    },
                                    "dry_run": {"type": "boolean"},
                                },
                            },
                        }
                    },
                },
                responses=_responses(
                    "Probe results",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "success": {"type": "boolean"},
                            "findings": {"type": "array", "items": {"type": "object"}},
                            "probe_results": {"type": "object"},
                            "summary": {"type": "object"},
                            "errors": {"type": "array", "items": {"type": "string"}, "nullable": True},
                        },
                    },
                ),
            ),
        },
        "findings": {
            "get": _method(
                summary="List security findings (code scan or runtime gateway)",
                tags=["Findings"],
                parameters=[
                    {
                        "name": "source",
                        "in": "query",
                        "schema": {"type": "string", "enum": ["code", "runtime"], "default": "code"},
                        "description": "code = static findings; runtime = gateway detections",
                    },
                    {"name": "severity", "in": "query", "schema": {"type": "string"}},
                    {"name": "status", "in": "query", "schema": {"type": "string"}},
                    {"name": "category", "in": "query", "schema": {"type": "string"}},
                    {"name": "project_id", "in": "query", "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
                ],
                responses=_responses(
                    "Paginated findings",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "total": {"type": "integer"},
                            "limit": {"type": "integer"},
                            "offset": {"type": "integer"},
                            "source": {"type": "string", "enum": ["code", "runtime"]},
                            "findings": {"type": "array", "items": _FINDING_SUMMARY},
                        },
                    },
                ),
            ),
        },
        "finding_detail": {
            "get": _method(
                summary="Get finding detail",
                tags=["Findings"],
                parameters=[
                    {
                        "name": "finding_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                responses=_responses("Finding detail", success_schema=_FINDING_SUMMARY),
            ),
            "patch": _method(
                summary="Update finding status",
                tags=["Findings"],
                parameters=[
                    {
                        "name": "finding_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["status"],
                                "properties": {
                                    "status": {
                                        "type": "string",
                                        "enum": [
                                            "open",
                                            "acknowledged",
                                            "in_progress",
                                            "resolved",
                                            "false_positive",
                                            "dismissed",
                                        ],
                                    },
                                },
                            },
                        }
                    },
                },
                responses=_responses("Finding updated", success_schema=_FINDING_SUMMARY),
            ),
        },
        "threat_intel": {
            "get": _method(
                summary="List vulnerability / CVE intelligence findings",
                tags=["Threat Intel"],
                parameters=[
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
                ],
                responses=_responses(
                    "Threat intelligence feed",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "total": {"type": "integer"},
                            "entries": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                ),
            ),
            "post": _method(
                summary="Refresh CVE data from NVD and GitHub GHSA for a project",
                tags=["Threat Intel"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["project_id"],
                                "properties": {
                                    "project_id": {"type": "integer"},
                                },
                            }
                        }
                    },
                },
                responses=_responses(
                    "Threat intel refreshed",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "success": {"type": "boolean"},
                            "findings_count": {"type": "integer"},
                            "entries": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                ),
            ),
        },
        "traces": {
            "get": _method(
                summary="List AI traces (LLM calls, tool invocations)",
                tags=["Traces"],
                parameters=[
                    {"name": "project_id", "in": "query", "schema": {"type": "integer"}},
                    {"name": "trace_type", "in": "query", "schema": {"type": "string"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
                ],
                responses=_responses(
                    "Paginated traces",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "total": {"type": "integer"},
                            "traces": {"type": "array", "items": _TRACE},
                        },
                    },
                ),
            ),
            "post": _method(
                summary="Ingest AI trace spans (SDK / runtime telemetry)",
                tags=["Traces"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": [
                                    _TRACE_INGEST,
                                    {
                                        "type": "object",
                                        "required": ["traces"],
                                        "properties": {
                                            "traces": {
                                                "type": "array",
                                                "items": _TRACE_INGEST,
                                                "maxItems": 100,
                                            },
                                        },
                                    },
                                ],
                            },
                        }
                    },
                },
                responses={
                    "201": {
                        "description": "Trace(s) created",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "trace": _TRACE,
                                        "created": {"type": "integer"},
                                        "traces": {"type": "array", "items": _TRACE},
                                    },
                                }
                            }
                        },
                    },
                    "400": {"description": "Bad request", "content": {"application/json": {"schema": _ERROR}}},
                    "401": {"description": "Unauthorized", "content": {"application/json": {"schema": _ERROR}}},
                    "403": {
                        "description": "Telemetry disabled",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                },
            ),
        },

        "agents": {
            "get": _method(
                summary="List managed agents (auto-detected from gateway traffic)",
                tags=["Agents"],
                responses=_responses(
                    "Managed agents",
                    success_schema={
                        "type": "object",
                        "properties": {
                            "agents": {"type": "array", "items": _AGENT},
                        },
                    },
                ),
            ),
            "post": _method(
                summary="Register or upsert an agent by key",
                tags=["Agents"],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["agent_key"],
                                "properties": {
                                    "agent_key": {"type": "string"},
                                    "name": {"type": "string"},
                                    "metadata": {"type": "object"},
                                },
                            },
                        }
                    },
                },
                responses={
                    "201": {
                        "description": "Agent registered",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "agent": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "string", "format": "uuid"},
                                                "agent_key": {"type": "string"},
                                                "name": {"type": "string"},
                                                "control_status": {
                                                    "type": "string",
                                                    "enum": ["active", "paused", "quarantined"],
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "400": {
                        "description": "Bad request",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                    "401": {
                        "description": "Unauthorized",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                },
            ),
        },
        "agent_control": {
            "post": _method(
                summary="Pause, start, or quarantine a managed agent",
                tags=["Agents"],
                parameters=[
                    {
                        "name": "agent_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                request_body={
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["action"],
                                "properties": {
                                    "action": {
                                        "type": "string",
                                        "enum": ["pause", "start", "quarantine"],
                                    },
                                },
                            },
                        }
                    },
                },
                responses={
                    "200": {
                        "description": "Control action applied",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string", "format": "uuid"},
                                        "agent_key": {"type": "string"},
                                        "name": {"type": "string"},
                                        "control_status": {
                                            "type": "string",
                                            "enum": ["active", "paused", "quarantined"],
                                        },
                                        "action": {"type": "string"},
                                        "runtime_only": {"type": "boolean"},
                                    },
                                },
                            },
                        },
                    },
                    "400": {
                        "description": "Invalid action",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                    "401": {
                        "description": "Unauthorized",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                    "404": {
                        "description": "Agent not found",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                },
            ),
        },
        "compliance_evaluate": {
            "get": _method(
                summary="Evaluate compliance frameworks against current findings and traces",
                tags=["Compliance"],
                responses=_responses(
                    "Framework evaluation results",
                    success_schema={"type": "object"},
                ),
            ),
        },
        "compliance_posture": {
            "get": _method(
                summary="Compliance posture dashboard cards",
                tags=["Compliance"],
                responses=_responses(
                    "Posture dashboard",
                    success_schema={"type": "object"},
                ),
            ),
        },
        "compliance_audit": {
            "get": _method(
                summary="Realtime compliance audit over findings and traces",
                tags=["Compliance"],
                responses=_responses(
                    "Realtime audit report",
                    success_schema={"type": "object"},
                ),
            ),
        },
    }


def build_openapi_paths() -> Dict[str, Any]:
    """Paths under /api/v1: URLs from ``apps.api.urls``, docs from ``API_V1_ROUTE_OPERATIONS``."""
    from apps.api import openapi_discovery

    paths, warnings = openapi_discovery.build_paths_from_api_urlconf(
        API_V1_ROUTE_OPERATIONS,
        method_factory=_method,
        responses_factory=_responses,
    )
    for msg in warnings:
        logger.warning("%s", msg)
    return paths


def build_openapi_schema(*, request=None) -> Dict[str, Any]:
    if request is not None:
        origin = request.build_absolute_uri("/").rstrip("/")
    else:
        origin = "https://localhost"

    paths: Dict[str, Any] = {
        **_prefix_api_v1_paths(build_openapi_paths()),
    }

    tags = [
        {"name": "System", "description": "Health and schema"},
        {"name": "Organization", "description": "Tenant settings"},
        {"name": "Projects", "description": "Projects under your organization (list IDs here before POST /api/v1/scan/)"},
        {"name": "Scans", "description": "Static security scans (one RUNNING/QUEUED scan per project at a time)"},
        {"name": "Probes", "description": "Dynamic endpoint probes"},
        {"name": "Findings", "description": "Code, policy, and runtime gateway findings"},
        {"name": "Threat Intel", "description": "CVE and dependency advisories"},
        {"name": "Traces", "description": "AI observability traces"},
        {
            "name": "Agents",
            "description": (
                "Managed agents auto-detected from gateway traffic "
                "(X-EEG-Agent / metadata.agent_id); pause/start/quarantine"
            ),
        },
        {
            "name": "Compliance",
            "description": "Framework evaluation, posture, and realtime audit",
        },
        {
            "name": "Gateway",
            "description": "In-path runtime LLM protection (server-side scoring, optional block)",
        },
    ]

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "EEG API",
            "version": "1.0.0",
            "description": (
                "**Machine API (`/api/v1/...`):** use `Authorization: Bearer <api_key>` "
                "or `X-EEG-API-Key`. Session cookies are not accepted on these routes.\n\n"
                "**Route list:** `/api/v1/...` paths are aligned with `apps.api.urls`; each "
                "route must be documented in `API_V1_ROUTE_OPERATIONS` in `openapi_schema.py` "
                "(keyed by the route `name=`). Undocumented routes are omitted from this document.\n\n"
                "**Scans:** call `GET /api/v1/projects/` to choose a `project_id`, then "
                "`POST /api/v1/scan/` with that id. Only one scan may be RUNNING or QUEUED "
                "per project at a time (`409` if busy).\n\n"
                "**Agents:** appear automatically when gateway chat sends `X-EEG-Agent` or "
                "`metadata.agent_id`. Use `GET /api/v1/agents/` and "
                "`POST /api/v1/agents/{agent_id}/control/`.\n\n"
                "**Findings:** `GET /api/v1/findings/?source=runtime` returns gateway detections."
            ),
        },
        "servers": [{"url": origin}],
        "tags": tags,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "apiKeyHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-EEG-API-Key",
                },
            },
            "schemas": {
                "Error": _ERROR,
                "Project": _PROJECT,
                "FindingSummary": _FINDING_SUMMARY,
                "Agent": _AGENT,
                "Trace": _TRACE,
            },
        },
        "security": [{"bearerAuth": []}, {"apiKeyHeader": []}],
        "paths": paths,
    }
