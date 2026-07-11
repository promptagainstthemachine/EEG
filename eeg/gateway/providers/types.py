"""Vendor dispatch types for the EEG AI proxy gateway."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

TransportKind = Literal["http", "bedrock_sdk", "bedrock_invoke"]
ResponseShape = Literal[
    "openai_json",
    "anthropic_json",
    "bedrock_json",
    "vertex_json",
    "bedrock_embed_json",
    "bedrock_image_json",
    "bedrock_speech_json",
    "vertex_embed_json",
    "vertex_image_json",
]
StreamShape = Literal["openai_sse", "anthropic_sse", "bedrock_eventstream", "vertex_sse", "none"]


@dataclass
class VendorPlan:
    vendor_slug: str
    transport: TransportKind
    request_url: str
    request_headers: dict[str, str]
    request_body: dict[str, Any]
    response_shape: ResponseShape
    stream_shape: StreamShape
    capability: str = "chat"
    http_method: str = "POST"
    multipart: bool = False
    bedrock_model_id: str = ""
    bedrock_region: str = ""
    bedrock_credentials: dict[str, str] = field(default_factory=dict)
    vertex_model: str = ""
    vertex_project: str = ""
    vertex_location: str = ""
