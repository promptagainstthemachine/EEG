"""Provider catalog types for the EEG multi-vendor gateway."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Capability = Literal[
    "chat",
    "embed",
    "image",
    "speech",
    "transcription",
    "batch",
    "files",
    "realtime",
    "mcp_toolsets",
]

ProviderFamily = Literal[
    "openai",
    "anthropic",
    "google",
    "bedrock",
    "vertex",
    "azure_foundry",
    "cohere",
    "custom",
]

AuthStyle = Literal["bearer", "x-api-key", "none"]

ALL_CAPABILITIES: frozenset[str] = frozenset(
    {
        "chat",
        "embed",
        "image",
        "speech",
        "transcription",
        "batch",
        "files",
        "realtime",
        "mcp_toolsets",
    }
)

CHAT_CAPS: frozenset[str] = frozenset({"chat", "mcp_toolsets"})
CHAT_EMBED_CAPS: frozenset[str] = frozenset({"chat", "embed", "mcp_toolsets"})
FULL_OPENAI_CAPS: frozenset[str] = frozenset(ALL_CAPABILITIES)


@dataclass(frozen=True)
class ProviderDefinition:
    id: str
    name: str
    family: ProviderFamily
    base_url: str
    capabilities: frozenset[str]
    auth_style: AuthStyle = "bearer"
    api_version: str = ""
    notes: str = ""

    def supports(self, capability: str) -> bool:
        if capability == "mcp_toolsets":
            return "chat" in self.capabilities or "mcp_toolsets" in self.capabilities
        return capability in self.capabilities


CAPABILITY_PATHS: dict[str, str] = {
    "chat": "/chat/completions",
    "embed": "/embeddings",
    "image": "/images/generations",
    "speech": "/audio/speech",
    "transcription": "/audio/transcriptions",
    "batch": "/batches",
    "files": "/files",
    "realtime": "/realtime/sessions",
}

MULTIPART_CAPABILITIES: frozenset[str] = frozenset({"transcription", "files"})
