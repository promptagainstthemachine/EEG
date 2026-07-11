"""MCP toolset normalization for chat completion requests."""
from __future__ import annotations

from typing import Any


def normalize_mcp_toolsets(body: dict[str, Any]) -> dict[str, Any]:
    """Pass through MCP toolsets and ensure tools array is well-formed."""
    payload = dict(body)
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return payload

    normalized: list[Any] = []
    for tool in tools:
        if not isinstance(tool, dict):
            normalized.append(tool)
            continue
        tool_type = str(tool.get("type") or "function")
        if tool_type == "mcp_toolset":
            entry = dict(tool)
            entry.setdefault("type", "mcp_toolset")
            if "mcp_server_name" not in entry and "server" in entry:
                entry["mcp_server_name"] = entry["server"]
            normalized.append(entry)
        else:
            normalized.append(tool)
    payload["tools"] = normalized
    return payload
