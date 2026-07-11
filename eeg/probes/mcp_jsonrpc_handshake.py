"""MCP JSON-RPC initialize / tools/list handshake probe (EEG-native).

Implements a minimal MCP client handshake against an HTTP MCP endpoint, based
on patterns from Agentsec-Tools ``MCP-Sec`` / ``MCP-Scanner`` and the MCP
specification (protocolVersion 2024-11-05). Target must be the full MCP HTTP
URL (e.g. ``https://host/mcp`` or ``https://host/sse`` base if server accepts
POST at that path).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from eeg.probes import BaseProbe, ProbeResult, ProbeRegistry


def _post_json(url: str, body: Dict[str, Any], timeout: float) -> tuple[Any, List[str]]:
    errors: List[str] = []
    try:
        import requests

        r = requests.post(
            url,
            json=body,
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": "EEG-MCP-Handshake/1.0",
            },
        )
        return r, errors
    except ImportError:
        errors.append("requests library not available for HTTP probing")
        return None, errors
    except Exception as e:  # noqa: BLE001
        errors.append(f"{type(e).__name__}: {e}")
        return None, errors


@ProbeRegistry.register
class MCPJsonRpcHandshakeProbe(BaseProbe):
    """POST initialize + tools/list to an MCP HTTP endpoint."""

    probe_id = "mcp_jsonrpc_handshake"
    probe_type = "network"
    description = "MCP JSON-RPC initialize and tools/list handshake"
    categories = ["mcp", "protocol", "enumeration"]
    requires_network = True

    def execute(
        self,
        target: str,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ProbeResult:
        opts = options or {}
        timeout = float(opts.get("timeout", 15))
        protocol_version = str(opts.get("protocol_version", "2024-11-05"))
        signals: List[Dict[str, Any]] = []
        artifacts: List[Dict[str, Any]] = []
        errors: List[str] = []

        url = target.strip()
        parsed = urlparse(url if "://" in url else f"https://{url}")
        if not parsed.scheme or not parsed.netloc:
            return ProbeResult(
                probe_id=self.probe_id,
                probe_type=self.probe_type,
                posture_state="at_risk",
                signals=[
                    {
                        "signal_category": "input",
                        "severity_band": "medium",
                        "pulse_summary": "Provide full MCP HTTP URL including path.",
                    }
                ],
            )

        if parsed.scheme == "http":
            signals.append(
                {
                    "signal_category": "transport",
                    "severity_band": "high",
                    "pulse_summary": "MCP endpoint uses HTTP without TLS.",
                }
            )

        init_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "EEG-MCP-Handshake", "version": "1.0"},
            },
        }

        resp, err = _post_json(url, init_body, timeout)
        errors.extend(err)
        if resp is None:
            return ProbeResult(
                probe_id=self.probe_id,
                probe_type=self.probe_type,
                posture_state="unknown",
                signals=signals,
                errors=errors,
            )

        artifacts.append(
            {"kind": "initialize", "status_code": resp.status_code, "content_type": resp.headers.get("Content-Type")}
        )

        if resp.status_code >= 400:
            signals.append(
                {
                    "signal_category": "protocol",
                    "severity_band": "medium",
                    "pulse_summary": f"initialize returned HTTP {resp.status_code}.",
                }
            )
            posture = "at_risk" if resp.status_code >= 500 else "unknown"
            return ProbeResult(
                probe_id=self.probe_id,
                probe_type=self.probe_type,
                posture_state=posture,
                signals=signals,
                artifacts=artifacts,
                errors=errors,
                metadata={"target": url},
            )

        text = resp.text[:8000]
        if "jsonrpc" not in text and "event:" not in text.lower():
            signals.append(
                {
                    "signal_category": "protocol",
                    "severity_band": "medium",
                    "pulse_summary": "Response body does not look like JSON-RPC or SSE.",
                }
            )

        list_body = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        resp2, err2 = _post_json(url, list_body, timeout)
        errors.extend(err2)
        if resp2 is not None:
            artifacts.append({"kind": "tools_list", "status_code": resp2.status_code})
            if resp2.status_code == 200:
                try:
                    data = resp2.json()
                    tools = (data.get("result") or {}).get("tools")
                    if isinstance(tools, list) and len(tools) > 0:
                        signals.append(
                            {
                                "signal_category": "enumeration",
                                "severity_band": "low",
                                "pulse_summary": f"MCP server enumerated {len(tools)} tools (unauthenticated).",
                                "context": {"sample_names": [t.get("name") for t in tools[:5] if isinstance(t, dict)]},
                            }
                        )
                except (json.JSONDecodeError, TypeError, AttributeError):
                    signals.append(
                        {
                            "signal_category": "enumeration",
                            "severity_band": "low",
                            "pulse_summary": "tools/list returned 200 but body was not JSON-RPC JSON.",
                        }
                    )

        high = sum(1 for s in signals if s.get("severity_band") in ("high", "critical"))
        posture = "at_risk" if high else ("protected" if signals else "unknown")

        return ProbeResult(
            probe_id=self.probe_id,
            probe_type=self.probe_type,
            posture_state=posture,
            signals=signals,
            artifacts=artifacts,
            errors=errors,
            metadata={"target": url, "protocol_version": protocol_version},
        )
