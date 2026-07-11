"""MCP Transport Probe — checks MCP server endpoints.

Probes MCP server URLs for transport security, tool enumeration,
and configuration issues without full protocol interaction.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from eeg.probes import BaseProbe, ProbeResult, ProbeRegistry


@ProbeRegistry.register
class MCPTransportProbe(BaseProbe):
    """MCP server transport and configuration probe."""
    
    probe_id = "mcp_transport"
    probe_type = "network"
    description = "MCP server transport security and endpoint verification"
    categories = ["mcp", "transport", "endpoint", "configuration"]
    requires_network = True
    
    def execute(
        self,
        target: str,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ProbeResult:
        opts = options or {}
        timeout = opts.get("timeout", 10)
        
        signals: List[Dict[str, Any]] = []
        artifacts: List[Dict[str, Any]] = []
        errors: List[str] = []
        
        parsed = urlparse(target)
        
        if not parsed.scheme:
            return ProbeResult(
                probe_id=self.probe_id,
                probe_type=self.probe_type,
                posture_state="at_risk",
                signals=[{
                    "signal_category": "input",
                    "severity_band": "medium",
                    "pulse_summary": "Invalid URL format provided.",
                }],
            )
        
        if parsed.scheme == "http":
            signals.append({
                "signal_category": "transport",
                "severity_band": "high",
                "pulse_summary": "MCP server using unencrypted HTTP transport.",
                "context": {"scheme": "http", "recommendation": "Use HTTPS"},
            })
        
        if parsed.scheme in ("http", "https"):
            transport_result = self._probe_http_endpoint(target, timeout)
            signals.extend(transport_result.get("signals", []))
            artifacts.extend(transport_result.get("artifacts", []))
            errors.extend(transport_result.get("errors", []))
        elif parsed.scheme == "stdio":
            signals.append({
                "signal_category": "transport",
                "severity_band": "low",
                "pulse_summary": "MCP server using stdio transport (local process).",
            })
        elif parsed.scheme == "sse":
            signals.append({
                "signal_category": "transport",
                "severity_band": "medium", 
                "pulse_summary": "MCP server using SSE transport.",
                "context": {"note": "Verify TLS on underlying connection"},
            })
        
        high_signals = sum(1 for s in signals if s.get("severity_band") in ("high", "critical"))
        if high_signals > 0:
            posture = "at_risk"
        elif signals:
            posture = "protected"
        else:
            posture = "unknown"
        
        return ProbeResult(
            probe_id=self.probe_id,
            probe_type=self.probe_type,
            posture_state=posture,
            signals=signals,
            artifacts=artifacts,
            errors=errors,
            metadata={"target": target, "parsed_scheme": parsed.scheme},
        )
    
    def _probe_http_endpoint(self, url: str, timeout: int) -> Dict[str, Any]:
        """Probe HTTP/HTTPS MCP endpoint."""
        signals = []
        artifacts = []
        errors = []
        
        try:
            import requests
            
            headers = {
                "User-Agent": "EEG-MCP-Probe/1.0",
                "Accept": "application/json",
            }
            
            try:
                resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
                
                artifacts.append({
                    "kind": "http_response",
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "content_length": len(resp.content),
                })
                
                if "strict-transport-security" not in {k.lower() for k in resp.headers}:
                    signals.append({
                        "signal_category": "security_headers",
                        "severity_band": "medium",
                        "pulse_summary": "Missing HSTS header on MCP endpoint.",
                    })
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            if "tools" in data or "capabilities" in data:
                                signals.append({
                                    "signal_category": "enumeration",
                                    "severity_band": "low",
                                    "pulse_summary": "MCP endpoint exposes tool/capability listing.",
                                    "context": {"tool_count": len(data.get("tools", []))},
                                })
                    except json.JSONDecodeError:
                        pass
                        
            except requests.exceptions.SSLError as e:
                signals.append({
                    "signal_category": "tls",
                    "severity_band": "critical",
                    "pulse_summary": "TLS/SSL error on MCP endpoint.",
                    "context": {"error": str(e)[:200]},
                })
            except requests.exceptions.ConnectionError as e:
                errors.append(f"Connection failed: {e}")
            except requests.exceptions.Timeout:
                errors.append(f"Request timed out after {timeout}s")
                
        except ImportError:
            errors.append("requests library not available for HTTP probing")
        
        return {"signals": signals, "artifacts": artifacts, "errors": errors}
