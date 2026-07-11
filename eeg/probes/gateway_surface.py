"""LLM / MCP gateway posture probe (EEG-native).

Checks transport and common surface paths (health, MCP route) without invoking
external binaries. Target should be the gateway base URL.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from eeg.probes import BaseProbe, ProbeResult, ProbeRegistry


def _get(url: str, timeout: float) -> tuple[Any, List[str]]:
    errors: List[str] = []
    try:
        import requests

        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "EEG-GatewaySurface-Probe/1.0", "Accept": "*/*"},
        )
        return resp, errors
    except ImportError:
        errors.append("requests library not available for HTTP probing")
        return None, errors
    except Exception as e:  # noqa: BLE001 — surface probe errors to caller
        errors.append(f"{type(e).__name__}: {e}")
        return None, errors


@ProbeRegistry.register
class GatewaySurfaceProbe(BaseProbe):
    """TLS, health, and MCP route reachability for LLM/MCP gateways."""

    probe_id = "gateway_surface"
    probe_type = "network"
    description = "Gateway surface (TLS, /health, /mcp)"
    categories = ["gateway", "mcp", "llm", "transport"]
    requires_network = True

    def execute(
        self,
        target: str,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ProbeResult:
        opts = options or {}
        timeout = float(opts.get("timeout", 10))
        signals: List[Dict[str, Any]] = []
        artifacts: List[Dict[str, Any]] = []
        errors: List[str] = []

        base = target.strip().rstrip("/")
        parsed = urlparse(base if "://" in base else f"https://{base}")
        if not parsed.scheme or not parsed.netloc:
            return ProbeResult(
                probe_id=self.probe_id,
                probe_type=self.probe_type,
                posture_state="at_risk",
                signals=[
                    {
                        "signal_category": "input",
                        "severity_band": "medium",
                        "pulse_summary": "Invalid or missing gateway URL.",
                    }
                ],
            )

        origin = f"{parsed.scheme}://{parsed.netloc}"

        if parsed.scheme == "http":
            signals.append(
                {
                    "signal_category": "transport",
                    "severity_band": "high",
                    "pulse_summary": "Gateway uses cleartext HTTP.",
                    "context": {"recommendation": "Terminate TLS at the gateway or behind ingress"},
                }
            )

        for path in ("/health", "/mcp"):
            url = f"{origin}{path}"
            resp, err = _get(url, timeout)
            errors.extend(err)
            if resp is None:
                continue
            artifacts.append(
                {
                    "kind": "http_probe",
                    "url": url,
                    "status_code": resp.status_code,
                    "server": resp.headers.get("Server"),
                }
            )
            if resp.status_code in (301, 302, 307, 308):
                signals.append(
                    {
                        "signal_category": "routing",
                        "severity_band": "low",
                        "pulse_summary": f"{path} returned redirect {resp.status_code}.",
                        "context": {"location": resp.headers.get("Location", "")[:200]},
                    }
                )
            elif resp.status_code == 404 and path == "/mcp":
                signals.append(
                    {
                        "signal_category": "surface",
                        "severity_band": "low",
                        "pulse_summary": "MCP path not found at /mcp (custom mount may apply).",
                    }
                )
            elif resp.status_code >= 500:
                signals.append(
                    {
                        "signal_category": "availability",
                        "severity_band": "medium",
                        "pulse_summary": f"{path} returned server error {resp.status_code}.",
                    }
                )
            elif path == "/health" and resp.status_code == 200:
                ct = (resp.headers.get("Content-Type") or "").lower()
                if "json" in ct:
                    try:
                        body = resp.json()
                        if isinstance(body, dict) and str(body.get("status", "")).lower() in (
                            "ok",
                            "healthy",
                            "up",
                        ):
                            signals.append(
                                {
                                    "signal_category": "health",
                                    "severity_band": "low",
                                    "pulse_summary": "Health endpoint reports OK.",
                                }
                            )
                    except json.JSONDecodeError:
                        signals.append(
                            {
                                "signal_category": "health",
                                "severity_band": "low",
                                "pulse_summary": "Health endpoint reachable (non-JSON body).",
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
            metadata={"target": target, "origin": origin},
        )
