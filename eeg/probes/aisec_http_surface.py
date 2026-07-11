"""AISec HTTP surface probe — health, spec catalog, and self-probe auth posture.

Exercises common HTTP routes on an agent HTTP API: health, LLM spec catalog,
and unauthenticated self-probe. A healthy deployment should not allow
unauthenticated self-probe execution.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from eeg.probes import BaseProbe, ProbeResult, ProbeRegistry


def _request(
    method: str,
    url: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float,
    extra_headers: Optional[Dict[str, str]] = None,
) -> tuple[Any, List[str]]:
    errors: List[str] = []
    try:
        import requests

        headers = {"User-Agent": "EEG-AisecHttpSurface-Probe/1.0"}
        if extra_headers:
            headers.update(extra_headers)
        kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "allow_redirects": False,
            "headers": headers,
        }
        if json_body is not None:
            kwargs["json"] = json_body
        resp = requests.request(method, url, **kwargs)
        return resp, errors
    except ImportError:
        errors.append("requests library not available for HTTP probing")
        return None, errors
    except Exception as e:  # noqa: BLE001
        errors.append(f"{type(e).__name__}: {e}")
        return None, errors


@ProbeRegistry.register
class AisecHttpSurfaceProbe(BaseProbe):
    """Posture checks for an agent HTTP API (FastAPI-style routes)."""

    probe_id = "aisec_http_surface"
    probe_type = "network"
    description = "Agent HTTP surface (health, specs catalog, self-probe auth)"
    categories = ["redteam", "llm", "api", "auth"]
    requires_network = True

    def execute(
        self,
        target: str,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> ProbeResult:
        opts = options or {}
        timeout = float(opts.get("timeout", 10))
        bearer = opts.get("authorization_bearer")
        signals: List[Dict[str, Any]] = []
        artifacts: List[Dict[str, Any]] = []
        errors: List[str] = []

        raw = target.strip().rstrip("/")
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        if not parsed.netloc:
            return ProbeResult(
                probe_id=self.probe_id,
                probe_type=self.probe_type,
                posture_state="at_risk",
                signals=[
                    {
                        "signal_category": "input",
                        "severity_band": "medium",
                        "pulse_summary": "Invalid base URL for HTTP surface target.",
                    }
                ],
            )

        origin = f"{parsed.scheme}://{parsed.netloc}"

        health_url = f"{origin}/health"
        resp, err = _request("GET", health_url, timeout=timeout)
        errors.extend(err)
        if resp is not None:
            artifacts.append({"kind": "health", "status_code": resp.status_code})
            if resp.status_code == 200:
                signals.append(
                    {
                        "signal_category": "availability",
                        "severity_band": "low",
                        "pulse_summary": "/health reachable.",
                    }
                )

        specs_url = f"{origin}/v1/llm-specs"
        resp_specs, err2 = _request("GET", specs_url, timeout=timeout)
        errors.extend(err2)
        if resp_specs is not None:
            artifacts.append({"kind": "llm_specs", "status_code": resp_specs.status_code})
            if resp_specs.status_code == 200:
                signals.append(
                    {
                        "signal_category": "information_disclosure",
                        "severity_band": "medium",
                        "pulse_summary": "LLM HTTP specs exposed without authentication.",
                        "context": {"url": specs_url},
                    }
                )

        probe_url = f"{origin}/v1/self-probe"
        if isinstance(bearer, str) and bearer.strip():
            r_auth, _ = _request(
                "POST",
                probe_url,
                json_body={"prompt": "EEG probe ping"},
                timeout=timeout,
                extra_headers={"Authorization": f"Bearer {bearer.strip()}"},
            )
            if r_auth is not None:
                artifacts.append({"kind": "self_probe_authed", "status_code": r_auth.status_code})

        resp_open, err3 = _request(
            "POST",
            probe_url,
            json_body={"prompt": "EEG unauthenticated surface check"},
            timeout=timeout,
        )
        errors.extend(err3)
        if resp_open is not None:
            artifacts.append({"kind": "self_probe_no_auth", "status_code": resp_open.status_code})
            if resp_open.status_code == 200:
                signals.append(
                    {
                        "signal_category": "authz",
                        "severity_band": "critical",
                        "pulse_summary": "Unauthenticated /v1/self-probe returned 200.",
                        "context": {
                            "recommendation": "Require API key or network policy in front of probe routes"
                        },
                    }
                )
            elif resp_open.status_code in (401, 403):
                signals.append(
                    {
                        "signal_category": "authz",
                        "severity_band": "low",
                        "pulse_summary": "Self-probe rejects unauthenticated callers.",
                    }
                )

        crit = sum(1 for s in signals if s.get("severity_band") == "critical")
        high = sum(1 for s in signals if s.get("severity_band") == "high")
        if crit:
            posture = "critical"
        elif high:
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
            metadata={"target": target, "origin": origin},
        )
