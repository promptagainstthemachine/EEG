"""Local gateway wrap server — proxy OpenAI-style chat through EEG runtime."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse

from eeg.gateway.proxy import GatewayBlockedError, blocked_response, proxy_chat_completion
from eeg.gateway.streaming_proxy import stream_chat_completion
from eeg.runtime.policy_config import RuntimePolicyConfig


def normalize_wrap_upstream(url: str) -> str:
    """Ensure wrap target ends at a chat-completions style path when bare."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError("gateway-wrap URL is required")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("gateway-wrap URL must use http or https")
    if not parsed.netloc:
        raise ValueError("gateway-wrap URL must include a host")
    path = (parsed.path or "").rstrip("/")
    if not path or path == "":
        return raw.rstrip("/") + "/v1/chat/completions"
    # Already points at a concrete path (e.g. .../v1/chat/completions)
    return raw.rstrip("/")


class GatewayWrapHandler(BaseHTTPRequestHandler):
    """Minimal OpenAI-compatible front door in front of a wrap upstream."""

    upstream_url: str = ""
    listen_prefix: str = "/v1"
    config: RuntimePolicyConfig = RuntimePolicyConfig(
        enforcement_enabled=True,
        runtime_protection_enabled=True,
    )

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("eeg-gateway-wrap: " + (fmt % args) + "\n")

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON body") from exc
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object")
        return data

    def _upstream_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        auth = self.headers.get("Authorization") or self.headers.get("X-EEG-Upstream-Authorization")
        if auth:
            headers["Authorization"] = auth
        api_key = self.headers.get("X-EEG-Provider-Key")
        if api_key and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/health", "/healthz", f"{self.listen_prefix}/health"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "mode": "gateway-wrap",
                    "upstream": self.upstream_url,
                },
            )
            return
        self._send_json(404, {"error": {"message": "Not found", "code": "not_found"}})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        chat_paths = {
            f"{self.listen_prefix}/chat/completions",
            "/v1/chat/completions",
            "/chat/completions",
        }
        if path not in chat_paths:
            self._send_json(404, {"error": {"message": f"Unsupported path: {path}", "code": "not_found"}})
            return

        try:
            body = self._read_json()
        except ValueError as exc:
            self._send_json(400, {"error": {"message": str(exc), "code": "invalid_request"}})
            return

        stream = bool(body.get("stream"))
        headers = self._upstream_headers()

        try:
            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                try:
                    for chunk in stream_chat_completion(
                        body,
                        upstream_url=self.upstream_url,
                        upstream_headers=headers,
                        config=self.config,
                    ):
                        self.wfile.write(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)
                        self.wfile.flush()
                except GatewayBlockedError as exc:
                    _, blocked = blocked_response(exc.decision)
                    self.wfile.write(f"data: {json.dumps(blocked)}\n\n".encode("utf-8"))
                    self.wfile.write(b"data: [DONE]\n\n")
                return

            status, payload = proxy_chat_completion(
                body,
                upstream_url=self.upstream_url,
                upstream_headers=headers,
                config=self.config,
            )
            self._send_json(status, payload)
        except GatewayBlockedError as exc:
            code, blocked = blocked_response(exc.decision)
            self._send_json(code, blocked)
        except Exception as exc:  # noqa: BLE001
            self._send_json(
                502,
                {"error": {"message": f"Gateway wrap failed: {exc}", "code": "gateway_wrap_error"}},
            )


def run_gateway_wrap(
    upstream_url: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    allow_private: bool = True,
) -> int:
    """Serve a local EEG gateway that wraps *upstream_url*."""
    from eeg.gateway.url_safety import validate_upstream_url
    from eeg.runtime.conduit_gates import gate_url

    normalized = normalize_wrap_upstream(upstream_url)
    conduit = gate_url(normalized, allow_private=allow_private)
    if not conduit.allowed and conduit.result_class != "infrastructure":
        raise SystemExit(
            f"eeg: gateway-wrap refused upstream ({', '.join(conduit.reasons) or conduit.action})\n"
        )
    validate_upstream_url(normalized, allow_private=allow_private)

    handler = type(
        "BoundGatewayWrapHandler",
        (GatewayWrapHandler,),
        {
            "upstream_url": normalized,
            "config": RuntimePolicyConfig(
                enforcement_enabled=True,
                runtime_protection_enabled=True,
            ),
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    sys.stderr.write(
        f"EEG gateway-wrap listening on http://{host}:{port}\n"
        f"  POST /v1/chat/completions  →  {normalized}\n"
        f"  GET  /health\n"
        "Press Ctrl+C to stop.\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nEEG gateway-wrap stopped.\n")
        return 0
    finally:
        server.server_close()
    return 0


def run_web_serve(*, host: str = "127.0.0.1", port: int = 8000) -> int:
    """Serve the full EEG OSS Django/ASGI web app."""
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
    # Allow binding host in ALLOWED_HOSTS for local serve
    allowed = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
    if host not in allowed.split(",") and host not in ("0.0.0.0", "::"):
        os.environ["DJANGO_ALLOWED_HOSTS"] = f"{allowed},{host}"

    bind = f"{host}:{port}"
    sys.stderr.write(f"EEG serve starting on http://{host}:{port}\n")

    try:
        from daphne.cli import CommandLineInterface

        CommandLineInterface().run(["-b", host, "-p", str(port), "core.asgi:application"])
        return 0
    except ImportError:
        pass

    from django.core.management import execute_from_command_line

    execute_from_command_line(["manage.py", "runserver", bind, "--noreload"])
    return 0
