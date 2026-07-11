"""Runtime gateway API — in-path LLM protection (OSS)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from django.http import JsonResponse, StreamingHttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.api.gateway_audit import record_gateway_block
from apps.api.views import require_api_auth
from apps.security.trace_ingest import ingest_traces
from eeg.gateway.capability_executor import dispatch_capability
from eeg.gateway.connector_dispatch import build_connector_vendor_plan
from eeg.gateway.pass_through import build_pass_through_config, parse_pass_through
from eeg.gateway.proxy import GatewayBlockedError, blocked_response, guard_messages, proxy_chat_completion
from eeg.gateway.streaming_proxy import stream_chat_completion
from eeg.gateway.vendor_executor import proxy_chat_via_plan, stream_chat_via_plan
from eeg.runtime.policy_config import RuntimePolicyConfig


def _org_runtime_flags(org) -> tuple[bool, bool]:
    enforcement = bool(getattr(org, "policy_enforcement_enabled", False))
    runtime = bool(getattr(org, "runtime_protection_enabled", False))
    return enforcement, runtime or enforcement


def _policy_config(org) -> RuntimePolicyConfig:
    enforcement, runtime = _org_runtime_flags(org)
    workspace = getattr(org, "runtime_policy_config", None) or {}
    if not isinstance(workspace, dict):
        workspace = {}
    return RuntimePolicyConfig(
        enforcement_enabled=enforcement,
        runtime_protection_enabled=runtime,
        workspace_config=dict(workspace),
    )


def _parse_json_body(request) -> tuple[Optional[dict], Optional[JsonResponse]]:
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return None, JsonResponse({"error": "Invalid JSON"}, status=400)
    if not isinstance(body, dict):
        return None, JsonResponse({"error": "Request body must be a JSON object"}, status=400)
    return body, None


def _default_trace_type_for_capability(capability: str) -> str:
    if capability in ("embed", "embeddings", "retrieval"):
        return "retrieval"
    if capability in ("mcp", "mcp_tool", "mcp_toolsets"):
        return "mcp_tool"
    return "llm_call"


def _extract_tool_calls(payload: Any) -> list[dict]:
    """Collect tool/function call descriptors from chat request or response bodies."""
    found: list[dict] = []
    if not isinstance(payload, dict):
        return found
    # Request-side tools / tool_choice context is not a call; look for messages tool_calls
    for msg in payload.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        for tc in msg.get("tool_calls") or []:
            if isinstance(tc, dict):
                found.append(tc)
        if msg.get("role") == "tool" and msg.get("name"):
            found.append({"function": {"name": msg.get("name"), "arguments": msg.get("content", "")}})
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        msg = choice.get("message") or {}
        if isinstance(msg, dict):
            for tc in msg.get("tool_calls") or []:
                if isinstance(tc, dict):
                    found.append(tc)
    for tc in payload.get("tool_calls") or []:
        if isinstance(tc, dict):
            found.append(tc)
    return found


def _tool_name_args(tc: dict) -> tuple[str, str]:
    fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
    name = str(tc.get("name") or fn.get("name") or "tool")[:128]
    args = tc.get("arguments") if tc.get("arguments") is not None else fn.get("arguments", "")
    if isinstance(args, (dict, list)):
        args = json.dumps(args)[:2000]
    else:
        args = str(args or "")[:2000]
    return name, args


def _make_ingest_cb(org, project_id=None, *, default_trace_type: str = "llm_call", agent_key: str = ""):
    def _ingest_cb(**fields):
        if not getattr(org, "realtime_telemetry_enabled", True):
            return
        started = fields.get("started_at") or datetime.now(timezone.utc)
        blocked = bool(fields.get("blocked_by_policy") or fields.get("blocked"))
        risk = float(fields.get("risk_score") or 0)
        trace_type = fields.get("trace_type") or default_trace_type or "llm_call"
        meta = {
            "source": "eeg_gateway",
            "blocked_by_policy": blocked,
            "policy_action": fields.get("policy_action"),
            "tier": fields.get("tier"),
            "detection_tags": list(fields.get("detection_tags") or []),
            "agent_key": agent_key or fields.get("agent_key") or "",
            "surface": trace_type,
        }
        if fields.get("tool_name"):
            meta["tool_name"] = fields.get("tool_name")
        if fields.get("tool_arguments") is not None:
            meta["tool_arguments"] = fields.get("tool_arguments")
        if fields.get("mcp_server"):
            meta["mcp_server"] = fields.get("mcp_server")
        if fields.get("mcp_tool"):
            meta["mcp_tool"] = fields.get("mcp_tool")
        extra_meta = fields.get("metadata")
        if isinstance(extra_meta, dict):
            meta.update(extra_meta)

        parent_trace_id = fields.get("trace_id") or f"gw-{uuid4().hex[:16]}"
        rows = [
            {
                "trace_id": parent_trace_id,
                "span_id": f"span-{uuid4().hex[:12]}",
                "trace_type": trace_type,
                "status": "blocked" if blocked else "success",
                "provider": fields.get("provider") or "gateway",
                "model": fields.get("model", ""),
                "input_text": fields.get("input_text", ""),
                "output_text": fields.get("output_text", ""),
                "risk_score": risk,
                "risk_signals": fields.get("risk_signals", []),
                "latency_ms": fields.get("latency_ms", 0),
                "started_at": started.isoformat() if hasattr(started, "isoformat") else started,
                "project_id": project_id,
                "session_id": fields.get("session_id") or (f"agent-{agent_key}" if agent_key else "gateway"),
                "metadata": meta,
            }
        ]

        # Emit separate tool_call / mcp_tool spans when tool invocations are present.
        tool_payload = fields.get("response_body") or fields.get("request_body") or {}
        for tc in _extract_tool_calls(tool_payload):
            name, args = _tool_name_args(tc)
            is_mcp = name.startswith("mcp_") or "mcp" in name.lower() or bool(fields.get("mcp_server"))
            rows.append(
                {
                    "trace_id": parent_trace_id,
                    "span_id": f"span-{uuid4().hex[:12]}",
                    "parent_span_id": rows[0]["span_id"],
                    "trace_type": "mcp_tool" if is_mcp else "tool_call",
                    "status": "blocked" if blocked else "success",
                    "provider": fields.get("provider") or "gateway",
                    "model": fields.get("model", ""),
                    "input_text": args,
                    "output_text": "",
                    "risk_score": risk,
                    "risk_signals": list(fields.get("risk_signals") or []) + ["tool_call"],
                    "latency_ms": 0,
                    "started_at": started.isoformat() if hasattr(started, "isoformat") else started,
                    "project_id": project_id,
                    "session_id": fields.get("session_id") or (f"agent-{agent_key}" if agent_key else "gateway"),
                    "metadata": {
                        **meta,
                        "tool_name": name,
                        "tool_arguments": args,
                        "surface": "mcp_tool" if is_mcp else "tool_call",
                        "detection_tags": list(meta.get("detection_tags") or [])
                        + (["mcp", name] if is_mcp else ["tool", name]),
                    },
                }
            )

        ingest_traces(org, rows)
        # Prefer explicit agent_key; fall back to fields metadata.
        key = (agent_key or fields.get("agent_key") or "").strip()
        if not key:
            meta_agent = meta.get("agent_key") or meta.get("agent_id") or ""
            key = str(meta_agent).strip()
        if key:
            from apps.security.agent_control import ensure_agent

            ensure_agent(org, key, name=str(meta.get("name") or key))

    return _ingest_cb


def _maybe_block_agent(org, request, body: dict) -> Optional[JsonResponse]:
    from apps.security.agent_control import (
        is_agent_blocked,
        resolve_agent_ref,
        touch_agent_from_request,
    )
    from eeg.runtime.guard import GuardDecision

    # Always auto-register when an agent identity is present — before block checks.
    touch_agent_from_request(org, request, body)

    agent_ref = resolve_agent_ref(request, body)
    blocked, status = is_agent_blocked(org, agent_ref)
    if not blocked:
        return None
    decision = GuardDecision(
        blocked=True,
        reason=f"Agent '{agent_ref}' is {status}",
        risk_score=1.0,
        risk_signals=["agent_control", status],
        phase="request",
        tier="block",
        policy_action="block",
        detection_tags=["agent_control", status],
        primary_reason=f"Agent '{agent_ref}' is {status}",
    )
    record_gateway_block(
        organization=org,
        request=request,
        phase="request",
        reason=decision.reason,
        risk_score=decision.risk_score,
        risk_signals=decision.risk_signals,
        extra={"agent_key": agent_ref, "control_status": status},
    )
    ingest = _make_ingest_cb(org, body.get("project_id"), agent_key=agent_ref)
    ingest(
        trace_id=f"block-{uuid4().hex[:12]}",
        model=str(body.get("model") or ""),
        input_text=f"agent_control:{status}:{agent_ref}",
        output_text="",
        risk_score=1.0,
        risk_signals=["agent_control", status],
        blocked=True,
        detection_tags=["agent_control", status],
        trace_type="agent_control",
        session_id=f"agent-{agent_ref}",
    )
    status_code, payload = blocked_response(decision)
    return JsonResponse(payload, status=status_code)

def _header(request, name: str) -> Optional[str]:
    return request.headers.get(name)


def _resolve_pass_through(request, body: dict) -> Any:
    provider_config = body.pop("provider_config", None)
    if isinstance(provider_config, dict):
        provider_config_header = json.dumps(provider_config)
    else:
        provider_config_header = _header(request, "X-EEG-Provider-Config") or provider_config
    return parse_pass_through(
        provider_header=_header(request, "X-EEG-Provider") or body.pop("provider", None),
        api_key_header=_header(request, "X-EEG-Provider-Key") or body.pop("provider_key", None),
        upstream_url=_header(request, "X-EEG-Upstream-URL") or body.get("upstream_url"),
        upstream_authorization=_header(request, "X-EEG-Upstream-Authorization"),
        provider_config_header=provider_config_header,
    )


def _connector_id(request, body: dict) -> Optional[int]:
    raw = _header(request, "X-EEG-Connector-Id") or body.pop("connector_id", None)
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("connector_id must be an integer") from exc


def _dispatch_with_plan(
    *,
    org,
    body: dict,
    request,
    capability: str = "chat",
    stream: bool = False,
):
    cfg = _policy_config(org)
    project_id = body.pop("project_id", None)
    from apps.security.agent_control import resolve_agent_ref

    agent_key = resolve_agent_ref(request, body)
    base_ingest = _make_ingest_cb(
        org,
        project_id,
        default_trace_type=_default_trace_type_for_capability(capability),
        agent_key=agent_key,
    )
    request_snapshot = dict(body)

    def ingest(**fields):
        fields.setdefault("request_body", request_snapshot)
        return base_ingest(**fields)

    gateway_label = _header(request, "X-EEG-Gateway-Label") or body.pop("gateway_label", None)
    session_id = f"agent-{agent_key}" if agent_key else f"org-{org.pk}"

    auth = _resolve_pass_through(request, body)
    connector_id = _connector_id(request, body)

    if auth is not None:
        config_override = build_pass_through_config(auth)
        _row, plan, _config, _route = build_connector_vendor_plan(
            None,
            org.id,
            body,
            stream=stream,
            capability=capability,
            config_override=config_override,
        )
    elif connector_id is not None or gateway_label:
        _row, plan, _config, _route = build_connector_vendor_plan(
            None,
            org.id,
            body,
            stream=stream,
            connector_id=connector_id,
            gateway_label=gateway_label,
            capability=capability,
        )
    else:
        if capability != "chat":
            raise ValueError(
                f"Capability '{capability}' requires X-EEG-Provider + X-EEG-Provider-Key "
                "or a stored gateway connector."
            )
        upstream_url = (
            _header(request, "X-EEG-Upstream-URL") or body.pop("upstream_url", None) or ""
        ).strip()
        if not upstream_url:
            raise ValueError(
                "Missing upstream. Set X-EEG-Provider + X-EEG-Provider-Key, "
                "a connector, or X-EEG-Upstream-URL."
            )
        upstream_headers = body.pop("upstream_headers", None) or {}
        if not isinstance(upstream_headers, dict):
            raise ValueError("upstream_headers must be an object")
        auth_hdr = _header(request, "X-EEG-Upstream-Authorization")
        if auth_hdr and "Authorization" not in upstream_headers:
            upstream_headers["Authorization"] = auth_hdr
        if stream:
            return "stream_url", stream_chat_completion(
                body,
                upstream_url=upstream_url,
                upstream_headers=upstream_headers,
                config=cfg,
                ingest_callback=ingest,
                session_id=session_id,
            )
        status, payload = proxy_chat_completion(
            body,
            upstream_url=upstream_url,
            upstream_headers=upstream_headers,
            enforcement_enabled=cfg.enforcement_enabled,
            runtime_protection_enabled=cfg.runtime_protection_enabled,
            block_threshold=cfg.block_threshold,
            ingest_callback=ingest,
            session_id=session_id,
        )
        return "json", (status, payload)

    if capability != "chat":
        result = dispatch_capability(
            capability,
            body,
            plan,
            config=cfg,
            ingest_callback=ingest,
            stream=stream,
            session_id=session_id,
        )
        if stream:
            return "stream_plan", result
        return "json", result

    if stream:
        return "stream_plan", stream_chat_via_plan(
            body,
            plan,
            config=cfg,
            ingest_callback=ingest,
            session_id=session_id,
        )
    status, payload = proxy_chat_via_plan(
        body,
        plan,
        config=cfg,
        ingest_callback=ingest,
        session_id=session_id,
    )
    return "json", (status, payload)


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class GatewayGuardView(View):
    """Check prompts/responses without calling an upstream LLM."""

    def post(self, request):
        org = request.organization
        enforcement, runtime = _org_runtime_flags(org)

        body, err = _parse_json_body(request)
        if err:
            return err

        messages = body.get("messages")
        if not isinstance(messages, list):
            return JsonResponse({"error": "messages must be an array"}, status=400)

        phase = str(body.get("phase") or "request").lower()
        if phase not in ("request", "response"):
            return JsonResponse({"error": "phase must be request or response"}, status=400)

        decision = guard_messages(
            messages,
            phase=phase,
            enforcement_enabled=enforcement,
            runtime_protection_enabled=runtime,
            session_id=f"org-{org.pk}",
        )
        return JsonResponse(
            {
                "allowed": not decision.blocked,
                "blocked": decision.blocked,
                "reason": decision.reason,
                "risk_score": decision.risk_score,
                "risk_signals": decision.risk_signals,
                "phase": phase,
                "tier": decision.tier,
                "policy_action": decision.policy_action,
                "detection_tags": decision.detection_tags,
                "primary_reason": decision.primary_reason,
                "confidence": decision.confidence,
                "confidence_band": decision.confidence_band,
                "layer_scores": decision.layer_scores,
                "guardrail_categories": decision.guardrail_categories,
                "sanitized_text": decision.sanitized_text,
            }
        )


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class GatewayLatticeView(View):
    """Full multi-layer lattice inspection (sigil / spectral / tool / shard)."""

    def post(self, request):
        org = request.organization
        enforcement, runtime = _org_runtime_flags(org)
        body, err = _parse_json_body(request)
        if err:
            return err

        text = body.get("text")
        messages = body.get("messages")
        if text is None and isinstance(messages, list):
            from eeg.runtime.guard import guard_messages as _gm

            decision, _ = _gm(
                messages,
                phase=str(body.get("phase") or "request").lower(),
                enforcement_enabled=enforcement,
                runtime_protection_enabled=runtime,
                session_id=str(body.get("session_id") or f"org-{org.pk}"),
            )
            return JsonResponse(
                {
                    "allowed": not decision.blocked,
                    "blocked": decision.blocked,
                    "action": decision.policy_action,
                    "tier": decision.tier,
                    "primary_reason": decision.primary_reason,
                    "risk_score": decision.risk_score,
                    "confidence": decision.confidence,
                    "confidence_band": decision.confidence_band,
                    "threats": decision.detection_tags,
                    "detection_tags": decision.detection_tags,
                    "layer_scores": decision.layer_scores,
                    "risk_signals": decision.risk_signals,
                    "sanitized_text": decision.sanitized_text,
                    "phase": str(body.get("phase") or "request").lower(),
                }
            )

        if not isinstance(text, str) or not text.strip():
            return JsonResponse(
                {"error": "Provide non-empty 'text' or 'messages' array"},
                status=400,
            )

        from eeg.runtime.lattice_pipeline import inspect_lattice, lattice_result_payload
        from eeg.runtime.policy_config import RuntimePolicyConfig

        # Lattice inspect is an analysis surface: always evaluate layers.
        cfg = RuntimePolicyConfig(
            enforcement_enabled=True,
            runtime_protection_enabled=True,
        )
        result = inspect_lattice(
            text,
            phase=str(body.get("phase") or "request").lower(),
            prior_prompt=str(body.get("prior_prompt") or ""),
            config=cfg,
            session_id=str(body.get("session_id") or f"org-{org.pk}"),
            tool_name=str(body.get("tool_name") or ""),
            tool_arguments=body.get("tool_arguments"),
        )
        payload = lattice_result_payload(result)
        payload["phase"] = str(body.get("phase") or "request").lower()
        payload["org_runtime_enabled"] = bool(runtime or enforcement)
        return JsonResponse(payload)


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class GatewayLatticePacksView(View):
    """List compiled runtime sigil packs available to the lattice."""

    def get(self, request):
        from eeg.runtime.sigil_weave import list_pack_catalog
        from eeg.runtime.spectral_probe import spectral_engine_status

        packs = list_pack_catalog()
        return JsonResponse(
            {
                "packs": packs,
                "count": len(packs),
                "layers": [
                    {"id": "sigil", "label": "Sigil weave"},
                    {"id": "spectral", "label": "Spectral probe"},
                    {"id": "heuristic", "label": "Heuristic scorer"},
                    {"id": "tool", "label": "Tool weave"},
                    {"id": "shard", "label": "Shard buffer"},
                ],
                "ml_engines": spectral_engine_status(),
            }
        )


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class GatewayConduitView(View):
    """Egress URL admission check for gateway-wrap / tool fetches."""

    def post(self, request):
        body, err = _parse_json_body(request)
        if err:
            return err
        url = body.get("url")
        if not isinstance(url, str) or not url.strip():
            return JsonResponse({"error": "url is required"}, status=400)
        from eeg.runtime.conduit_gates import gate_url

        allow_private = bool(
            body.get("allow_private")
            or getattr(request.organization, "allow_private_upstream", False)
        )
        verdict = gate_url(url.strip(), allow_private=allow_private)
        return JsonResponse(verdict.to_dict())


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class GatewayChatCompletionsView(View):
    """OpenAI-compatible chat completions proxy (URL, BYOK, or stored connector)."""

    def post(self, request):
        org = request.organization
        enforcement, runtime = _org_runtime_flags(org)

        if not runtime and not enforcement:
            return JsonResponse(
                {
                    "error": "Runtime protection is disabled for this organization.",
                    "code": "runtime_protection_disabled",
                },
                status=403,
            )

        body, err = _parse_json_body(request)
        if err:
            return err

        agent_block = _maybe_block_agent(org, request, body)
        if agent_block is not None:
            return agent_block

        stream = bool(body.get("stream"))
        try:
            kind, result = _dispatch_with_plan(
                org=org,
                body=body,
                request=request,
                capability="chat",
                stream=stream,
            )
        except GatewayBlockedError as exc:
            record_gateway_block(
                organization=org,
                request=request,
                phase=exc.decision.phase,
                reason=exc.decision.reason,
                risk_score=exc.decision.risk_score,
                risk_signals=exc.decision.risk_signals,
            )
            code, blocked = blocked_response(exc.decision)
            return JsonResponse(blocked, status=code)
        except ValueError as exc:
            return JsonResponse({"error": str(exc), "code": "invalid_request"}, status=400)

        if kind in ("stream_url", "stream_plan"):

            def _gen():
                try:
                    yield from result
                except GatewayBlockedError as exc:
                    record_gateway_block(
                        organization=org,
                        request=request,
                        phase=exc.decision.phase,
                        reason=exc.decision.reason,
                        risk_score=exc.decision.risk_score,
                        risk_signals=exc.decision.risk_signals,
                    )
                    _, blocked = blocked_response(exc.decision)
                    yield f"data: {json.dumps(blocked)}\n\n"
                    yield "data: [DONE]\n\n"

            resp = StreamingHttpResponse(_gen(), content_type="text/event-stream")
            resp["Cache-Control"] = "no-cache"
            resp["X-Accel-Buffering"] = "no"
            return resp

        status, payload = result
        return JsonResponse(payload, status=status, safe=False)


@method_decorator([csrf_exempt, require_api_auth], name="dispatch")
class GatewayProvidersView(View):
    """List supported gateway providers and capabilities."""

    def get(self, request):
        from eeg.gateway.providers.vendor_router import list_supported_providers, total_provider_count

        capability = request.GET.get("capability")
        return JsonResponse(
            {
                "count": total_provider_count(),
                "providers": list_supported_providers(capability=capability),
                "capabilities": [
                    "chat",
                    "embed",
                    "image",
                    "speech",
                    "transcription",
                    "batch",
                    "files",
                    "realtime",
                    "mcp_toolsets",
                ],
            }
        )


class _CapabilityProxyView(View):
    capability = "embed"

    @method_decorator(csrf_exempt)
    @method_decorator(require_api_auth)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        org = request.organization
        enforcement, runtime = _org_runtime_flags(org)
        if not runtime and not enforcement:
            return JsonResponse(
                {
                    "error": "Runtime protection is disabled for this organization.",
                    "code": "runtime_protection_disabled",
                },
                status=403,
            )

        body, err = _parse_json_body(request)
        if err:
            return err

        agent_block = _maybe_block_agent(org, request, body)
        if agent_block is not None:
            return agent_block

        stream = bool(body.get("stream"))
        try:
            kind, result = _dispatch_with_plan(
                org=org,
                body=body,
                request=request,
                capability=self.capability,
                stream=stream,
            )
        except GatewayBlockedError as exc:
            record_gateway_block(
                organization=org,
                request=request,
                phase=exc.decision.phase,
                reason=exc.decision.reason,
                risk_score=exc.decision.risk_score,
                risk_signals=exc.decision.risk_signals,
            )
            code, blocked = blocked_response(exc.decision)
            return JsonResponse(blocked, status=code)
        except ValueError as exc:
            return JsonResponse({"error": str(exc), "code": "invalid_request"}, status=400)

        if kind in ("stream_url", "stream_plan"):
            resp = StreamingHttpResponse(result, content_type="text/event-stream")
            resp["Cache-Control"] = "no-cache"
            return resp
        status, payload = result
        return JsonResponse(payload, status=status, safe=False)


class GatewayEmbeddingsView(_CapabilityProxyView):
    capability = "embed"


class GatewayImagesView(_CapabilityProxyView):
    capability = "image"


class GatewaySpeechView(_CapabilityProxyView):
    capability = "speech"


class GatewayTranscriptionsView(_CapabilityProxyView):
    capability = "transcription"
