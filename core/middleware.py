"""Project-level middleware."""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse, StreamingHttpResponse
from django.shortcuts import render

logger = logging.getLogger(__name__)

_BRANDED_STATUS_TEMPLATES = {
    403: "403.html",
    404: "404.html",
    500: "500.html",
}


def should_use_branded_client_errors(request) -> bool:
    """True for browser / HTMX HTML routes (not API or admin)."""
    if not getattr(settings, "EEG_BRANDED_CLIENT_ERRORS", True):
        return False
    path = request.path
    if path.startswith("/api/") or path.startswith("/admin/"):
        return False
    if request.headers.get("HX-Request"):
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "text/html" in accept or "*/*" in accept or not accept:
        return True
    if "application/json" in accept and "text/html" not in accept:
        return False
    return True


def render_branded_error(request, template: str, status: int, **context):
    return render(request, template, context, status=status)


class BrandedClientErrorMiddleware:
    """
    Always serve templates/404.html, /403.html, and /500.html on UI routes.

    Wraps the full middleware stack so uncaught exceptions (including when
    DEBUG=True) never surface Django's technical error pages to browsers.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not should_use_branded_client_errors(request):
            return self.get_response(request)

        try:
            response = self.get_response(request)
        except Http404:
            return render_branded_error(request, "404.html", 404)
        except PermissionDenied as exc:
            ctx = {}
            if exc.args:
                ctx["denial_message"] = str(exc.args[0])
            return render_branded_error(request, "403.html", 403, **ctx)
        except Exception:
            logger.exception("Unhandled error on %s", request.path)
            return render_branded_error(request, "500.html", 500)

        return self._brand_response(request, response)

    def _brand_response(self, request, response: HttpResponse):
        if isinstance(response, StreamingHttpResponse):
            return response

        template = _BRANDED_STATUS_TEMPLATES.get(response.status_code)
        if not template:
            return response

        return render_branded_error(request, template, response.status_code)
