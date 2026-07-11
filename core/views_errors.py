"""Branded HTTP error pages (404 / 403 / CSRF)."""

from __future__ import annotations

from django.shortcuts import render


def page_not_found(request, exception):
    return render(request, "404.html", status=404)


def server_error(request):
    return render(request, "500.html", status=500)


def permission_denied(request, exception):
    ctx = {}
    if exception and getattr(exception, "args", None) and exception.args:
        ctx["denial_message"] = str(exception.args[0])
    return render(request, "403.html", ctx, status=403)


def csrf_failure(request, reason=""):
    return render(
        request,
        "403.html",
        {
            "csrf_failure": True,
            "csrf_failure_reason": reason or "",
        },
        status=403,
    )
