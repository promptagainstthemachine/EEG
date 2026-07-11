"""EEG OSS API middleware — API key authentication only (no session cookies on /api/)."""

from __future__ import annotations

from apps.accounts.models import ApiKey


class ApiKeyAuthMiddleware:
    """
    Authenticate /api/v1/ requests with API keys only.

    Accepted credentials (industry-standard machine-to-machine):
    - Authorization: Bearer <api_key>
    - X-EEG-API-Key: <api_key>

    Session cookies from the web UI are intentionally NOT accepted on API routes.
    """

    API_PATHS = ("/api/",)
    PUBLIC_SUFFIXES = ("/schema", "/health")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not any(request.path.startswith(prefix) for prefix in self.API_PATHS):
            return self.get_response(request)

        path = request.path.rstrip("/")
        if any(path.endswith(suffix) for suffix in self.PUBLIC_SUFFIXES):
            return self.get_response(request)

        request.api_authenticated = False
        request.api_key = None

        raw_key = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_key = auth_header[7:].strip()

        if not raw_key:
            raw_key = request.headers.get("X-EEG-API-Key", "").strip()

        if raw_key:
            api_key = ApiKey.resolve(raw_key)
            if api_key and api_key.is_active:
                api_key.touch_used()
                request.api_key = api_key
                request.organization = api_key.organization
                request.api_authenticated = True

        if getattr(request, "api_authenticated", False):
            from apps.api.rate_limit import check_api_rate_limit

            limited = check_api_rate_limit(request)
            if limited is not None:
                return limited

        return self.get_response(request)
