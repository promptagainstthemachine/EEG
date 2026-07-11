"""Map ``apps.api.urls`` patterns to OpenAPI path keys.

Operation bodies come only from ``openapi_schema.API_V1_ROUTE_OPERATIONS`` (keyed by
Django route ``name=``). Undocumented named routes are omitted from the schema rather
than auto-generated.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from django.urls import URLPattern


def django_url_pattern_to_openapi_path(p: URLPattern) -> str:
    """Map a resolved URLPattern to an OpenAPI path (``/a/{id}/``)."""
    regex = p.pattern.regex.pattern
    core = regex
    if core.startswith("^"):
        core = core[1:]
    if core.endswith("\\Z"):
        core = core[:-2]
    elif core.endswith("$"):
        core = core[:-1]
    core = re.sub(r"\(\?P<(\w+)>[^)]+\)", r"{\1}", core)
    path = core.strip("/")
    # Django's URL resolver may escape hyphens in the regex source (e.g. threat\-intel).
    path = path.replace("\\-", "-")
    if not path:
        return "/"
    return "/" + path + "/"


def build_paths_from_api_urlconf(
    route_operations: Dict[str, Dict[str, Any]],
    *,
    method_factory: Any,
    responses_factory: Any,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Walk ``apps.api.urls.urlpatterns`` and assemble ``path -> operations``.

    ``route_operations`` maps Django route *name* (e.g. ``health``) to an OpenAPI path item.
    ``method_factory`` and ``responses_factory`` are kept for a stable call signature;
    they are not used when routes are skipped.
    """
    del method_factory, responses_factory

    from apps.api import urls as api_urls

    paths: Dict[str, Any] = {}
    warnings: List[str] = []

    for p in api_urls.urlpatterns:
        if not isinstance(p, URLPattern):
            continue
        name = p.name
        if not name:
            warnings.append(
                f"OpenAPI: URL pattern without name= skipped ({p.pattern}). "
                "Named routes are required."
            )
            continue
        openapi_path = django_url_pattern_to_openapi_path(p)
        if openapi_path in paths:
            warnings.append(f"OpenAPI: duplicate path {openapi_path} — check urls.py")
            continue

        if name in route_operations:
            paths[openapi_path] = route_operations[name]
            continue

        warnings.append(
            f"OpenAPI: route name={name!r} path={openapi_path!r} has no "
            f"API_V1_ROUTE_OPERATIONS[{name!r}] entry — skipped."
        )

    return paths, warnings
