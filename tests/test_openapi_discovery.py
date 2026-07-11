"""OpenAPI path list stays aligned with apps.api.urls."""

from django.test import SimpleTestCase


class ApiOpenapiPathSyncTests(SimpleTestCase):
    def test_each_named_api_url_has_openapi_path(self):
        from apps.api import openapi_discovery
        from apps.api import urls as api_urls
        from apps.api.openapi_schema import build_openapi_paths

        named = [p for p in api_urls.urlpatterns if getattr(p, "name", None)]
        openapi_paths = build_openapi_paths()

        self.assertEqual(
            len(named),
            len(openapi_paths),
        )

        for p in named:
            key = openapi_discovery.django_url_pattern_to_openapi_path(p)
            self.assertIn(key, openapi_paths, msg=f"url name={p.name!r} path={key!r}")
