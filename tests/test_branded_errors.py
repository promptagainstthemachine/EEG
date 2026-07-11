"""Branded HTML error pages replace Django debug pages on UI routes."""

from django.test import Client, TestCase, override_settings


@override_settings(
    ROOT_URLCONF="tests.urls_errors",
    DEBUG=True,
    EEG_BRANDED_CLIENT_ERRORS=True,
)
class BrandedClientErrorTests(TestCase):
    def setUp(self):
        self.client = Client(raise_request_exception=False)

    def test_404_page_is_branded_not_django_debug(self):
        response = self.client.get(
            "/test-404/",
            HTTP_ACCEPT="text/html,application/xhtml+xml",
        )
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "404", status_code=404)
        self.assertContains(response, "Page Not Found", status_code=404)
        self.assertNotIn(b"urlpatterns", response.content)

    def test_500_page_is_branded_when_debug_true(self):
        response = self.client.get(
            "/test-500/",
            HTTP_ACCEPT="text/html,application/xhtml+xml",
        )
        self.assertEqual(response.status_code, 500)
        self.assertContains(response, "500", status_code=500)
        self.assertContains(response, "Server Error", status_code=500)
        self.assertNotIn(b"Traceback", response.content)
        self.assertNotIn(b"technical_500", response.content)

    def test_unknown_url_uses_branded_404(self):
        response = self.client.get(
            "/does-not-exist-xyz/",
            HTTP_ACCEPT="text/html",
        )
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "Page Not Found", status_code=404)
        self.assertNotIn(b"urlpatterns", response.content)

    def test_api_json_404_not_replaced_with_html(self):
        response = self.client.get(
            "/api/v1/test-not-found/",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn(b'"error"', response.content)

    @override_settings(EEG_BRANDED_CLIENT_ERRORS=False)
    def test_branding_can_be_disabled(self):
        response = Client(raise_request_exception=False).get(
            "/test-404/",
            HTTP_ACCEPT="text/html",
        )
        self.assertEqual(response.status_code, 404)
        # Django debug 404 when DEBUG=True and branding off
        self.assertIn(b"Page not found", response.content)
