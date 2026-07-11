"""URLconf for branded error page tests."""

from django.http import Http404, JsonResponse
from django.urls import path


def raise_server_error(request):
    raise RuntimeError("intentional test failure")


def raise_not_found(request):
    raise Http404()


def json_not_found(request):
    return JsonResponse({"error": "not found"}, status=404)


urlpatterns = [
    path("test-500/", raise_server_error),
    path("test-404/", raise_not_found),
    path("test-api-404/", json_not_found),
    path("api/v1/test-not-found/", json_not_found),
]
