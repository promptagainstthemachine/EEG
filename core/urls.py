"""EEG OSS URL Configuration."""
from django.contrib import admin
from django.urls import include, path

from core import views_errors

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("apps.api.urls", namespace="api")),
    path("accounts/", include("apps.accounts.urls", namespace="accounts")),
    path("", include("apps.ui.urls", namespace="ui")),
]

handler404 = views_errors.page_not_found
handler403 = views_errors.permission_denied
handler500 = views_errors.server_error

admin.site.site_header = "EEG OSS Admin"
admin.site.site_title = "EEG OSS"
admin.site.index_title = "AI Security Platform Administration"
