"""EEG OSS account URLs."""
from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.EEGLoginView.as_view(), name="login"),
    path("logout/", views.EEGLogoutView.as_view(), name="logout"),
    path("signup/", views.signup, name="signup"),
    
    # Profile management
    path("profile/", views.profile, name="profile"),
    path("password/change/", views.password_change, name="password_change"),
    path("account/delete/", views.delete_account, name="delete_account"),
    path("profile/update/", views.profile_update, name="profile_update"),
    path("profile/logs/download/", views.activity_logs_download, name="activity_logs_download"),
    path("profile/logs/clear/", views.activity_logs_clear, name="activity_logs_clear"),
    
    # Organization management
    path("organization/", views.organization_settings, name="organization_settings"),
    path("organization/create/", views.create_organization, name="create_organization"),
    path("organization/security/", views.security_controls, name="security_controls"),
    
    path("api-keys/", views.api_keys, name="api_keys"),
    path("api-docs/", views.api_docs, name="api_docs"),
    # API key management
    path("api-keys/create/", views.create_api_key, name="create_api_key"),
    path("api-keys/<int:key_id>/revoke/", views.revoke_api_key, name="revoke_api_key"),
]
