"""EEG OSS account views - Profile, organization settings, API keys."""
from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpRequest, HttpResponse
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.text import slugify
from django.views.decorators.http import require_POST

from .forms import (
    ApiKeyCreateForm,
    EEGPasswordChangeForm,
    OrganizationSettingsForm,
    ProfileForm,
    SignUpForm,
)
from .activity_log import record_user_activity
from .models import ApiKey, Organization, UserActivityLog


def _api_keys_active_qs(org: Organization):
    return ApiKey.objects.filter(organization=org, is_active=True).order_by("-created_at")


def _profile_api_tab_url() -> str:
    return reverse("accounts:profile") + "?tab=api"


def _render_api_keys_root(request: HttpRequest, **extra) -> HttpResponse:
    org = request.organization
    ctx = {
        "api_keys": list(_api_keys_active_qs(org)) if org else [],
        "raw_api_key": None,
        "form_error": "",
        "revoke_error": "",
    }
    ctx.update(extra)
    return render(request, "accounts/partials/api_keys_root.html", ctx)


class EEGLoginView(LoginView):
    """EEG OSS login view."""

    template_name = "accounts/login.html"


class EEGLogoutView(LogoutView):
    """EEG OSS logout view."""

    next_page = "accounts:login"


def signup(request: HttpRequest) -> HttpResponse:
    """User registration with organization creation."""
    if request.user.is_authenticated:
        return redirect("ui:dashboard")

    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            org = user.organization
            from .activity_log import record_user_activity

            record_user_activity(
                user=user,
                organization=org,
                event_type=UserActivityLog.EventType.USER_REGISTERED,
                metadata={
                    "organization_id": org.pk,
                    "organization_name": org.name,
                    "organization_slug": org.slug,
                },
                request=request,
            )
            record_user_activity(
                user=user,
                organization=org,
                event_type=UserActivityLog.EventType.ORGANIZATION_CREATED,
                metadata={
                    "organization_id": org.pk,
                    "organization_name": org.name,
                    "organization_slug": org.slug,
                    "source": "signup",
                },
                request=request,
            )
            login(request, user)
            messages.success(
                request,
                f"Welcome to EEG! Your organization '{user.organization.name}' has been created.",
            )
            return redirect("ui:dashboard")
    else:
        form = SignUpForm()

    return render(request, "accounts/signup.html", {"form": form})


@login_required
def profile(request: HttpRequest) -> HttpResponse:
    """User profile page with all settings tabs."""
    org = request.organization
    raw_api_key = request.session.pop("new_api_key", None)
    ctx = {
        "api_keys": list(_api_keys_active_qs(org)) if org else [],
        "raw_api_key": raw_api_key,
        "initial_tab": (request.GET.get("tab") or "profile").strip(),
        "activity_logs": list(
            UserActivityLog.objects.filter(user=request.user).select_related("organization")[:200]
        ),
    }
    return render(request, "accounts/profile.html", ctx)


@login_required
def profile_update(request: HttpRequest) -> HttpResponse:
    """Update user profile information."""
    if request.method == "POST":
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile updated successfully.")
            return redirect("accounts:profile")
    else:
        form = ProfileForm(instance=request.user)

    return render(request, "accounts/profile_update.html", {"form": form})


@login_required
def password_change(request: HttpRequest) -> HttpResponse:
    """Change user password."""
    if request.method == "POST":
        form = EEGPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Password changed successfully.")
            return redirect("accounts:profile")
    else:
        form = EEGPasswordChangeForm(request.user)

    return render(request, "accounts/password_change.html", {"form": form})


@login_required
def delete_account(request: HttpRequest) -> HttpResponse:
    """Permanently delete the signed-in user, their organization, and related data."""
    if request.method == "POST":
        password = request.POST.get("password", "")
        if not request.user.check_password(password):
            messages.error(request, "Incorrect password. Account was not deleted.")
            return render(request, "accounts/delete_account.html")
        user = request.user
        with transaction.atomic():
            org = user.organization
            if org:
                org.delete()
            user.delete()
        logout(request)
        return redirect(f"{reverse('accounts:login')}?account_deleted=1")

    return render(request, "accounts/delete_account.html")


@login_required
def organization_settings(request: HttpRequest) -> HttpResponse:
    """Organization settings management."""
    org = request.organization
    
    if not org:
        messages.error(request, "You need to create an organization first.")
        return redirect("accounts:create_organization")

    if request.method == "POST":
        form = OrganizationSettingsForm(request.POST, instance=org)
        if form.is_valid():
            form.save()
            messages.success(request, "Organization settings updated.")
            return redirect("accounts:profile")
    else:
        form = OrganizationSettingsForm(instance=org)

    return render(
        request,
        "accounts/organization_settings.html",
        {"form": form, "organization": org},
    )


@login_required
def create_organization(request: HttpRequest) -> HttpResponse:
    """Create organization for user (only if they don't have one)."""
    if request.organization:
        messages.info(request, "You already have an organization.")
        return redirect("accounts:profile")

    if request.method == "POST":
        org_name = request.POST.get("organization_name", "").strip()
        if not org_name:
            messages.error(request, "Organization name is required.")
        else:
            slug = slugify(org_name)
            if Organization.objects.filter(slug=slug).exists():
                messages.error(
                    request,
                    "An organization with this name already exists. Please choose a different name.",
                )
            else:
                org = Organization.objects.create(name=org_name, slug=slug)
                request.user.organization = org
                request.user.save(update_fields=["organization"])
                from .activity_log import record_user_activity

                record_user_activity(
                    user=request.user,
                    organization=org,
                    event_type=UserActivityLog.EventType.ORGANIZATION_CREATED,
                    metadata={
                        "organization_id": org.pk,
                        "organization_name": org.name,
                        "organization_slug": org.slug,
                        "source": "create_organization_view",
                    },
                    request=request,
                )
                messages.success(request, f"Organization '{org_name}' created successfully.")
                return redirect("ui:dashboard")

    return render(request, "accounts/create_organization.html")


@login_required
def api_keys(request: HttpRequest) -> HttpResponse:
    """Legacy URL — API keys are managed in Profile."""
    return redirect(_profile_api_tab_url())


@login_required
def api_docs(request: HttpRequest) -> HttpResponse:
    """Swagger UI for the live REST API."""
    from apps.api.openapi_schema import build_openapi_schema

    return render(
        request,
        "accounts/api_documentation.html",
        {"openapi_spec": build_openapi_schema(request=request)},
    )


@login_required
@require_POST
def create_api_key(request: HttpRequest) -> HttpResponse:
    """Create a new API key."""
    org = request.organization
    is_htmx = bool(request.headers.get("HX-Request"))

    if not org:
        if is_htmx:
            return _render_api_keys_root(
                request,
                form_error="You need an organization to create API keys.",
            )
        messages.error(request, "You need an organization to create API keys.")
        return redirect(_profile_api_tab_url())

    form = ApiKeyCreateForm(request.POST)
    if form.is_valid():
        label = form.cleaned_data["label"]
        api_key_obj, raw_key = ApiKey.create_key(org, label)
        record_user_activity(
            user=request.user,
            organization=org,
            event_type=UserActivityLog.EventType.API_KEY_CREATED,
            metadata={
                "label": label,
                "api_key_id": api_key_obj.pk,
                "prefix": api_key_obj.prefix,
            },
            request=request,
        )
        if is_htmx:
            return _render_api_keys_root(
                request,
                raw_api_key=raw_key,
            )
        request.session["new_api_key"] = raw_key
        messages.success(
            request,
            "API key created. Copy it now — it won't be shown again.",
        )
        return redirect(_profile_api_tab_url())

    err = " ".join(
        f"{field}: {', '.join(e)}" for field, errs in form.errors.items() for e in errs
    ) or "Invalid form data."
    if is_htmx:
        return _render_api_keys_root(request, form_error=err)
    messages.error(request, err)
    return redirect(_profile_api_tab_url())


@login_required
@require_POST
def revoke_api_key(request: HttpRequest, key_id: int) -> HttpResponse:
    """Revoke an API key."""
    org = request.organization
    is_htmx = bool(request.headers.get("HX-Request"))

    if not org:
        if is_htmx:
            return _render_api_keys_root(
                request,
                revoke_error="Organization not found.",
            )
        messages.error(request, "Organization not found.")
        return redirect(_profile_api_tab_url())

    try:
        api_key = ApiKey.objects.get(pk=key_id, organization=org)
        label = api_key.label
        revoked_id = api_key.pk
        revoked_prefix = api_key.prefix
        api_key.revoke()
        record_user_activity(
            user=request.user,
            organization=org,
            event_type=UserActivityLog.EventType.API_KEY_REVOKED,
            metadata={
                "label": label,
                "api_key_id": revoked_id,
                "prefix": revoked_prefix,
            },
            request=request,
        )
        if not is_htmx:
            messages.success(request, f"API key '{label}' has been revoked.")
    except ApiKey.DoesNotExist:
        if is_htmx:
            return _render_api_keys_root(
                request,
                revoke_error="API key not found or already revoked.",
            )
        messages.error(request, "API key not found.")
        return redirect(_profile_api_tab_url())
    else:
        if is_htmx:
            return _render_api_keys_root(request)

    return redirect(_profile_api_tab_url())


@login_required
def security_controls(request: HttpRequest) -> HttpResponse:
    """Quick security controls toggle (HTMX partial)."""
    org = request.organization
    
    if not org:
        return HttpResponse("<p class='muted'>No organization configured.</p>")

    if request.method == "POST":
        field = request.POST.get("field")
        value = request.POST.get("value") == "true"
        
        valid_fields = [
            "auto_redteam_enabled",
            "model_scanning_enabled",
            "realtime_telemetry_enabled",
            "realtime_monitoring_enabled",
            "policy_enforcement_enabled",
            "runtime_protection_enabled",
        ]
        
        if field in valid_fields:
            setattr(org, field, value)
            org.save(update_fields=[field])
            messages.success(request, "Security setting updated.")

    return render(request, "accounts/partials/security_controls.html", {"organization": org})


@login_required
def activity_logs_download(request: HttpRequest) -> HttpResponse:
    """Download all activity log rows for the current user as JSON."""
    import json

    logs = UserActivityLog.objects.filter(user=request.user).order_by("-created_at")
    data = []
    for log in logs:
        data.append(
            {
                "id": log.id,
                "event_type": log.event_type,
                "event_label": log.get_event_type_display(),
                "actor_username": log.actor_username,
                "organization_id": log.organization_id,
                "metadata": log.metadata,
                "ip_address": str(log.ip_address) if log.ip_address else None,
                "created_at": log.created_at.isoformat(),
            }
        )
    response = HttpResponse(
        json.dumps(data, indent=2),
        content_type="application/json; charset=utf-8",
    )
    response["Content-Disposition"] = 'attachment; filename="eeg-activity-log.json"'
    return response


@login_required
@require_POST
def activity_logs_clear(request: HttpRequest) -> HttpResponse:
    """Delete all activity logs for the current user."""
    deleted, _ = UserActivityLog.objects.filter(user=request.user).delete()
    messages.success(
        request,
        f"Cleared {deleted} log entr{'y' if deleted == 1 else 'ies'}.",
    )
    return redirect(reverse("accounts:profile") + "?tab=logs")
