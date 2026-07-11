"""EEG OSS account forms."""
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.utils.text import slugify

from .models import ApiKey, Organization

User = get_user_model()


class SignUpForm(UserCreationForm):
    """User registration form with organization creation."""

    email = forms.EmailField(required=True)
    organization_name = forms.CharField(
        max_length=255,
        label="Organization Name",
        help_text="Name for your organization (e.g., your company or project name)",
    )

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_organization_name(self):
        name = self.cleaned_data["organization_name"]
        slug = slugify(name)
        if Organization.objects.filter(slug=slug).exists():
            raise forms.ValidationError(
                "An organization with this name already exists. Please choose a different name."
            )
        return name

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        
        org_name = self.cleaned_data["organization_name"]
        org = Organization.objects.create(
            name=org_name,
            slug=slugify(org_name),
        )
        user.organization = org
        
        if commit:
            user.save()
        return user


class ProfileForm(forms.ModelForm):
    """User profile update form."""

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name")


class OrganizationSettingsForm(forms.ModelForm):
    """Organization settings form (user acts as admin in OSS)."""

    class Meta:
        model = Organization
        fields = (
            "name",
            "auto_redteam_enabled",
            "model_scanning_enabled",
            "realtime_telemetry_enabled",
            "realtime_monitoring_enabled",
            "policy_enforcement_enabled",
            "runtime_protection_enabled",
        )
        widgets = {
            "auto_redteam_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
            "model_scanning_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
            "realtime_telemetry_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
            "realtime_monitoring_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
            "policy_enforcement_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
            "runtime_protection_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
        }


class ApiKeyCreateForm(forms.Form):
    """Form to create a new API key."""

    label = forms.CharField(
        max_length=120,
        label="Key Label",
        help_text="A descriptive name for this API key (e.g., 'CI/CD Pipeline', 'Development')",
    )


class EEGPasswordChangeForm(PasswordChangeForm):
    """Custom password change form with styling."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs["class"] = "eeg-input"
