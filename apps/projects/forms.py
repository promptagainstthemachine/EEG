"""EEG OSS project forms."""
from django import forms
from django.conf import settings

from apps.projects.path_utils import is_file_url, resolve_local_source_path

from .models import Project
from .utils import unique_project_slug


class ProjectForm(forms.ModelForm):
    """Form for creating and editing projects."""

    class Meta:
        model = Project
        fields = (
            "name",
            "description",
            "project_type",
            "repository_url",
            "cloud_resource_id",
            "api_endpoint",
            "local_path",
            "auto_scan_enabled",
            "scan_schedule",
        )
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
            "auto_scan_enabled": forms.CheckboxInput(attrs={"class": "toggle-switch"}),
        }

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)

        # Manual create: static types by default. Gateway may be posted from
        # the "Runtime security" mode on the create form.
        if not self.is_bound:
            self.fields["project_type"].choices = [
                c for c in Project.ProjectType.choices if c[0] != Project.ProjectType.GATEWAY
            ]
        else:
            self.fields["project_type"].choices = list(Project.ProjectType.choices)

        for field in self.fields.values():
            if not isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs["class"] = "eeg-input"

    def clean(self):
        cleaned_data = super().clean()

        if self.instance.pk is None and self.organization and not self.organization.can_add_project():
            max_projects = int(getattr(settings, "EEG_MAX_PROJECTS_PER_ORG", 0) or 0)
            raise forms.ValidationError(
                f"Maximum of {max_projects} projects per organization reached. "
                "Please remove a project before adding a new one."
            )

        project_type = cleaned_data.get("project_type")
        repository_url = (cleaned_data.get("repository_url") or "").strip()
        local_path = (cleaned_data.get("local_path") or "").strip()

        if project_type == Project.ProjectType.GATEWAY:
            cleaned_data["auto_scan_enabled"] = False
            cleaned_data["repository_url"] = ""
            cleaned_data["local_path"] = ""
            cleaned_data["api_endpoint"] = ""
            cleaned_data["cloud_resource_id"] = ""
            return cleaned_data

        if repository_url and is_file_url(repository_url):
            if local_path and local_path != repository_url:
                raise forms.ValidationError(
                    "Use either a file:// path in Local Path or Repository URL, not both."
                )
            cleaned_data["local_path"] = repository_url
            cleaned_data["repository_url"] = ""
            local_path = cleaned_data["local_path"]
            repository_url = ""

        resolved = resolve_local_source_path(
            local_path=local_path,
            repository_url=repository_url,
        )
        if local_path or (repository_url and is_file_url(repository_url)):
            if resolved is None:
                raise forms.ValidationError(
                    "Local path is invalid, missing, or outside the allowed scan roots. "
                    "Use a path under the app directory "
                    "(e.g. fixtures/vulnerable-apps/ai-goat), or set "
                    "EEG_ALLOWED_SCAN_ROOTS for extra roots. Absolute paths like "
                    "/etc or /Users are not allowed."
                )
            cleaned_data["local_path"] = str(resolved)

        if project_type == Project.ProjectType.REPOSITORY:
            if not cleaned_data.get("repository_url") and not cleaned_data.get("local_path"):
                raise forms.ValidationError(
                    "Repository projects require either a repository URL or local path."
                )
        elif project_type in [Project.ProjectType.AWS, Project.ProjectType.GCP, Project.ProjectType.AZURE]:
            if not cleaned_data.get("cloud_resource_id"):
                raise forms.ValidationError(
                    "Cloud projects require a cloud resource identifier."
                )
        elif project_type == Project.ProjectType.API_ENDPOINT:
            if not cleaned_data.get("api_endpoint"):
                raise forms.ValidationError(
                    "API endpoint projects require an API endpoint URL."
                )
        
        return cleaned_data

    def save(self, commit=True):
        project = super().save(commit=False)
        
        if self.organization:
            project.organization = self.organization
        
        if not project.slug and project.organization_id:
            project.slug = unique_project_slug(
                project.organization,
                project.name,
                project.slug,
            )
        
        if commit:
            project.save()
        return project
