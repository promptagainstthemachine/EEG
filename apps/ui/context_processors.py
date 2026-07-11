"""EEG OSS UI context processors."""
from django.conf import settings


def eeg_context(request):
    """Add EEG-specific context to all templates."""
    org = getattr(request, "organization", None)
    
    return {
        "eeg_organization": org,
        "eeg_max_projects": getattr(settings, "EEG_MAX_PROJECTS_PER_ORG", 0),
        "eeg_has_organization": org is not None,
    }
