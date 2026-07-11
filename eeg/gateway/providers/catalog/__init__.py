"""EEG gateway provider catalog."""
from eeg.gateway.providers.catalog.definitions import PROVIDER_DEFINITIONS
from eeg.gateway.providers.catalog.plan_builder import compose_catalog_plan
from eeg.gateway.providers.catalog.registry import get_provider, list_providers, provider_count, resolve_provider_id

__all__ = [
    "PROVIDER_DEFINITIONS",
    "compose_catalog_plan",
    "get_provider",
    "list_providers",
    "provider_count",
    "resolve_provider_id",
]
