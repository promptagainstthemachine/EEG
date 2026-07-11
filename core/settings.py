"""
Django settings for EEG OSS — Open Source AI Security Platform.

Simplified single-tenant deployment for self-hosted AI security.
1 user = 1 organization; projects are unlimited by default (EEG_MAX_PROJECTS_PER_ORG=0).
"""

from __future__ import annotations

import os
from pathlib import Path


def _is_source_checkout(root: Path) -> bool:
    return (root / "manage.py").is_file() and (root / "pyproject.toml").is_file()


def _package_root() -> Path:
    """Directory that contains ``core/`` (repo root in checkout, site-packages when installed)."""
    return Path(__file__).resolve().parent.parent


def _data_root() -> Path:
    """Writable runtime data (DB, repos, collected static)."""
    env = os.environ.get("EEG_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    pkg = _package_root()
    if _is_source_checkout(pkg):
        return pkg
    return Path.home() / ".eeg"


def _webdata_root() -> Path:
    """Shipped templates/static (``eeg.webdata`` package)."""
    try:
        from eeg.webdata import PACKAGE_DIR

        return PACKAGE_DIR
    except Exception:
        # Source checkout fallback before/during partial installs
        candidate = _package_root() / "eeg" / "webdata"
        if candidate.is_dir():
            return candidate
        return _package_root()


BASE_DIR = _data_root()
WEBDATA_DIR = _webdata_root()
BASE_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "dev-only-change-me-in-production-use-long-random-string",
)

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() in ("1", "true", "yes")

# Replace browser HTML 403/404/500 (including Django debug pages when DEBUG=True)
# with eeg/webdata/templates/403.html, 404.html, and 500.html. Skips /api/ and /admin/.
# Set EEG_BRANDED_CLIENT_ERRORS=false to restore Django technical error pages in dev.
_branded = os.environ.get("EEG_BRANDED_CLIENT_ERRORS", "").strip().lower()
if _branded in ("1", "true", "yes"):
    EEG_BRANDED_CLIENT_ERRORS = True
elif _branded in ("0", "false", "no"):
    EEG_BRANDED_CLIENT_ERRORS = False
else:
    EEG_BRANDED_CLIENT_ERRORS = True

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h.strip()
]
# Django test Client (UI → API internal calls)
if "testserver" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append("testserver")

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "channels",
    "django_htmx",
    "django_celery_beat",
    # EEG OSS apps
    "apps.accounts.apps.AccountsConfig",
    "apps.projects",
    "apps.security.apps.SecurityConfig",
    "apps.api",
    "apps.ui",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Outermost wrapper (after SecurityMiddleware): branded HTML errors even when DEBUG=True.
    "core.middleware.BrandedClientErrorMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.accounts.middleware.OrganizationContextMiddleware",
    "apps.api.middleware.ApiKeyAuthMiddleware",
]

ROOT_URLCONF = "core.urls"

# HTML page for CSRF verification failures (default is Django's plain 403).
CSRF_FAILURE_VIEW = "core.views_errors.csrf_failure"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [WEBDATA_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.ui.context_processors.eeg_context",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"
ASGI_APPLICATION = "core.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
        "OPTIONS": {
            "timeout": 30,
        },
    }
}

_pg_url = os.environ.get("EEG_DATABASE_URL", "")
if _pg_url:
    try:
        from urllib.parse import urlparse

        u = urlparse(_pg_url)
        DATABASES["default"] = {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": (u.path or "").lstrip("/"),
            "USER": u.username or "",
            "PASSWORD": u.password or "",
            "HOST": u.hostname or "",
            "PORT": str(u.port or 5432),
            "CONN_MAX_AGE": 600,
        }
    except Exception:
        pass

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTH_USER_MODEL = "accounts.User"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
_static_dir = WEBDATA_DIR / "static"
STATICFILES_DIRS = [_static_dir] if _static_dir.exists() else []
# Avoid Manifest storage: hashed URLs 404 unless collectstatic+manifest stay in sync
# (dashboard-charts.js / threat-graph-3d.js were blank on the dashboard because of this).
if DEBUG:
    STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"
    WHITENOISE_USE_FINDERS = True
    WHITENOISE_AUTOREFRESH = True
else:
    STATICFILES_STORAGE = "whitenoise.storage.CompressedStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "ui:dashboard"
LOGOUT_REDIRECT_URL = "accounts:login"

# --- EEG OSS Configuration ---
EEG_FERNET_KEY = os.environ.get("EEG_FERNET_KEY", "")
EEG_NOVA_RULES_PATH = os.environ.get("EEG_NOVA_RULES_PATH", "")

# OSS Limits
EEG_MAX_PROJECTS_PER_ORG = int(os.environ.get("EEG_MAX_PROJECTS_PER_ORG", "0"))  # 0 = unlimited
EEG_GATEWAY_CONNECTED_WINDOW_SECONDS = int(
    os.environ.get("EEG_GATEWAY_CONNECTED_WINDOW_SECONDS", "900")
)  # 15 minutes

# Persistent clone storage: data/repos/org/{org_slug}/{project_slug}/
EEG_REPO_STORAGE_ROOT = Path(
    os.environ.get("EEG_REPO_STORAGE_ROOT", str(BASE_DIR / "data" / "repos"))
)
# Extra roots for local_path / scan file reads (os.pathsep or comma-separated).
# Absolute paths outside BASE_DIR + EEG_REPO_STORAGE_ROOT are rejected otherwise.
EEG_ALLOWED_SCAN_ROOTS = os.environ.get("EEG_ALLOWED_SCAN_ROOTS", "")

# --- Celery & Redis configuration ---
REDIS_URL = os.environ.get("EEG_REDIS_URL", "redis://localhost:6379/0")

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "").lower() in (
    "1",
    "true",
    "yes",
)


def _build_cache_config(redis_url: str) -> dict:
    try:
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(redis_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        sock = socket.create_connection((host, port), timeout=1)
        sock.close()
        return {
            "default": {
                "BACKEND": "django.core.cache.backends.redis.RedisCache",
                "LOCATION": redis_url,
                "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
                "KEY_PREFIX": "eeg_oss",
                "TIMEOUT": 300,
            }
        }
    except Exception:
        return {
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "KEY_PREFIX": "eeg_oss",
                "TIMEOUT": 300,
            }
        }


CACHES = _build_cache_config(REDIS_URL)


def _build_channel_layer_config(redis_url: str) -> dict:
    try:
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(redis_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        sock = socket.create_connection((host, port), timeout=1)
        sock.close()
        return {
            "default": {
                "BACKEND": "channels_redis.core.RedisChannelLayer",
                "CONFIG": {"hosts": [redis_url], "capacity": 1500, "expiry": 60},
            }
        }
    except Exception:
        return {
            "default": {
                "BACKEND": "channels.layers.InMemoryChannelLayer",
            }
        }


CHANNEL_LAYERS = _build_channel_layer_config(REDIS_URL)

# --- EEG Telemetry configuration ---
EEG_TELEMETRY_RETENTION_DAYS = int(os.environ.get("EEG_TELEMETRY_RETENTION_DAYS", "30"))
EEG_MAX_FINDINGS_PER_SCAN = int(os.environ.get("EEG_MAX_FINDINGS_PER_SCAN", "1000"))
EEG_REALTIME_BUFFER_SIZE = int(os.environ.get("EEG_REALTIME_BUFFER_SIZE", "100"))
