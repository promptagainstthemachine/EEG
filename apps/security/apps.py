from __future__ import annotations

import sys

from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.security"
    verbose_name = "Security"

    def ready(self) -> None:
        if self._should_skip_startup_reconcile():
            return
        from apps.security.scan_reconcile import reconcile_orphaned_scan_runs

        try:
            reconcile_orphaned_scan_runs()
        except Exception:
            import logging

            logging.getLogger(__name__).exception(
                "Failed to reconcile orphaned scan runs on startup"
            )

    @staticmethod
    def _should_skip_startup_reconcile() -> bool:
        argv = sys.argv
        if not argv:
            return True
        script = argv[0]
        if "manage.py" not in script and "django" not in script:
            return False
        skip_commands = {
            "migrate",
            "makemigrations",
            "flush",
            "shell",
            "collectstatic",
            "test",
        }
        return any(cmd in argv for cmd in skip_commands)
