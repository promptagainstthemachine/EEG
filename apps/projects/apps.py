from django.apps import AppConfig


class ProjectsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.projects"
    verbose_name = "Projects"

    def ready(self) -> None:
        from apps.projects import signals  # noqa: F401
