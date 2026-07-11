"""EEG OSS project URLs."""
from django.urls import path

from . import views

app_name = "projects"

urlpatterns = [
    path("", views.project_list, name="list"),
    path("create/", views.project_create, name="create"),
    path("<int:project_id>/", views.project_detail, name="detail"),
    path("<int:project_id>/edit/", views.project_edit, name="edit"),
    path("<int:project_id>/delete/", views.project_delete, name="delete"),
    path("<int:project_id>/scan/", views.project_scan, name="scan"),
    path("<int:project_id>/scan/status/", views.project_scan_status, name="scan_status"),
    path("<int:project_id>/toggle-status/", views.project_toggle_status, name="toggle_status"),
]
