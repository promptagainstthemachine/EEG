"""Managed org/project repository storage."""

import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from apps.accounts.models import Organization
from apps.projects.models import Project
from apps.projects.repo_storage import (
    is_managed_repo_path,
    project_repo_path,
    remove_project_repository,
    repo_storage_root,
)


class RepoStorageTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.storage = Path(self.tmp.name) / "repos"
        self.storage.mkdir(parents=True)

        self.org = Organization.objects.create(name="X Corp", slug="xcorp")
        self.project = Project.objects.create(
            organization=self.org,
            name="Example Repo",
            slug="example-repo",
        )

    def tearDown(self):
        self.tmp.cleanup()

    @override_settings(EEG_REPO_STORAGE_ROOT=None)
    def test_project_repo_path_layout(self):
        with self.settings(EEG_REPO_STORAGE_ROOT=str(self.storage)):
            path = project_repo_path(self.project)
            self.assertEqual(
                path,
                self.storage.resolve() / "org" / "xcorp" / "example-repo",
            )

    @override_settings(EEG_REPO_STORAGE_ROOT=None)
    def test_remove_only_managed_paths(self):
        with self.settings(EEG_REPO_STORAGE_ROOT=str(self.storage)):
            managed = project_repo_path(self.project)
            managed.mkdir(parents=True)
            (managed / "file.py").write_text("x", encoding="utf-8")

            remove_project_repository(self.project)
            self.assertFalse(managed.exists())
            org_dir = self.storage / "org" / "xcorp"
            self.assertTrue(org_dir.exists())

    def test_is_managed_repo_path(self):
        with self.settings(EEG_REPO_STORAGE_ROOT=str(self.storage)):
            managed = project_repo_path(self.project)
            self.assertTrue(is_managed_repo_path(managed))
            self.assertFalse(is_managed_repo_path("/etc/passwd"))

    @override_settings(EEG_REPO_STORAGE_ROOT=None)
    def test_post_delete_removes_project_dir(self):
        with self.settings(EEG_REPO_STORAGE_ROOT=str(self.storage)):
            managed = project_repo_path(self.project)
            managed.mkdir(parents=True)
            (managed / "main.py").write_text("print('hi')", encoding="utf-8")

            self.project.delete()
            self.assertFalse(managed.exists())
            self.assertEqual(repo_storage_root(), self.storage.resolve())
