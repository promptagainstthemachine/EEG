"""Local path resolution for project create."""

from django.conf import settings
from django.test import TestCase

from apps.projects.path_utils import is_file_url, resolve_local_source_path


class ProjectPathUtilsTests(TestCase):
    def test_file_url_relative_to_base_dir(self):
        raw = "file://fixtures/vulnerable-apps/ai-goat"
        self.assertTrue(is_file_url(raw))
        path = resolve_local_source_path(repository_url=raw)
        self.assertIsNotNone(path)
        self.assertTrue(path.is_dir())
        self.assertEqual(
            path,
            (settings.BASE_DIR / "fixtures" / "vulnerable-apps" / "ai-goat").resolve(),
        )

    def test_relative_local_path(self):
        path = resolve_local_source_path(local_path="fixtures/vulnerable-apps/ai-goat")
        self.assertIsNotNone(path)
        self.assertTrue(path.name, "ai-goat")
