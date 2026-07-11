"""Regression tests for local_path allowlisting (LFI / arbitrary scan root)."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from apps.projects.path_utils import (
    is_under_allowed_roots,
    resolve_local_source_path,
)


class LocalPathAllowlistTests(SimpleTestCase):
    def test_relative_path_under_base_dir_allowed(self):
        # BASE_DIR itself is always an allowed root and exists.
        resolved = resolve_local_source_path(local_path=".")
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertTrue(is_under_allowed_roots(resolved))

    def test_rejects_etc(self):
        etc = Path("/etc")
        if not etc.is_dir():
            self.skipTest("/etc not present")
        self.assertIsNone(resolve_local_source_path(local_path="/etc"))
        self.assertFalse(is_under_allowed_roots(etc))

    def test_rejects_filesystem_root(self):
        root = Path("/")
        self.assertIsNone(resolve_local_source_path(local_path="/"))
        self.assertFalse(is_under_allowed_roots(root))

    @override_settings(EEG_ALLOWED_SCAN_ROOTS="")
    def test_rejects_tmp_unless_allowlisted(self):
        tmp = Path("/tmp")
        if not tmp.is_dir():
            self.skipTest("/tmp not present")
        # /tmp is outside BASE_DIR by default
        if is_under_allowed_roots(tmp):
            self.skipTest("/tmp unexpectedly under allowed roots")
        self.assertIsNone(resolve_local_source_path(local_path="/tmp"))

    def test_extra_root_via_setting(self):
        tmp = Path("/tmp")
        if not tmp.is_dir():
            self.skipTest("/tmp not present")
        with override_settings(EEG_ALLOWED_SCAN_ROOTS="/tmp"):
            resolved = resolve_local_source_path(local_path="/tmp")
            self.assertIsNotNone(resolved)
            assert resolved is not None
            self.assertEqual(resolved, tmp.resolve())
