"""Tests for codebase semantic indexing."""

import tempfile
from pathlib import Path

from django.test import TestCase

from apps.security.code_semantic_index import build_semantic_index_for_roots


class CodeSemanticIndexTests(TestCase):
    def test_indexes_python_symbols_and_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "__init__.py").write_text("")
            (root / "pkg" / "util.py").write_text("def helper():\n    return 1\n")
            (root / "app.py").write_text(
                "from pkg import util\n\n"
                "def run():\n    return util.helper()\n"
            )

            index = build_semantic_index_for_roots([str(root)], max_files_per_root=50)
            self.assertGreaterEqual(index.files_indexed, 2)
            sym = index.symbol_at("app.py", 4)
            self.assertIsNotNone(sym)
            self.assertEqual(sym.name, "run")
            mod = index.module_for_file("app.py")
            self.assertIsNotNone(mod)
