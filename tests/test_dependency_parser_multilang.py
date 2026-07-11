"""Multi-ecosystem dependency manifest parsing."""

import tempfile
from pathlib import Path

from django.test import TestCase

from eeg.vuln_manager.dependency_parser import DependencyParser


class DependencyParserMultilangTests(TestCase):
    def test_parses_python_and_javascript(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests>=2.28.0\n")
            (root / "package.json").write_text(
                '{"dependencies":{"express":"^4.18.0","lodash":"4.17.21"}}'
            )
            deps = DependencyParser(str(root)).parse_all()
            names_ecos = {(d.name, d.ecosystem) for d in deps}
            self.assertIn(("requests", "pip"), names_ecos)
            self.assertIn(("express", "npm"), names_ecos)

    def test_parses_go_mod(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.com/app\n\n"
                "require (\n"
                "\tgithub.com/gin-gonic/gin v1.9.1\n"
                "\tgolang.org/x/net v0.17.0\n"
                ")\n"
            )
            deps = DependencyParser(str(root)).parse_all()
            eco_go = [d for d in deps if d.ecosystem == "go"]
            self.assertEqual(len(eco_go), 2)
            self.assertTrue(any(d.name.endswith("/gin") for d in eco_go))

    def test_parses_csproj_nuget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "App.csproj").write_text(
                '<Project><ItemGroup>'
                '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
                "</ItemGroup></Project>"
            )
            deps = DependencyParser(str(root)).parse_all()
            nuget = [d for d in deps if d.ecosystem == "nuget"]
            self.assertEqual(len(nuget), 1)
            self.assertEqual(nuget[0].name, "Newtonsoft.Json")

    def test_parse_ai_only_filters_pypi_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("torch>=2.0.0\nrequests>=2.0\n")
            (root / "package.json").write_text('{"dependencies":{"express":"4.18.0"}}')
            ai = DependencyParser(str(root)).parse()
            self.assertIn("torch", ai)
            self.assertNotIn("requests", ai)
            self.assertNotIn("express", ai)
