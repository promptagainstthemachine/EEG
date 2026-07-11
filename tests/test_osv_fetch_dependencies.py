"""OSV multi-ecosystem batch helper."""

from unittest.mock import MagicMock, patch

from django.test import TestCase

from eeg.vuln_manager.dependency_parser import ParsedDependency
from eeg.vuln_manager.osv_fetcher import OSVFetcher


class OSVFetchDependenciesTests(TestCase):
    @patch.object(OSVFetcher, "batch_query")
    def test_fetch_dependencies_maps_ecosystems(self, mock_batch):
        mock_batch.return_value = []
        deps = [
            ParsedDependency("requests", "2.28.0", "pip", "requirements.txt"),
            ParsedDependency("express", "4.18.0", "npm", "package.json"),
            ParsedDependency("github.com/foo/bar", "v1.2.3", "go", "go.mod"),
            ParsedDependency("MyLib", "8.0.0", "nuget", "App.csproj"),
        ]
        OSVFetcher().fetch_dependencies(deps, "any")
        packages = mock_batch.call_args[0][0]
        ecosystems = {p["ecosystem"] for p in packages}
        self.assertIn("PyPI", ecosystems)
        self.assertIn("npm", ecosystems)
        self.assertIn("Go", ecosystems)
        self.assertIn("NuGet", ecosystems)
        go_pkg = next(p for p in packages if p["ecosystem"] == "Go")
        self.assertEqual(go_pkg["version"], "1.2.3")
