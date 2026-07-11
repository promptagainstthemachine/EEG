"""
EEG - Repository Crawler
Walks a project directory and collects scannable files, respecting .gitignore patterns.
"""

import os
from typing import List, Dict, Set


SCANNABLE_EXTENSIONS = {
    ".py", ".tf", ".yaml", ".yml", ".json", ".toml",
    ".hcl", ".cfg", ".ini", ".env", ".sh", ".bash",
    ".ts", ".js", ".jsx", ".tsx", ".bicep", ".tfvars",
    ".java", ".go", ".rb",
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".eggs", "dist", "build", ".terraform",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


class RepoCrawler:
    """Recursively crawl a repository and collect scannable files."""

    def __init__(self, root_path: str):
        self.root_path = os.path.abspath(root_path)
        self._gitignore_patterns: Set[str] = set()
        self._load_gitignore()

    def _load_gitignore(self):
        gitignore = os.path.join(self.root_path, ".gitignore")
        if os.path.isfile(gitignore):
            with open(gitignore, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._gitignore_patterns.add(line.rstrip("/"))

    def _is_ignored(self, rel_path: str) -> bool:
        parts = rel_path.split(os.sep)
        for p in self._gitignore_patterns:
            if p in parts or rel_path.endswith(p):
                return True
        return False

    def crawl(self) -> List[Dict]:
        """Return list of dicts with file_path, relative_path, extension, size."""
        results = []
        for dirpath, dirnames, filenames in os.walk(self.root_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, self.root_path)

                if self._is_ignored(rel_path):
                    continue

                _, ext = os.path.splitext(fname)
                if ext.lower() not in SCANNABLE_EXTENSIONS:
                    continue

                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    continue
                if size > MAX_FILE_SIZE_BYTES or size == 0:
                    continue

                results.append({
                    "file_path": full_path,
                    "relative_path": rel_path,
                    "extension": ext.lower(),
                    "size": size,
                })
        return results
