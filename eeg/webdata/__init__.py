"""Shipped web console assets (templates + static) for ``eeg --serve``."""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def templates_dir() -> Path:
    return PACKAGE_DIR / "templates"


def static_dir() -> Path:
    return PACKAGE_DIR / "static"
