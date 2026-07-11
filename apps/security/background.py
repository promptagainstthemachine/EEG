"""Fire-and-forget background work (daemon threads) for long-running scans."""

from __future__ import annotations

import logging
import threading
from typing import Callable

from django.db import close_old_connections

logger = logging.getLogger(__name__)


def run_in_background(target: Callable[[], None], *, name: str = "eeg-background") -> threading.Thread:
    """Run *target* on a daemon thread with a fresh DB connection."""

    def wrapper() -> None:
        close_old_connections()
        try:
            target()
        except Exception:
            logger.exception("Background task failed: %s", name)
        finally:
            close_old_connections()

    thread = threading.Thread(target=wrapper, name=name, daemon=True)
    thread.start()
    return thread
