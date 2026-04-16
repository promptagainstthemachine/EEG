"""
EEG - Thread Pool Executor
Manages concurrent scanning with configurable pool sizes.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Any

POOL_SIZES = {"min": 1, "med": 4, "max": 8}


class ThreadManager:
    """Thread pool wrapper for parallel detector execution."""

    def __init__(self, level: str = "min"):
        self.pool_size = POOL_SIZES.get(level, 1)

    def execute(self, func: Callable, items: List[Any]) -> List[Any]:
        """Run func(item) concurrently for each item. Returns list of results."""
        results = []
        with ThreadPoolExecutor(max_workers=self.pool_size) as pool:
            futures = {pool.submit(func, item): item for item in items}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as exc:
                    item = futures[future]
                    name = getattr(item, "name", str(item))
                    print(f"  [WARN] Detector '{name}' raised: {exc}")
        return results
