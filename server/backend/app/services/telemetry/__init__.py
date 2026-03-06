"""Telemetry service package.

This package isolates ingest runtime orchestration from ClickHouse persistence
to keep backend responsibilities explicit and easier to test.
"""

from .runtime import IngestRuntime, get_runtime, init_runtime, shutdown_runtime
from .store import ClickHouseStore

__all__ = [
    "ClickHouseStore",
    "IngestRuntime",
    "get_runtime",
    "init_runtime",
    "shutdown_runtime",
]

