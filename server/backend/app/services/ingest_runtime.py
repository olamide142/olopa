"""Backward-compatible import wrapper.

Prefer importing from `app.services.telemetry.runtime`.
"""

from app.services.telemetry.runtime import IngestRuntime, get_runtime, init_runtime, shutdown_runtime

__all__ = ["IngestRuntime", "get_runtime", "init_runtime", "shutdown_runtime"]
