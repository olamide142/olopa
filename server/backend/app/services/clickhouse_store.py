"""Backward-compatible import wrapper.

Prefer importing from `app.services.telemetry.store`.
"""

from app.services.telemetry.store import ClickHouseStore

__all__ = ["ClickHouseStore"]
