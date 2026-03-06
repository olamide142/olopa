"""Lightweight security utilities for API edge protection."""

import hashlib
import time
from collections import defaultdict

# In-memory rate limit: IP -> list of timestamps (last N hours)
# For production, use Redis
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
def _hash_ip(ip: str) -> str:
    """Hash IP to avoid storing raw client addresses in memory."""
    return hashlib.sha256(ip.encode()).hexdigest()[:32]


def _clean_old(store: list[float], window_seconds: float) -> None:
    cutoff = time.monotonic() - window_seconds
    while store and store[0] < cutoff:
        store.pop(0)


def check_rate_limit(ip: str, limit: int, window_seconds: float = 3600) -> bool:
    """Return True if under limit, False if over (should reject)."""
    key = _hash_ip(ip)
    store = _rate_limit_store[key]
    _clean_old(store, window_seconds)
    if len(store) >= limit:
        return False
    store.append(time.monotonic())
    return True
