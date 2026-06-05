"""Threat-intelligence feed downloader.

Downloads the configured feed sources, de-duplicates entries, and writes a
single ``intel.json`` artifact that the Olopa agent's IntelStore loads.

Usage
-----
Standalone (runs one sync then exits)::

    python -m app.intel_sync.sync

Daemon loop (used by the control-plane background task)::

    python -m app.intel_sync.sync --loop

The output path and refresh interval are controlled via environment variables:
  OLOPA_INTEL_PATH          — output file (default /etc/olopa/intel.json)
  OLOPA_INTEL_REFRESH_S     — loop interval in seconds (default 3600)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import pathlib
import time
from typing import Iterator

import httpx

from .config import INTEL_SETS, FeedSource, IntelSetConfig, default_output_path, refresh_interval_s

logger = logging.getLogger("intel_sync")


# ── Entry parsing ──────────────────────────────────────────────────────────────

def _parse_lines(text: str, comment_prefix: str) -> Iterator[str]:
    """Yield non-empty, non-comment lines from raw feed text."""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(comment_prefix):
            continue
        # Strip inline comments (e.g. "1.2.3.4  # scanner")
        if " " in line:
            line = line.split()[0].strip()
        if line:
            yield line


# ── Feed fetching ──────────────────────────────────────────────────────────────

def _fetch_source(source: FeedSource, client: httpx.Client) -> list[str]:
    """Download one feed source and return parsed entries."""
    try:
        resp = client.get(source.url, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("feed fetch failed url=%s: %s", source.url, exc)
        return []

    entries = list(_parse_lines(resp.text, source.comment_prefix))
    logger.debug("fetched %d entries from %s", len(entries), source.url)
    return entries


# ── Set assembly ───────────────────────────────────────────────────────────────

def _build_set(cfg: IntelSetConfig, client: httpx.Client) -> dict:
    """Download all sources for one intel set and return the wire-format dict."""
    seen: set[str] = set()
    entries: list[str] = []

    for source in cfg.sources:
        for entry in _fetch_source(source, client):
            normalised = entry.lower()
            if normalised not in seen:
                seen.add(normalised)
                entries.append(normalised)
                if cfg.max_entries and len(entries) >= cfg.max_entries:
                    logger.debug(
                        "set %s capped at %d entries (max_entries limit)",
                        cfg.name,
                        cfg.max_entries,
                    )
                    break
        if cfg.max_entries and len(entries) >= cfg.max_entries:
            break

    logger.info(
        "set %s: %d entries (type=%s)", cfg.name, len(entries), cfg.set_type
    )
    return {
        "type": cfg.set_type,
        "description": cfg.description,
        "count": len(entries),
        "items": entries,
    }


# ── Output writing ─────────────────────────────────────────────────────────────

def _write_intel_json(sets: dict[str, dict], output_path: str) -> None:
    """Atomically write intel.json to *output_path*."""
    payload = {
        "version": 1,
        "generated_at_unix_s": int(time.time()),
        "sets": sets,
    }

    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)

    total_entries = sum(s["count"] for s in sets.values())
    logger.info(
        "intel.json written: path=%s sets=%d total_entries=%d",
        output_path,
        len(sets),
        total_entries,
    )


# ── Checksum helpers ───────────────────────────────────────────────────────────

def _file_sha256(path: str) -> str | None:
    """Return hex SHA-256 of file contents, or None if file absent."""
    try:
        data = pathlib.Path(path).read_bytes()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return None


# ── Public sync function ───────────────────────────────────────────────────────

def run_sync(output_path: str | None = None) -> SyncResult:
    """Run one full sync cycle: fetch all feeds and write intel.json.

    Parameters
    ----------
    output_path:
        Destination file.  Defaults to ``OLOPA_INTEL_PATH`` env var or
        ``/etc/olopa/intel.json``.

    Returns
    -------
    SyncResult
        Summary of the sync run (used by the control-plane API endpoint).
    """
    if output_path is None:
        output_path = default_output_path()

    t_start = time.monotonic()
    sets: dict[str, dict] = {}
    errors: list[str] = []

    with httpx.Client(
        headers={"User-Agent": "olopa-intel-sync/1.0"},
        http2=False,
    ) as client:
        for cfg in INTEL_SETS:
            try:
                sets[cfg.name] = _build_set(cfg, client)
            except Exception as exc:  # noqa: BLE001
                msg = f"set {cfg.name}: {exc}"
                logger.error("sync error: %s", msg)
                errors.append(msg)

    if sets:
        sha_before = _file_sha256(output_path)
        _write_intel_json(sets, output_path)
        sha_after = _file_sha256(output_path)
        changed = sha_before != sha_after
    else:
        changed = False

    elapsed_ms = int((time.monotonic() - t_start) * 1000)
    return SyncResult(
        sets_synced=list(sets.keys()),
        total_entries=sum(s["count"] for s in sets.values()),
        errors=errors,
        output_path=output_path,
        changed=changed,
        elapsed_ms=elapsed_ms,
    )


# ── Result type ────────────────────────────────────────────────────────────────

class SyncResult:
    __slots__ = (
        "sets_synced",
        "total_entries",
        "errors",
        "output_path",
        "changed",
        "elapsed_ms",
    )

    def __init__(
        self,
        sets_synced: list[str],
        total_entries: int,
        errors: list[str],
        output_path: str,
        changed: bool,
        elapsed_ms: int,
    ) -> None:
        self.sets_synced = sets_synced
        self.total_entries = total_entries
        self.errors = errors
        self.output_path = output_path
        self.changed = changed
        self.elapsed_ms = elapsed_ms

    def to_dict(self) -> dict:
        return {
            "sets_synced": self.sets_synced,
            "total_entries": self.total_entries,
            "errors": self.errors,
            "output_path": self.output_path,
            "changed": self.changed,
            "elapsed_ms": self.elapsed_ms,
            "ok": len(self.errors) == 0,
        }


# ── Daemon loop ────────────────────────────────────────────────────────────────

def run_loop(output_path: str | None = None) -> None:
    """Run sync in a daemon loop, re-fetching every ``refresh_interval_s()``."""
    interval = refresh_interval_s()
    logger.info("intel-sync daemon starting: interval=%ds", interval)
    while True:
        result = run_sync(output_path)
        if result.errors:
            logger.warning(
                "sync completed with %d error(s): %s",
                len(result.errors),
                result.errors,
            )
        else:
            logger.info(
                "sync ok: sets=%d entries=%d changed=%s elapsed=%dms",
                len(result.sets_synced),
                result.total_entries,
                result.changed,
                result.elapsed_ms,
            )
        time.sleep(interval)


# ── CLI entry-point ────────────────────────────────────────────────────────────

def _main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    parser = argparse.ArgumentParser(description="Olopa threat-intel feed sync")
    parser.add_argument(
        "--loop",
        action="store_true",
        help="run as a daemon, re-syncing every OLOPA_INTEL_REFRESH_S seconds",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"output path (default: {default_output_path()})",
    )
    args = parser.parse_args()

    if args.loop:
        run_loop(args.output)
    else:
        result = run_sync(args.output)
        print(json.dumps(result.to_dict(), indent=2))
        raise SystemExit(0 if not result.errors else 1)


if __name__ == "__main__":
    _main()
