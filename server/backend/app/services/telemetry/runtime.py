"""Telemetry ingest runtime.

Owns queueing, backpressure ACK behavior, and background flush worker.
"""

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone

from app.config import Settings, get_settings
from app.schemas.telemetry import AckResponse, IngestBatchRequest, IngestStatsResponse

from .store import ClickHouseStore

logger = logging.getLogger(__name__)


@dataclass
class IngestCounters:
    accepted_total: int = 0
    rejected_total: int = 0
    flushed_total: int = 0
    failed_flush_total: int = 0
    last_flush_at: datetime | None = None


class IngestRuntime:
    """In-memory buffering runtime with explicit overload behavior."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = ClickHouseStore()
        self.queue: asyncio.Queue[IngestBatchRequest] = asyncio.Queue(maxsize=settings.ingest_queue_maxsize)
        self.counters = IngestCounters()
        self._worker_task: asyncio.Task[None] | None = None
        self._shutdown = asyncio.Event()
        self.available = False
        self.startup_error: str | None = None

    async def start(self) -> None:
        if not self.settings.telemetry_enabled:
            self.available = False
            self.startup_error = "telemetry disabled by config"
            return
        await self.store.init_schema()
        self._worker_task = asyncio.create_task(self._worker(), name="ingest-writer")
        self.available = True

    async def stop(self) -> None:
        self._shutdown.set()
        if self._worker_task is not None:
            self._worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._worker_task
        self.available = False

    def ack_batch(self, batch: IngestBatchRequest) -> AckResponse:
        if not self.available:
            self.counters.rejected_total += 1
            return AckResponse(
                accepted=False,
                rejected=1,
                retry_after_ms=self.settings.ingest_default_retry_after_ms,
                suggested_batch_bytes=0,
                throttle_ratio=1.0,
                message=self.startup_error or "telemetry backend unavailable",
            )

        if self.queue.full():
            self.counters.rejected_total += 1
            return AckResponse(
                accepted=False,
                rejected=1,
                retry_after_ms=self.settings.ingest_default_retry_after_ms,
                suggested_batch_bytes=max(500_000, self.settings.ingest_suggested_batch_bytes // 2),
                throttle_ratio=min(1.0, self.queue.qsize() / max(1, self.queue.maxsize)),
                message="queue saturated",
            )

        self.queue.put_nowait(batch)
        self.counters.accepted_total += 1
        return AckResponse(
            accepted=True,
            rejected=0,
            retry_after_ms=0,
            suggested_batch_bytes=self.settings.ingest_suggested_batch_bytes,
            throttle_ratio=self.queue.qsize() / max(1, self.queue.maxsize),
        )

    def stats(self) -> IngestStatsResponse:
        return IngestStatsResponse(
            queued=self.queue.qsize(),
            max_queue=self.queue.maxsize,
            accepted_total=self.counters.accepted_total,
            rejected_total=self.counters.rejected_total,
            flushed_total=self.counters.flushed_total,
            failed_flush_total=self.counters.failed_flush_total,
            last_flush_at=self.counters.last_flush_at,
        )

    async def _worker(self) -> None:
        flush_interval = self.settings.ingest_flush_interval_ms / 1000
        max_rows = self.settings.ingest_flush_max_rows
        pending: list[IngestBatchRequest] = []
        pending_rows = 0

        while not self._shutdown.is_set():
            try:
                batch = await asyncio.wait_for(self.queue.get(), timeout=flush_interval)
                pending.append(batch)
                pending_rows += (
                    len(batch.process_exec_events)
                    + len(batch.file_events)
                    + len(batch.net_events)
                    + len(batch.agent_heartbeats)
                )
                self.queue.task_done()
            except asyncio.TimeoutError:
                pass

            if not pending:
                continue

            # Flush if row threshold reached or queue drained.
            if pending_rows < max_rows and not self.queue.empty():
                continue

            await self._flush_pending(pending)
            pending.clear()
            pending_rows = 0

    async def _flush_pending(self, pending: list[IngestBatchRequest]) -> None:
        try:
            inserted = 0
            for batch in pending:
                inserted += await self.store.insert_batch(batch)
            self.counters.flushed_total += inserted
            self.counters.last_flush_at = datetime.now(timezone.utc)
        except Exception as exc:
            self.counters.failed_flush_total += len(pending)
            logger.exception("failed to flush ingest batches: %s", exc)
            for batch in pending:
                with suppress(Exception):
                    await self.store.record_failure(
                        tenant_id=batch.tenant_id,
                        host_id=batch.host_id,
                        batch_id=str(batch.batch_id),
                        message=str(exc),
                    )


runtime: IngestRuntime | None = None


def get_runtime() -> IngestRuntime:
    if runtime is None:
        raise RuntimeError("ingest runtime not initialized")
    return runtime


async def init_runtime() -> IngestRuntime:
    global runtime
    if runtime is None:
        runtime = IngestRuntime(get_settings())
        try:
            await runtime.start()
        except Exception as exc:
            runtime.available = False
            runtime.startup_error = f"startup failed: {exc}"
            logger.exception("telemetry runtime startup failed: %s", exc)
    return runtime


async def shutdown_runtime() -> None:
    global runtime
    if runtime is not None:
        await runtime.stop()
        runtime = None

