"""ClickHouse persistence layer for telemetry events."""

import asyncio
from typing import Any, Iterable
from urllib.parse import urlparse

import clickhouse_connect

from app.config import get_settings
from app.schemas.telemetry import IngestBatchRequest


PROCESS_EXEC_DDL = """
CREATE TABLE IF NOT EXISTS process_exec_events
(
    ts DateTime64(9, 'UTC'),
    tenant_id String,
    host_id String,
    event_id UUID,
    schema_version UInt16,
    pid UInt32,
    tgid UInt32,
    ppid UInt32,
    uid UInt32,
    gid UInt32,
    comm LowCardinality(String),
    filename String,
    argv_hash Nullable(String),
    cgroup_id UInt64,
    container_id Nullable(String),
    attrs Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, host_id, ts, pid)
TTL ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192
"""

FILE_DDL = """
CREATE TABLE IF NOT EXISTS file_events
(
    ts DateTime64(9, 'UTC'),
    tenant_id String,
    host_id String,
    event_id UUID,
    schema_version UInt16,
    pid UInt32,
    tgid UInt32,
    uid UInt32,
    gid UInt32,
    comm LowCardinality(String),
    operation LowCardinality(String),
    path String,
    path_hash Nullable(String),
    bytes Nullable(UInt64),
    attrs Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, host_id, ts, pid)
TTL ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192
"""

NET_DDL = """
CREATE TABLE IF NOT EXISTS net_events
(
    ts DateTime64(9, 'UTC'),
    tenant_id String,
    host_id String,
    event_id UUID,
    schema_version UInt16,
    pid UInt32,
    tgid UInt32,
    uid UInt32,
    gid UInt32,
    comm LowCardinality(String),
    direction LowCardinality(String),
    protocol LowCardinality(String),
    src_ip Nullable(String),
    src_port Nullable(UInt16),
    dst_ip Nullable(String),
    dst_port Nullable(UInt16),
    bytes Nullable(UInt64),
    attrs Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, host_id, ts, pid)
TTL ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192
"""

HEARTBEAT_DDL = """
CREATE TABLE IF NOT EXISTS agent_heartbeats
(
    ts DateTime64(9, 'UTC'),
    tenant_id String,
    host_id String,
    event_id UUID,
    schema_version UInt16,
    agent_version String,
    kernel_version String,
    events_read_total UInt64,
    events_dropped_total UInt64,
    queue_depth UInt32,
    cpu_pct Nullable(Float32),
    mem_rss_bytes Nullable(UInt64),
    attrs Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, host_id, ts)
TTL ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192
"""

FAILURE_DDL = """
CREATE TABLE IF NOT EXISTS ingest_failures
(
    ts DateTime64(9, 'UTC'),
    tenant_id String,
    host_id String,
    batch_id UUID,
    message String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, ts, host_id)
TTL ts + INTERVAL 14 DAY
SETTINGS index_granularity = 8192
"""

ALL_DDLS = [PROCESS_EXEC_DDL, FILE_DDL, NET_DDL, HEARTBEAT_DDL, FAILURE_DDL]


class ClickHouseStore:
    """Persistence API used by the ingest runtime and query routes."""

    def __init__(self) -> None:
        settings = get_settings()
        parsed = urlparse(settings.clickhouse_url)
        secure = settings.clickhouse_secure or parsed.scheme == "https"
        host = parsed.hostname or "localhost"
        port = parsed.port or (8443 if secure else 8123)
        self.client = clickhouse_connect.get_client(
            host=host,
            port=port,
            username=settings.clickhouse_username,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
            secure=secure,
        )

    async def init_schema(self) -> None:
        for ddl in ALL_DDLS:
            await asyncio.to_thread(self.client.command, ddl)

    async def insert_batch(self, batch: IngestBatchRequest) -> int:
        inserted = 0
        inserted += await self._insert_process_exec(batch)
        inserted += await self._insert_file_events(batch)
        inserted += await self._insert_net_events(batch)
        inserted += await self._insert_heartbeats(batch)
        return inserted

    async def _insert_process_exec(self, batch: IngestBatchRequest) -> int:
        if not batch.process_exec_events:
            return 0
        columns = [
            "ts",
            "tenant_id",
            "host_id",
            "event_id",
            "schema_version",
            "pid",
            "tgid",
            "ppid",
            "uid",
            "gid",
            "comm",
            "filename",
            "argv_hash",
            "cgroup_id",
            "container_id",
            "attrs",
        ]
        rows = [
            (
                e.ts,
                batch.tenant_id,
                batch.host_id,
                str(e.event_id),
                e.schema_version,
                e.pid,
                e.tgid,
                e.ppid,
                e.uid,
                e.gid,
                e.comm,
                e.filename,
                e.argv_hash,
                e.cgroup_id,
                e.container_id,
                e.attrs,
            )
            for e in batch.process_exec_events
        ]
        await self._insert_rows("process_exec_events", rows, columns)
        return len(rows)

    async def _insert_file_events(self, batch: IngestBatchRequest) -> int:
        if not batch.file_events:
            return 0
        columns = [
            "ts",
            "tenant_id",
            "host_id",
            "event_id",
            "schema_version",
            "pid",
            "tgid",
            "uid",
            "gid",
            "comm",
            "operation",
            "path",
            "path_hash",
            "bytes",
            "attrs",
        ]
        rows = [
            (
                e.ts,
                batch.tenant_id,
                batch.host_id,
                str(e.event_id),
                e.schema_version,
                e.pid,
                e.tgid,
                e.uid,
                e.gid,
                e.comm,
                e.operation,
                e.path,
                e.path_hash,
                e.bytes,
                e.attrs,
            )
            for e in batch.file_events
        ]
        await self._insert_rows("file_events", rows, columns)
        return len(rows)

    async def _insert_net_events(self, batch: IngestBatchRequest) -> int:
        if not batch.net_events:
            return 0
        columns = [
            "ts",
            "tenant_id",
            "host_id",
            "event_id",
            "schema_version",
            "pid",
            "tgid",
            "uid",
            "gid",
            "comm",
            "direction",
            "protocol",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "bytes",
            "attrs",
        ]
        rows = [
            (
                e.ts,
                batch.tenant_id,
                batch.host_id,
                str(e.event_id),
                e.schema_version,
                e.pid,
                e.tgid,
                e.uid,
                e.gid,
                e.comm,
                e.direction,
                e.protocol,
                e.src_ip,
                e.src_port,
                e.dst_ip,
                e.dst_port,
                e.bytes,
                e.attrs,
            )
            for e in batch.net_events
        ]
        await self._insert_rows("net_events", rows, columns)
        return len(rows)

    async def _insert_heartbeats(self, batch: IngestBatchRequest) -> int:
        if not batch.agent_heartbeats:
            return 0
        columns = [
            "ts",
            "tenant_id",
            "host_id",
            "event_id",
            "schema_version",
            "agent_version",
            "kernel_version",
            "events_read_total",
            "events_dropped_total",
            "queue_depth",
            "cpu_pct",
            "mem_rss_bytes",
            "attrs",
        ]
        rows = [
            (
                e.ts,
                batch.tenant_id,
                batch.host_id,
                str(e.event_id),
                e.schema_version,
                e.agent_version,
                e.kernel_version,
                e.events_read_total,
                e.events_dropped_total,
                e.queue_depth,
                e.cpu_pct,
                e.mem_rss_bytes,
                e.attrs,
            )
            for e in batch.agent_heartbeats
        ]
        await self._insert_rows("agent_heartbeats", rows, columns)
        return len(rows)

    async def _insert_rows(
        self,
        table: str,
        rows: Iterable[tuple[Any, ...]],
        columns: list[str],
    ) -> None:
        await asyncio.to_thread(self.client.insert, table, list(rows), column_names=columns)

    async def record_failure(self, tenant_id: str, host_id: str, batch_id: str, message: str) -> None:
        query = """
        INSERT INTO ingest_failures (ts, tenant_id, host_id, batch_id, message)
        VALUES (now64(9), {tenant_id:String}, {host_id:String}, {batch_id:UUID}, {message:String})
        """
        await asyncio.to_thread(
            self.client.command,
            query,
            parameters={
                "tenant_id": tenant_id,
                "host_id": host_id,
                "batch_id": batch_id,
                "message": message[:1024],
            },
        )

    async def query_events(self, table: str, tenant_id: str, host_id: str | None, limit: int) -> list[dict[str, Any]]:
        host_filter = "AND host_id = {host_id:String}" if host_id else ""
        query = f"""
        SELECT *
        FROM {table}
        WHERE tenant_id = {{tenant_id:String}}
        {host_filter}
        ORDER BY ts DESC
        LIMIT {{limit:UInt32}}
        """
        parameters: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
        if host_id:
            parameters["host_id"] = host_id
        result = await asyncio.to_thread(self.client.query, query, parameters=parameters)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

