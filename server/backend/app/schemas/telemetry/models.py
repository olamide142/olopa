"""Telemetry API request/response and event models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EventFamily(str, Enum):
    exec = "exec"
    file = "file"
    net = "net"
    heartbeat = "heartbeat"


class EventEnvelope(BaseModel):
    ts: datetime = Field(default_factory=utc_now)
    event_id: UUID = Field(default_factory=uuid4)
    schema_version: int = 1
    attrs: dict[str, str] = Field(default_factory=dict)


class ProcessExecEvent(EventEnvelope):
    pid: int
    tgid: int
    ppid: int = 0
    uid: int
    gid: int
    comm: str
    filename: str
    argv_hash: str | None = None
    cgroup_id: int = 0
    container_id: str | None = None


class FileEvent(EventEnvelope):
    pid: int
    tgid: int
    uid: int
    gid: int
    comm: str
    operation: str
    path: str
    path_hash: str | None = None
    bytes: int | None = None


class NetEvent(EventEnvelope):
    pid: int
    tgid: int
    uid: int
    gid: int
    comm: str
    direction: str = "egress"
    protocol: str = "tcp"
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    bytes: int | None = None


class AgentHeartbeatEvent(EventEnvelope):
    agent_version: str
    kernel_version: str
    events_read_total: int = 0
    events_dropped_total: int = 0
    queue_depth: int = 0
    cpu_pct: float | None = None
    mem_rss_bytes: int | None = None


class IngestBatchRequest(BaseModel):
    tenant_id: str
    host_id: str
    batch_id: UUID = Field(default_factory=uuid4)
    schema_version: int = 1
    compression: str = "none"
    process_exec_events: list[ProcessExecEvent] = Field(default_factory=list)
    file_events: list[FileEvent] = Field(default_factory=list)
    net_events: list[NetEvent] = Field(default_factory=list)
    agent_heartbeats: list[AgentHeartbeatEvent] = Field(default_factory=list)


class AckResponse(BaseModel):
    accepted: bool
    rejected: int = 0
    retry_after_ms: int = 0
    suggested_batch_bytes: int = 4_000_000
    throttle_ratio: float = 0.0
    message: str = "ok"


class IngestStatsResponse(BaseModel):
    queued: int
    max_queue: int
    accepted_total: int
    rejected_total: int
    flushed_total: int
    failed_flush_total: int
    last_flush_at: datetime | None


class EventQueryResponse(BaseModel):
    events: list[dict[str, Any]]
