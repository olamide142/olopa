from fastapi import APIRouter, Depends, Query

from app.schemas.telemetry import EventQueryResponse
from app.services.telemetry import IngestRuntime, get_runtime

router = APIRouter(prefix="/events", tags=["telemetry-events"])


async def _query_table(
    table: str,
    tenant_id: str,
    host_id: str | None,
    limit: int,
    runtime: IngestRuntime,
) -> EventQueryResponse:
    if not runtime.available:
        return EventQueryResponse(events=[])
    rows = await runtime.store.query_events(table=table, tenant_id=tenant_id, host_id=host_id, limit=limit)
    return EventQueryResponse(events=rows)


@router.get("/exec", response_model=EventQueryResponse)
async def get_exec_events(
    tenant_id: str = Query(...),
    host_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=5000),
    runtime: IngestRuntime = Depends(get_runtime),
) -> EventQueryResponse:
    """Query process execution events ordered by newest first."""
    return await _query_table("process_exec_events", tenant_id, host_id, limit, runtime)


@router.get("/file", response_model=EventQueryResponse)
async def get_file_events(
    tenant_id: str = Query(...),
    host_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=5000),
    runtime: IngestRuntime = Depends(get_runtime),
) -> EventQueryResponse:
    """Query file activity events ordered by newest first."""
    return await _query_table("file_events", tenant_id, host_id, limit, runtime)


@router.get("/net", response_model=EventQueryResponse)
async def get_net_events(
    tenant_id: str = Query(...),
    host_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=5000),
    runtime: IngestRuntime = Depends(get_runtime),
) -> EventQueryResponse:
    """Query network activity events ordered by newest first."""
    return await _query_table("net_events", tenant_id, host_id, limit, runtime)


@router.get("/heartbeats", response_model=EventQueryResponse)
async def get_heartbeats(
    tenant_id: str = Query(...),
    host_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=5000),
    runtime: IngestRuntime = Depends(get_runtime),
) -> EventQueryResponse:
    """Query agent heartbeat events ordered by newest first."""
    return await _query_table("agent_heartbeats", tenant_id, host_id, limit, runtime)

