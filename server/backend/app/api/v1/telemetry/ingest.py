from fastapi import APIRouter, Depends

from app.schemas.telemetry import AckResponse, IngestBatchRequest, IngestStatsResponse
from app.services.telemetry import IngestRuntime, get_runtime

router = APIRouter(prefix="/ingest", tags=["telemetry-ingest"])


@router.post("/batches", response_model=AckResponse)
async def ingest_batch(
    body: IngestBatchRequest,
    runtime: IngestRuntime = Depends(get_runtime),
) -> AckResponse:
    """Accept a telemetry batch and return backpressure hints to the agent."""
    return runtime.ack_batch(body)


@router.get("/stats", response_model=IngestStatsResponse)
async def ingest_stats(runtime: IngestRuntime = Depends(get_runtime)) -> IngestStatsResponse:
    """Expose ingest runtime queue/counter metrics for operations visibility."""
    return runtime.stats()


