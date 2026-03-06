from fastapi import APIRouter

from app.api.v1 import health, waitlist
from app.api.v1.telemetry import events, ingest

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(waitlist.router)
api_router.include_router(ingest.router)
api_router.include_router(events.router)
