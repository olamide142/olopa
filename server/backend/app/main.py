from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.core.db import init_db
from app.api.v1.router import api_router
from app.services.telemetry import init_runtime, shutdown_runtime

# Directory containing index.html (parent of backend/)
WEB_ROOT = Path(__file__).resolve().parent.parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize shared resources on startup and shutdown."""
    await init_db()
    await init_runtime()
    yield
    await shutdown_runtime()


def _parse_cors_origins(raw: str) -> list[str]:
    return [origin.strip() for origin in raw.split(",")] if "," in raw else [raw]


def create_app() -> FastAPI:
    """Create and configure FastAPI application instance."""
    settings = get_settings()
    app = FastAPI(
        title="Olopa API",
        description="Machine control plane - waitlist and telemetry platform",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_parse_cors_origins(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/health")
    async def root_health() -> dict[str, str]:
        return {"status": "ok"}

    # Serve landing page and mascot assets from same origin (no CORS)
    index_path = WEB_ROOT / "index.html"
    assets_dir = WEB_ROOT / "assets"
    if index_path.exists():
        @app.get("/")
        async def index():
            return FileResponse(index_path)
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    return app


app = create_app()


