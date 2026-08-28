"""Agent binary download.

Landing, install script, and docs are static files served directly by Caddy now
(see ``app/control_plane/site/`` and ``Caddyfile``). This is the one route that
still needs the backend: which binary to hand back depends on env config
(``AGENT_BINARY_PATH`` / ``AGENT_DOWNLOAD_URL``) resolved at runtime.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse, Response

from ..deps import settings

router = APIRouter(tags=["downloads"])


@router.get("/downloads/agent/latest", response_model=None)
async def download_agent_latest() -> Response:
    """Download latest agent binary from local path or configured upstream URL."""
    configured_path = settings.agent_binary_path.strip()
    if configured_path:
        local_path = Path(configured_path)
        if local_path.exists() and local_path.is_file():
            return FileResponse(
                path=str(local_path),
                media_type="application/octet-stream",
                filename=local_path.name,
            )

    configured_url = settings.agent_download_url.strip()
    if configured_url:
        return RedirectResponse(url=configured_url, status_code=307)

    raise HTTPException(
        status_code=404,
        detail=(
            "agent download is not configured; set AGENT_BINARY_PATH or "
            "AGENT_DOWNLOAD_URL in control-plane environment"
        ),
    )
