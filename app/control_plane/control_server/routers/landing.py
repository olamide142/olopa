"""Public landing page, install script, and agent download."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse

from ..deps import settings, template_root, templates

router = APIRouter(tags=["landing"])


@router.get("/landing", response_class=HTMLResponse)
async def landing_page(request: Request) -> HTMLResponse:
    """Render the public landing page."""
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})


@router.get("/install", include_in_schema=False)
async def install_redirect() -> RedirectResponse:
    """Route install landing traffic into the in-app install panel."""
    return RedirectResponse(url="/#install", status_code=307)


@router.get("/install.sh")
async def install_script() -> PlainTextResponse:
    """Return the checked-in installer script."""
    script_path = template_root / "install.sh"
    if not script_path.exists() or not script_path.is_file():
        raise HTTPException(status_code=404, detail="install script not found")
    try:
        return PlainTextResponse(content=script_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"failed to read install script: {exc}") from exc


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
