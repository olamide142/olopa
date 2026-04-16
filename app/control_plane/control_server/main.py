"""FastAPI control-plane server for dashboard/control/compiler workflows.

Design intent:
- Rust server stays on the ingest hot path (agent -> ingest).
- Python server orchestrates control workflows and dashboard aggregation.
- Dashboard read endpoints proxy to Rust ingest APIs for now.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request, Response
import httpx
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import Settings


settings = Settings.from_env()
app = FastAPI(title="olopa-control-plane", version="0.1.0")
template_root = Path(__file__).resolve().parent / "template"
templates = Jinja2Templates(directory=str(template_root))
app.mount("/assets", StaticFiles(directory=str(template_root / "assets")), name="assets")


@app.get("/", response_class=HTMLResponse)
async def app_page(request: Request) -> HTMLResponse:
    """Render the control dashboard shell."""
    return templates.TemplateResponse(
        request=request,
        name="app.html",
        context={"request": request},
    )


@app.get("/landing", response_class=HTMLResponse)
async def landing_page(request: Request) -> HTMLResponse:
    """Render the public landing page."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request},
    )

@app.get("/quickstart", response_class=HTMLResponse)
@app.get("/quickstart/", response_class=HTMLResponse)
async def docs_quickstart_page(request: Request) -> HTMLResponse:
    """Render docs quickstart page."""
    return templates.TemplateResponse(
        request=request,
        name="docs_quickstart.html",
        context={"request": request},
    )


@app.get("/agent/config", response_class=HTMLResponse)
@app.get("/agent/config/", response_class=HTMLResponse)
async def docs_agent_config_page(request: Request) -> HTMLResponse:
    """Render docs page for agent configuration."""
    return templates.TemplateResponse(
        request=request,
        name="docs_agent_config.html",
        context={"request": request},
    )


@app.get("/oil", response_class=HTMLResponse)
@app.get("/oil/", response_class=HTMLResponse)
async def docs_oil_page(request: Request) -> HTMLResponse:
    """Render OIL language reference docs page."""
    return templates.TemplateResponse(
        request=request,
        name="docs_oil.html",
        context={"request": request},
    )

@app.get("/app")
async def legacy_app_route() -> RedirectResponse:
    """Backwards-compatible redirect from /app to /."""
    return RedirectResponse(url="/", status_code=307)


@app.get("/install")
async def install_page_redirect() -> RedirectResponse:
    """Route install landing traffic into the in-app install panel."""
    return RedirectResponse(url="/#install", status_code=307)


@app.get("/install.sh")
async def install_script() -> PlainTextResponse:
    """Return the checked-in installer script from template/install.sh."""
    script_path = template_root / "install.sh"
    if not script_path.exists() or not script_path.is_file():
        raise HTTPException(status_code=404, detail="install script not found")
    try:
        script_text = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"failed to read install script: {exc}") from exc
    return PlainTextResponse(content=script_text)


@app.get("/downloads/agent/latest", response_model=None)
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


async def proxy_rust_get(path: str, *, params: dict | None = None) -> dict:
    """Proxy a GET request to the Rust ingest server and return parsed JSON."""
    url = f"{settings.rust_ingest_base_url}{path}"
    try:
        async with httpx.AsyncClient(timeout=settings.rust_request_timeout_s) as client:
            response = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"rust ingest unreachable: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"rust ingest error: {response.text}",
        )
    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="invalid JSON from rust ingest") from exc


async def check_rust_health() -> bool:
    """Return True when Rust ingest health endpoint responds with status=ok."""
    try:
        payload = await proxy_rust_get("/health")
        return payload.get("status") == "ok"
    except HTTPException:
        return False


class CompileRequest(BaseModel):
    """Request body for triggering the OIL compiler."""

    source: str | None = Field(
        default=None,
        description="Inline OIL source. If provided, compiler runs on a temp file.",
    )
    source_path: str | None = Field(
        default=None,
        description="Path to existing .oil file on disk.",
    )
    mode: Literal["check", "ast", "mir", "runtime-ir", "cypher", "codegen"] = Field(
        default="runtime-ir"
    )
    emit_runtime_ir: str | None = Field(
        default=None,
        description="Optional output path for --emit-runtime-ir artifact JSON.",
    )


@app.get("/health")
async def health() -> dict:
    """Control-plane health with downstream Rust ingest reachability."""
    rust_ok = await check_rust_health()
    return {
        "status": "ok",
        "service": "control-plane",
        "rust_ingest": {
            "reachable": rust_ok,
            "base_url": settings.rust_ingest_base_url,
        },
    }


@app.get("/api/v1/control/status")
async def control_status() -> dict:
    """Composite control status for UI/system checks."""
    rust_ok = await check_rust_health()
    return {
        "control_plane": {"status": "ok"},
        "rust_ingest": {
            "status": "online" if rust_ok else "offline",
            "base_url": settings.rust_ingest_base_url,
        },
        "compiler": {
            "oilc_manifest_path": settings.oilc_manifest_path,
            "manifest_exists": Path(settings.oilc_manifest_path).exists(),
        },
    }


@app.get("/api/v1/ingest/stats")
@app.get("/api/v1/dashboard/ingest/stats")
async def ingest_stats_proxy() -> dict:
    """Dashboard-facing proxy for ingest stats."""
    return await proxy_rust_get("/api/v1/ingest/stats")


@app.get("/api/v1/ingest/summary")
@app.get("/api/v1/dashboard/ingest/summary")
async def ingest_summary_proxy() -> dict:
    """Dashboard-facing proxy for ingest summary."""
    return await proxy_rust_get("/api/v1/ingest/summary")


@app.get("/api/v1/ingest/recent")
@app.get("/api/v1/dashboard/ingest/recent")
async def ingest_recent_proxy(limit: int = Query(default=100, ge=1, le=5000)) -> dict:
    """Dashboard-facing proxy for recent ingest rows."""
    return await proxy_rust_get("/api/v1/ingest/recent", params={"limit": limit})


@app.post("/api/v1/control/compiler/compile")
async def compile_oil(req: CompileRequest) -> dict:
    """Trigger `oilc` from Python control-plane and return process output."""
    if not req.source and not req.source_path:
        raise HTTPException(
            status_code=400,
            detail="provide either `source` or `source_path`",
        )

    manifest = Path(settings.oilc_manifest_path)
    if not manifest.exists():
        raise HTTPException(
            status_code=500,
            detail=f"oilc manifest not found: {manifest}",
        )

    tmp_path: Path | None = None
    source_path: Path
    if req.source_path:
        source_path = Path(req.source_path)
        if not source_path.exists():
            raise HTTPException(status_code=400, detail=f"source_path not found: {source_path}")
    else:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".oil",
            prefix="olopa-control-",
            delete=False,
        ) as tmp:
            tmp.write(req.source or "")
            tmp_path = Path(tmp.name)
        source_path = tmp_path

    cmd = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(manifest),
        "--",
        "--source",
        str(source_path),
        "--mode",
        req.mode,
        "--diagnostics-format",
        "json",
    ]
    if req.emit_runtime_ir:
        cmd.extend(["--emit-runtime-ir", req.emit_runtime_ir])

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=settings.compiler_timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail=f"compile timeout: {exc}") from exc
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    stdout_json = None
    try:
        stdout_json = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        stdout_json = None

    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "command": cmd,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_json": stdout_json,
    }
