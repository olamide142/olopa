"""FastAPI control-plane server for dashboard/control/compiler workflows.

Design intent:
- Rust server stays on the ingest hot path (agent -> ingest).
- Python server orchestrates control workflows and dashboard aggregation.
- Dashboard read endpoints proxy to Rust ingest APIs for now.

Route organisation:
- routers.dashboard  /           app shell
- routers.landing    /landing    public marketing page, /install, /downloads
- routers.docs       /quickstart /agent/config /oil
- main               /health /api/v1/**  control-plane API
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel, Field

from .deps import settings, template_root
from .routers import dashboard, docs, landing


app = FastAPI(title="olopa-control-plane", version="0.1.0")
app.mount("/assets", StaticFiles(directory=str(template_root / "assets")), name="assets")

app.include_router(dashboard.router)
app.include_router(landing.router)
app.include_router(docs.router)


# ── Ingest proxy helpers ──────────────────────────────────────────────────────

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


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["api"])
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


# ── Control API ───────────────────────────────────────────────────────────────

@app.get("/api/v1/control/status", tags=["api"])
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


# ── Ingest proxies ────────────────────────────────────────────────────────────

@app.get("/api/v1/ingest/stats", tags=["api"])
@app.get("/api/v1/dashboard/ingest/stats", include_in_schema=False)
async def ingest_stats_proxy() -> dict:
    """Dashboard-facing proxy for ingest stats."""
    return await proxy_rust_get("/api/v1/ingest/stats")


@app.get("/api/v1/ingest/summary", tags=["api"])
@app.get("/api/v1/dashboard/ingest/summary", include_in_schema=False)
async def ingest_summary_proxy() -> dict:
    """Dashboard-facing proxy for ingest summary."""
    return await proxy_rust_get("/api/v1/ingest/summary")


@app.get("/api/v1/ingest/recent", tags=["api"])
@app.get("/api/v1/dashboard/ingest/recent", include_in_schema=False)
async def ingest_recent_proxy(limit: int = Query(default=100, ge=1, le=5000)) -> dict:
    """Dashboard-facing proxy for recent ingest rows."""
    return await proxy_rust_get("/api/v1/ingest/recent", params={"limit": limit})


# ── Compiler API ──────────────────────────────────────────────────────────────

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


@app.post("/api/v1/control/compiler/compile", tags=["api"])
async def compile_oil(req: CompileRequest) -> dict:
    """Trigger `oilc` from Python control-plane and return process output."""
    if not req.source and not req.source_path:
        raise HTTPException(status_code=400, detail="provide either `source` or `source_path`")

    manifest = Path(settings.oilc_manifest_path)
    if not manifest.exists():
        raise HTTPException(status_code=500, detail=f"oilc manifest not found: {manifest}")

    tmp_path: Path | None = None
    if req.source_path:
        source_path = Path(req.source_path)
        if not source_path.exists():
            raise HTTPException(status_code=400, detail=f"source_path not found: {source_path}")
    else:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".oil", prefix="olopa-control-", delete=False
        ) as tmp:
            tmp.write(req.source or "")
            tmp_path = Path(tmp.name)
        source_path = tmp_path

    cmd = [
        "cargo", "run", "--quiet",
        "--manifest-path", str(manifest),
        "--",
        "--source", str(source_path),
        "--mode", req.mode,
        "--diagnostics-format", "json",
    ]
    if req.emit_runtime_ir:
        cmd.extend(["--emit-runtime-ir", req.emit_runtime_ir])

    try:
        proc = subprocess.run(
            cmd, text=True, capture_output=True,
            timeout=settings.compiler_timeout_s, check=False,
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
        pass

    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "command": cmd,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_json": stdout_json,
    }
