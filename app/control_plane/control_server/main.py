"""FastAPI control-plane server for dashboard/control/compiler workflows.

Design intent:
- Rust server stays on the ingest hot path (agent -> ingest).
- Python server orchestrates control workflows and dashboard aggregation.
- Dashboard read endpoints proxy to Rust ingest APIs for now.

Route organisation:
- routers.dashboard    /           app shell
- routers.landing      /landing    public marketing page, /install, /downloads
- routers.docs         /quickstart /agent/config /oil
- routers.auth         /api/v1/auth/**
- routers.audit        /api/v1/audit/**
- routers.rules        /api/v1/rules/**
- routers.deployments  /api/v1/deployments/**
- secure_connect       /api/v1/secure-connect/**  managed WireGuard orchestration
- main                 /health /api/v1/**  control-plane API
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
import subprocess
import tempfile
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Query, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
import httpx
from pydantic import BaseModel, Field

from .db import init_db
from .auth import RequestContext
from .deps import settings, template_root
from .rbac import require_analyst, require_operator, require_viewer
from .routers import dashboard, docs, landing, auth, audit, rules, deployments
from .secure_connect.router import router as secure_connect_router
from .secure_connect.worker import run_maintenance_loop as run_secure_connect_maintenance

try:
    from app.intel_sync.sync import run_loop, run_sync
except ModuleNotFoundError:
    run_loop = None
    run_sync = None

logger = logging.getLogger("control_plane")


# -- Intel sync background task ------------------------------------------------

_intel_sync_thread: threading.Thread | None = None


def _start_intel_sync_daemon() -> None:
    """Start the intel feed sync daemon in a background thread."""
    global _intel_sync_thread
    if run_loop is None:
        logger.warning(
            "intel-sync package is unavailable; background synchronization is disabled"
        )
        return
    intel_path = settings.__dict__.get("intel_path") or None  # optional setting
    t = threading.Thread(
        target=run_loop,
        args=(intel_path,),
        daemon=True,
        name="intel-sync",
    )
    t.start()
    _intel_sync_thread = t
    logger.info("intel-sync daemon thread started (pid-thread=%s)", t.ident)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite/SQLAlchemy schema on startup
    try:
        init_db()
        logger.info("Control plane database tables initialized.")
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc)

    _start_intel_sync_daemon()

    # Secure Connect session reaping and detection-stream risk subscription.
    secure_connect_task: asyncio.Task | None = None
    if settings.sc_worker_enabled:
        secure_connect_task = asyncio.create_task(
            run_secure_connect_maintenance(), name="secure-connect-worker"
        )

    try:
        yield
    finally:
        if secure_connect_task is not None:
            secure_connect_task.cancel()
            try:
                await secure_connect_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.warning("Secure Connect worker stopped with an error: %s", exc)


app = FastAPI(title="olopa-control-plane", version="0.1.0", lifespan=lifespan)

# -- Middleware for Request ID tracking ----------------------------------------

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["x-request-id"] = req_id
    return response


# -- Standardized Error Handlers -----------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    if isinstance(exc.detail, dict) and "code" in exc.detail:
        payload = exc.detail
        if "request_id" not in payload:
            payload["request_id"] = req_id
    else:
        payload = {
            "code": f"HTTP_{exc.status_code}",
            "message": str(exc.detail),
            "request_id": req_id,
        }
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "code": "VALIDATION_ERROR",
            "message": "Request payload validation failed",
            "details": exc.errors(),
            "request_id": req_id,
        },
    )


# -- Static assets and Router inclusion ---------------------------------------

app.mount("/assets", StaticFiles(directory=str(template_root / "assets")), name="assets")

_webdist = template_root.parent / "webdist"
if _webdist.is_dir():
    app.mount("/ui", StaticFiles(directory=str(_webdist)), name="ui")

app.include_router(dashboard.router)
app.include_router(landing.router)
app.include_router(docs.router)
app.include_router(auth.router)
app.include_router(audit.router)
app.include_router(rules.router)
app.include_router(deployments.router)
app.include_router(secure_connect_router)


# -- Ingest proxy helpers ------------------------------------------------------

async def proxy_rust_get(path: str, *, params: dict | None = None) -> dict:
    """Proxy a GET request to the Rust ingest server and return parsed JSON."""
    url = f"{settings.rust_ingest_base_url}{path}"
    headers = {}
    if settings.rust_ingest_api_token:
        headers["authorization"] = f"Bearer {settings.rust_ingest_api_token}"
    try:
        async with httpx.AsyncClient(timeout=settings.rust_request_timeout_s) as client:
            response = await client.get(url, params=params, headers=headers)
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


# -- Health --------------------------------------------------------------------

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


# -- Control API ---------------------------------------------------------------

@app.get("/api/v1/control/status", tags=["api"])
async def control_status(
    _ctx: RequestContext = Depends(require_viewer),
) -> dict:
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
            "oilc_binary_path": settings.oilc_binary_path or None,
            "binary_exists": bool(settings.oilc_binary_path)
            and Path(settings.oilc_binary_path).is_file(),
        },
    }


# -- Ingest proxies ------------------------------------------------------------

@app.get("/api/v1/ingest/stats", tags=["api"])
@app.get("/api/v1/dashboard/ingest/stats", include_in_schema=False)
async def ingest_stats_proxy(
    _ctx: RequestContext = Depends(require_viewer),
) -> dict:
    """Dashboard-facing proxy for ingest stats."""
    return await proxy_rust_get("/api/v1/ingest/stats")


@app.get("/api/v1/ingest/summary", tags=["api"])
@app.get("/api/v1/dashboard/ingest/summary", include_in_schema=False)
async def ingest_summary_proxy(
    ctx: RequestContext = Depends(require_viewer),
) -> dict:
    """Dashboard-facing proxy for ingest summary."""
    return await proxy_rust_get(
        "/api/v1/ingest/summary",
        params={"tenant_id": ctx.tenant_id},
    )


@app.get("/api/v1/ingest/recent", tags=["api"])
@app.get("/api/v1/dashboard/ingest/recent", include_in_schema=False)
async def ingest_recent_proxy(
    limit: int = Query(default=100, ge=1, le=5000),
    ctx: RequestContext = Depends(require_viewer),
) -> dict:
    """Dashboard-facing proxy for recent ingest rows."""
    return await proxy_rust_get(
        "/api/v1/ingest/recent",
        params={"limit": limit, "tenant_id": ctx.tenant_id},
    )


# -- Compiler API --------------------------------------------------------------

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


def _remove_temp_paths(*paths: Path | None) -> None:
    for path in paths:
        if path is None:
            continue
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("failed to remove compiler temporary file %s", path)


@app.post("/api/v1/control/compiler/compile", tags=["api"])
async def compile_oil(
    req: CompileRequest,
    _ctx: RequestContext = Depends(require_analyst),
) -> dict:
    """Trigger `oilc` from Python control-plane and return process output."""
    if bool(req.source) == bool(req.source_path):
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of `source` or `source_path`",
        )
    if req.emit_runtime_ir:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "UNSAFE_OUTPUT_PATH",
                "message": "Client-selected compiler output paths are not allowed",
            },
        )

    manifest = Path(settings.oilc_manifest_path)
    compiler_binary = (
        Path(settings.oilc_binary_path) if settings.oilc_binary_path else None
    )
    if compiler_binary is not None and not compiler_binary.is_file():
        raise HTTPException(
            status_code=500,
            detail=f"oilc binary not found: {compiler_binary}",
        )
    if compiler_binary is None and not manifest.exists():
        raise HTTPException(status_code=500, detail=f"oilc manifest not found: {manifest}")

    tmp_path: Path | None = None
    if req.source_path:
        if not settings.compiler_source_root:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "SOURCE_PATH_DISABLED",
                    "message": "Server-side source paths are disabled",
                },
            )
        source_root = Path(settings.compiler_source_root).resolve()
        try:
            source_path = Path(req.source_path).resolve(strict=True)
        except OSError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"source_path not found: {req.source_path}",
            ) from exc
        if not source_path.is_file() or not source_path.is_relative_to(source_root):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "SOURCE_PATH_FORBIDDEN",
                    "message": "source_path must be a file beneath CONTROL_COMPILER_SOURCE_ROOT",
                },
            )
    else:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".oil", prefix="olopa-control-", delete=False
        ) as tmp:
            tmp.write(req.source or "")
            tmp_path = Path(tmp.name)
        source_path = tmp_path

    cmd = (
        [str(compiler_binary)]
        if compiler_binary is not None
        else ["cargo", "run", "--locked", "--quiet", "--manifest-path", str(manifest), "--"]
    )
    cmd.extend([
        "--source", str(source_path),
        "--mode", req.mode,
        "--diagnostics-format", "json",
    ])

    runtime_ir_path: Path | None = None
    if req.mode == "runtime-ir":
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            prefix="olopa-control-runtime-ir-",
            delete=False,
        ) as artifact:
            runtime_ir_path = Path(artifact.name)
        cmd.extend(["--emit-runtime-ir", str(runtime_ir_path)])

    try:
        compiler_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                compiler_process.communicate(),
                timeout=settings.compiler_timeout_s,
            )
        except TimeoutError as exc:
            compiler_process.kill()
            await compiler_process.wait()
            _remove_temp_paths(tmp_path, runtime_ir_path)
            raise HTTPException(status_code=504, detail="oilc compilation timed out") from exc
        proc = subprocess.CompletedProcess(
            args=cmd,
            returncode=compiler_process.returncode,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
        )
    except HTTPException:
        raise
    except OSError as exc:
        _remove_temp_paths(tmp_path, runtime_ir_path)
        raise HTTPException(
            status_code=500,
            detail=f"failed to execute oilc: {exc}",
        ) from exc

    stdout_json = None
    try:
        stdout_json = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        pass

    runtime_ir_json = None
    if proc.returncode == 0 and runtime_ir_path is not None:
        try:
            runtime_ir_json = json.loads(runtime_ir_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("failed to read controlled runtime-ir artifact: %s", exc)

    _remove_temp_paths(tmp_path, runtime_ir_path)

    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "command": cmd,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_json": stdout_json,
        "runtime_ir": runtime_ir_json,
    }


# -- Intel feed API ------------------------------------------------------------

def _intel_path() -> str:
    """Resolve the intel.json output path from env / settings."""
    import os
    return os.environ.get("OLOPA_INTEL_PATH", "/etc/olopa/intel.json")


@app.post("/api/v1/intel/sync", tags=["api"])
async def intel_sync_now(
    _ctx: RequestContext = Depends(require_operator),
) -> dict:
    """Trigger an immediate threat-intel feed sync and return the result."""
    if run_sync is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "INTEL_SYNC_UNAVAILABLE",
                "message": "The intel-sync package is not installed in this deployment",
            },
        )
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, lambda: run_sync(_intel_path()))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"intel sync failed: {exc}") from exc
    return result.to_dict()


@app.get("/api/v1/intel/status", tags=["api"])
async def intel_status(
    _ctx: RequestContext = Depends(require_viewer),
) -> dict:
    """Return metadata from the current intel.json on disk."""
    path = Path(_intel_path())
    if not path.exists():
        return {
            "present": False,
            "path": str(path),
            "sync_available": run_sync is not None,
            "sync_daemon_running": _intel_sync_thread is not None and _intel_sync_thread.is_alive(),
        }

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"could not read intel.json: {exc}") from exc

    sets_meta = {
        name: {
            "type": s.get("type"),
            "count": s.get("count", 0),
            "description": s.get("description", ""),
        }
        for name, s in raw.get("sets", {}).items()
    }
    total_entries = sum(s["count"] for s in sets_meta.values())

    return {
        "present": True,
        "path": str(path),
        "version": raw.get("version"),
        "generated_at_unix_s": raw.get("generated_at_unix_s"),
        "sets": sets_meta,
        "total_entries": total_entries,
        "sync_available": run_sync is not None,
        "sync_daemon_running": _intel_sync_thread is not None and _intel_sync_thread.is_alive(),
    }
