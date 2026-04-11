# Olopa Python Control Plane

This service is the **Python control server** for:
- dashboard/control APIs,
- compiler trigger endpoints,
- orchestration workflows.

The Rust server remains the ingest hot path for:
- agent telemetry ingestion,
- ingest stats/recent/summary storage and retrieval.

## Why two servers

- Rust handles high-throughput ingest and low-latency telemetry operations.
- Python handles product/control workflows that need rapid iteration.

## Run

```bash
cd app/control_plane
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn control_server.main:app --host 0.0.0.0 --port 8100
```

## Environment

- `CONTROL_HOST` (default `0.0.0.0`)
- `CONTROL_PORT` (default `8100`)
- `RUST_INGEST_BASE_URL` (default `http://127.0.0.1:8000`)
- `RUST_REQUEST_TIMEOUT_S` (default `3.0`)
- `COMPILER_TIMEOUT_S` (default `20`)
- `OILC_MANIFEST_PATH` (default `<repo>/oilc/Cargo.toml`)

## Endpoints

- `GET /` (render `template/index.html`)
- `GET /app` (render `template/app.html`)
- `GET /health`
- `GET /api/v1/control/status`
- `GET /api/v1/ingest/stats` (proxy to Rust ingest)
- `GET /api/v1/ingest/summary` (proxy to Rust ingest)
- `GET /api/v1/ingest/recent?limit=100` (proxy to Rust ingest)
- `GET /api/v1/dashboard/ingest/*` (alias of ingest proxy endpoints)
- `POST /api/v1/control/compiler/compile`

### Compile endpoint body

```json
{
  "source": "rule \"x\" { ... }",
  "mode": "runtime-ir",
  "emit_runtime_ir": "/tmp/rule.json"
}
```

You can also pass `"source_path": "/abs/path/to/file.oil"` instead of inline source.
