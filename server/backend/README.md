# Olopa Platform Backend (FastAPI + ClickHouse)

FastAPI backend for:
- landing/waitlist API
- telemetry ingest API for Rust Aya eBPF agents
- ClickHouse-backed event queries (exec/file/net/heartbeats)

## Code structure

- `app/main.py`: FastAPI app bootstrap + lifespan wiring
- `app/config.py`: environment-backed settings
- `app/core/`: shared DB/security helpers
- `app/api/v1/`: API routes (waitlist + telemetry)
- `app/schemas/`: request/response models
- `app/services/telemetry/store.py`: ClickHouse persistence layer
- `app/services/telemetry/runtime.py`: ingest queue/backpressure/flush runtime

Compatibility wrappers remain in:
- `app/services/clickhouse_store.py`
- `app/services/ingest_runtime.py`

## Setup

```bash
cd server/backend
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
cp .env.example .env
```

## Run

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Core Endpoints

- `GET /health`
- `POST /api/v1/waitlist`
- `GET /api/v1/waitlist/count`
- `POST /api/v1/ingest/batches`
- `GET /api/v1/ingest/stats`
- `GET /api/v1/events/exec?tenant_id=...&host_id=...&limit=200`
- `GET /api/v1/events/file?tenant_id=...`
- `GET /api/v1/events/net?tenant_id=...`
- `GET /api/v1/events/heartbeats?tenant_id=...`

## Environment Variables

| Variable | Default |
|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./olopa_waitlist.db` |
| `CORS_ORIGINS` | `*` |
| `WAITLIST_RATE_LIMIT_PER_HOUR` | `5` |
| `CLICKHOUSE_URL` | `http://localhost:8123` |
| `CLICKHOUSE_USERNAME` | `default` |
| `CLICKHOUSE_PASSWORD` | *(empty)* |
| `CLICKHOUSE_DATABASE` | `default` |
| `CLICKHOUSE_SECURE` | `false` |
| `INGEST_QUEUE_MAXSIZE` | `2000` |
| `INGEST_FLUSH_INTERVAL_MS` | `250` |
| `INGEST_FLUSH_MAX_ROWS` | `10000` |
| `INGEST_DEFAULT_RETRY_AFTER_MS` | `500` |
| `INGEST_SUGGESTED_BATCH_BYTES` | `4000000` |
| `TELEMETRY_ENABLED` | `true` |

## Sample Telemetry Ingest Payload

```json
{
  "tenant_id": "acme",
  "host_id": "host-01",
  "schema_version": 1,
  "process_exec_events": [
    {
      "pid": 1042,
      "tgid": 1042,
      "uid": 0,
      "gid": 0,
      "comm": "bash",
      "filename": "/usr/bin/bash"
    }
  ]
}
```
