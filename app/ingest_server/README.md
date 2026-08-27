# Olopa Ingest Server

The Olopa ingest server (`olopa-ingest`) is a high-throughput, durable ingestion and real-time stream correlation gateway for endpoint telemetry.

## Architecture

The server combines two core functions in a single service:

1. **Durable Ingest Hot Path**:
   - Accepts compressed, batched telemetry (`POST /api/v1/ingest/batches`).
   - Fsyncs incoming batches to a Write-Ahead Log (`WAL`) before acknowledging.
   - Applies partitioned worker queues with bounded memory backpressure.
   - Flushes rows to **SurrealDB** (primary graph/relational store), with **ClickHouse** HTTP fallback and local **JSONL** fallback.
   - Persistent idempotency snapshot by `(tenant_id, host_id, batch_id)`.

2. **Central Multi-Source Stream Correlation Engine**:
   - Evaluates compiled OIL rules (`RuntimeProgram` from `oilc --emit-runtime-ir`) in near-real-time as telemetry streams through the ingest pipeline.
   - **Vectorized Filter Masks**: Zero-allocation 64-bit word bitsets to quickly eliminate non-matching rules across large event batches.
   - **Sharded Sliding Window Index**: 32-shard concurrent ring-buffered window index supporting multi-source joins (`correlate ... within 10m`) and `around` entity windows.
   - **Central Novelty & Baseline State**: 16-shard lock-striped frequency sketches for `rare()`, `unusual()`, and sliding `rate()` across multi-agent clusters.
   - **Central Fact / Intel Store**: Cross-host fact emitter (`emit fact ... expires`) and matcher (`has_fact(...)`), enabling multi-agent attack campaign detection.

---

## Configuration & Environment Variables

Production deployments should configure:

```bash
# General & Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
INGEST_PRODUCTION_MODE=true
INGEST_API_TOKENS=<token>[:tenant-a|tenant-b]
INGEST_CORS_ALLOWED_ORIGINS=https://console.example.com

# Durability & Sinks
INGEST_WAL_PATH=/var/lib/olopa/ingest/acceptance.wal
INGEST_DEDUPE_PATH=/var/lib/olopa/ingest/dedupe.json
INGEST_PERSIST_JSONL_PATH=/var/lib/olopa/ingest/events.jsonl
INGEST_DEAD_LETTER_PATH=/var/lib/olopa/ingest/dead-letter.jsonl
INGEST_SURREAL_URL=http://127.0.0.1:8000/sql
INGEST_SURREAL_NAMESPACE=olopa
INGEST_SURREAL_DATABASE=events
INGEST_SURREAL_TABLE=events_raw

# Stream Correlation Engine
INGEST_CORRELATION_ENABLED=true
INGEST_CORRELATION_RULES_PATH=/etc/olopa/runtime-ir.json
INGEST_CORRELATION_WINDOW_MAX_ENTRIES=10000
INGEST_CORRELATION_ALERTS_MAX=5000

# Performance & Rate Limiting
INGEST_MAX_REQUEST_BODY_BYTES=8388608
INGEST_RATE_LIMIT_PER_SECOND=200
INGEST_RATE_LIMIT_BURST=400
INGEST_QUEUE_MAXSIZE=2000
INGEST_FLUSH_WORKERS=4
INGEST_FLUSH_MAX_ROWS=10000
INGEST_FLUSH_INTERVAL_MS=250
```

---

## API Endpoints

### Telemetry Ingest & Storage
* `POST /api/v1/ingest/batches`: Ingest telemetry batch with backpressure hints.
* `GET /api/v1/ingest/stats`: Operational queue depth and flush metrics.
* `GET /api/v1/ingest/recent?limit=&tenant_id=`: Query recently flushed telemetry rows.
* `GET /api/v1/ingest/summary?tenant_id=`: Aggregate event counters by kind, tenant, and host.

### Stream Correlation & Intelligence
* `GET /api/v1/correlate/stats`: Performance metrics (active rules, events evaluated, matches, active window entries).
* `GET /api/v1/correlate/alerts?limit=&tenant_id=&severity=&rule_id=`: Retrieve recent correlated alerts.
* `POST /api/v1/correlate/rules`: Hot-reload or register `RuntimeProgram` rules JSON.
* `GET /api/v1/correlate/rules`: Inspect active correlation rules.
* `GET /api/v1/correlate/facts?tenant_id=`: Query active cluster facts in the central intel store.

### Health & Observability
* `GET /health`: Liveness probe.
* `GET /ready`: Readiness probe checking queue, WAL, worker, and sink circuit states.
* `GET /metrics`: Prometheus metrics (requires global-scope auth token when auth is enabled).

