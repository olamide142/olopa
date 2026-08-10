# Ingestion Server TODO (Current + Proposed)

## 1) Purpose

This document tracks the ingestion server status and roadmap.

It has two goals:

- capture what is already implemented in `app/ingest_server`,
- define structured future work with implementation procedures.

## 2) Service Scope

The ingestion server is the Rust HTTP ingest path for telemetry events.

Primary responsibilities:

- accept batched agent telemetry,
- apply bounded-queue backpressure,
- flush events to persistence,
- expose ingest operational read APIs.

## 3) Current Implementation (As Built)

### 3.1 Runtime and API

Implemented today:

- Axum server with tracing and graceful shutdown.
- Endpoints:
  - `GET /health`
  - `POST /api/v1/ingest/batches`
  - `GET /api/v1/ingest/stats`
  - `GET /api/v1/ingest/recent?limit=&tenant_id=`
  - `GET /api/v1/ingest/summary?tenant_id=`
- Token-based API auth (`Authorization: Bearer` or `x-api-key`) when `INGEST_API_TOKENS` is configured.
- Tenant-scoped authorization on ingest/read endpoints; global-scope only on stats endpoint.
- Single background worker drains a bounded `mpsc` queue.
- Flush is triggered by interval (`INGEST_FLUSH_INTERVAL_MS`) and row threshold (`INGEST_FLUSH_MAX_ROWS`).

### 3.2 Wire Schema and Backpressure

Implemented today:

- `IngestBatchRequest` supports `tenant_id`, `host_id`, `schema_version`, optional `batch_id`.
- Event families supported:
  - `process_exec_events`
  - `file_events`
  - `net_events`
  - `db_query_events` (schema version 2; optional for version 1 senders)
  - `agent_heartbeats`
- `ack_batch` returns `AckResponse` with:
  - `accepted`
  - `retry_after_ms`
  - `suggested_batch_bytes`
  - `throttle_ratio`
  - optional `message`

### 3.3 Persistence and Fallback

Implemented today:

- Row flattening to JSON envelope with shared metadata and `event_kind`.
- Persistence strategy:
  - SurrealDB HTTP SQL insert when `INGEST_SURREAL_URL` is configured,
  - ClickHouse HTTP fallback insert when `INGEST_CLICKHOUSE_URL` is configured,
  - JSONL fallback sink on downstream sink failure,
  - JSONL primary sink when both database sinks are disabled.
- Recent in-memory ring buffer and aggregate counters by kind/tenant/host.

### 3.4 Configuration and Ops Controls

Implemented today:

- Environment-driven typed config in `config.rs`.
- Queue, flush cadence, flush size, fallback path, and sink timeouts are configurable.
- ClickHouse and SurrealDB connection/auth settings are configurable via environment variables.
- API tokens and tenant scopes are configurable via `INGEST_API_TOKENS`.
- Stats counters include queue depth, accepted/rejected, flushed, failed flushes, last flush timestamp.

### 3.5 Test Coverage Baseline

Implemented today:

- Unit/integration-style tests in `telemetry.rs` cover:
  - queue acceptance and rejection,
  - worker flush behavior,
  - row flattening across event families,
  - recent rows and summary population,
  - tenant-scoped recent/summary filtering,
  - Surreal SQL generation and Surreal error parsing.
- Unit tests in `main.rs` and `config.rs` cover auth token parsing and tenant scope behavior.
- Current local test result: 13/13 passing.

## 4) Current Gaps

Not implemented yet:

- advanced identity integration beyond static API tokens (for example mTLS identity binding, token rotation/revocation),
- request size/rate limiting safeguards,
- idempotency and duplicate suppression using `batch_id`,
- durable pre-flush spool/WAL for crash recovery,
- retry policy and circuit-breaker logic for ClickHouse,
- Prometheus/OpenTelemetry metrics/traces,
- strict CORS policy (currently permissive),
- readiness endpoint with dependency checks,
- multi-worker/sharded flush pipeline for higher throughput.

## 5) Future Proposed Work

### Phase 0: Safety and Access Baseline

Objective:

- secure ingestion APIs and harden request boundaries before scale work.

#### Epic 0.1 Authn/Authz/Tenancy

Implementation procedure:

1. Add auth middleware (service token or mTLS identity binding).
2. Enforce tenant scoping from verified identity claims.
3. Reject mismatched tenant claims and payload tenant ids.
4. Add audit logging for auth failures and denied requests.

Done criteria:

- all non-health endpoints require authenticated identity,
- tenant spoofing attempts are rejected and tested.

Current status:

- token auth + tenant scope enforcement is implemented,
- remaining work is mTLS/identity binding and richer auth failure audit telemetry.

#### Epic 0.2 Input and Abuse Controls

Implementation procedure:

1. Add max request body size and per-event-family count limits.
2. Add per-tenant and per-host rate limiting.
3. Validate required fields and bounded string lengths.
4. Return consistent error envelope and reason codes.

Done criteria:

- oversized or malformed payloads are safely rejected,
- abuse limits are measurable and configurable.

#### Epic 0.3 Operational Hardening

Implementation procedure:

1. Replace permissive CORS with allow-list configuration.
2. Add `GET /ready` with queue and sink dependency checks.
3. Add explicit shutdown drain timeout.
4. Add structured error classifications for persistence failures.

Done criteria:

- runtime exposes clear liveness/readiness semantics,
- ingress security defaults are production-safe.

### Phase 1: Delivery Guarantees and Data Integrity

Objective:

- improve correctness under retries, restarts, and downstream outages.

#### Epic 1.0 DB Query Event Family Support

Implementation procedure:

1. Extend ingest wire schema with `db_query_events` (versioned, backwards compatible).
2. Define normalized DB event shape (`db_engine`, `db_server`, `database`, `operation`, `tables`, `statement_fingerprint`).
3. Persist DB query rows with explicit `event_kind` and summary counters.
4. Add compatibility tests for mixed old/new batch payloads.

Done criteria:

- ingest accepts and stores DB query telemetry without breaking existing senders,
- query-event rows are visible in `recent` and `summary` APIs.

Current status:

- steps 1, 3, and 4 are implemented; rows persist as `event_kind = "db_query"`
  and appear in `recent`/`summary`,
- the agent alert wire is at version 2, carrying statement hash, class, port,
  and process name end to end (`agent/agent/src/agent.rs`),
- step 2 is met: `db_engine`, `db_server`, `operation`, `statement_fingerprint`,
  `database`, and `tables` are all populated. The uprobe now copies statement
  text out (`SqlEvent::query`, 128 bytes), and the agent redacts it before
  deriving anything from it (`agent/agent/src/sql_norm.rs`). Raw text never
  leaves the decode scope, so no literal reaches ingest.

Two properties of that path are worth keeping in mind when changing it:

- `statement_fingerprint` is now the hash of the *redacted* statement, so the
  same query shape groups regardless of its literal values. The raw-text hash
  is retained as the `raw_statement_hash` attribute for continuity with rows
  written before this change,
- `database` is only reported when every qualified table reference in the
  statement agrees on it. A cross-database join yields `null` rather than an
  arbitrary pick,
- prepared statements report one row per *execution*, not per prepare. The
  agent records statement text at `PQprepare`/`mysql_stmt_prepare` and replays
  it at execute time, so `tables` is populated even though the execute call
  never carries SQL. An execute whose prepare was not observed still produces a
  row, with `tables` empty and `statement_fingerprint` `"00000000"` — a zero
  fingerprint is the explicit marker for "statement text unknown".

#### Epic 1.1 Idempotency and Deduplication

Implementation procedure:

1. Introduce idempotency key contract based on `tenant_id + host_id + batch_id`.
2. Persist dedup ledger with TTL.
3. Return idempotent ACK for duplicate batches.
4. Add tests for replay and duplicate submission scenarios.

Done criteria:

- duplicate batches no longer cause duplicate stored rows,
- replay behavior is deterministic.

#### Epic 1.2 Durable Spool Before Sink

Implementation procedure:

1. Add local WAL/spool for accepted batches before async processing.
2. Mark checkpoint after successful SurrealDB/ClickHouse/JSONL persistence.
3. Rehydrate pending spool items on restart.
4. Add corruption handling and quarantine path.

Done criteria:

- accepted data survives process crash/restart,
- replay from spool is verified in tests.

#### Epic 1.3 Sink Retry and Circuit Breaker

Implementation procedure:

1. Add exponential backoff retry policy for ClickHouse inserts.
2. Add circuit breaker states and cooldown.
3. Route to JSONL fallback while circuit is open.
4. Surface sink state in stats/readiness endpoints.

Done criteria:

- transient sink failures do not cause sustained ingest collapse,
- sink behavior is observable and predictable.

### Phase 2: Throughput and Scalability

Objective:

- increase sustained ingest capacity and control tail latency.

#### Epic 2.1 Worker Parallelism and Sharding

Implementation procedure:

1. Add configurable worker pool size.
2. Partition batches by tenant/host key to preserve ordering where needed.
3. Use per-shard pending buffers and independent flush clocks.
4. Add benchmarks for throughput and p95/p99 latency.

Done criteria:

- higher throughput with bounded latency under load,
- no cross-tenant starvation.

#### Epic 2.2 ClickHouse Path Optimization

Implementation procedure:

1. Formalize table schema and partitioning strategy.
2. Batch insert tuning (`max_rows`, `max_bytes`, timeout).
3. Add optional compression and tuned HTTP transport settings.
4. Add ingest error table and write-failure telemetry rows.

Done criteria:

- ClickHouse ingest path meets target throughput/SLO,
- ingestion failures are queryable historically.

#### Epic 2.3 Backpressure Policy Maturity

Implementation procedure:

1. Add explicit overload mode and 429 semantics option.
2. Calibrate `retry_after_ms` and suggested batch sizing by queue pressure.
3. Add adaptive throttling per tenant and global safety cap.
4. Publish backpressure contract for agent senders.

Done criteria:

- backpressure is stable and reduces overload amplification,
- sender behavior converges under pressure tests.

### Phase 3: Product and Ecosystem Integration

Objective:

- make ingestion observability and control-plane integration production complete.

#### Epic 3.1 Observability Surface

Implementation procedure:

1. Add Prometheus metrics endpoint.
2. Add OpenTelemetry trace propagation and spans.
3. Add request correlation ids and sink operation correlation.
4. Add SLO dashboards and alert thresholds.

Done criteria:

- ingest pipeline is debuggable end-to-end during incidents,
- SLOs are measured and alertable.

#### Epic 3.2 Query/API Expansion

Implementation procedure:

1. Add filters for recent/summary by tenant, host, and time window.
2. Add pagination cursors for recent rows.
3. Add top-k aggregations for common dashboard use cases.
4. Keep read APIs compatibility for control-plane proxy endpoints.

Done criteria:

- control plane and dashboard can query ingest data without ad-hoc transformations.

#### Epic 3.3 Integration and E2E Validation

Implementation procedure:

1. Add end-to-end test path: `agent -> ingest_server -> storage -> control_plane proxy`.
2. Add compatibility tests for schema-version evolution.
3. Add CI workflows to run ingest tests with optional ClickHouse container.
4. Add release checklist for config and migration compatibility.

Done criteria:

- integration regressions are caught automatically,
- release confidence is based on E2E coverage.

## 6) Proposed Work Checklist

- [ ] Authn/authz/tenant enforcement for ingest endpoints
- [ ] Request size and rate limiting
- [ ] Idempotency and deduplication ledger
- [ ] Durable spool/WAL and restart replay
- [ ] ClickHouse retry/circuit breaker
- [ ] Multi-worker sharded flush architecture
- [ ] Prometheus and OpenTelemetry instrumentation
- [ ] Readiness endpoint with dependency checks
- [ ] CORS allow-list and API hardening
- [ ] Expanded query filters and pagination
- [ ] Ingest-to-control-plane E2E integration tests
- [ ] CI pipeline with load/perf smoke tests

## 7) Immediate Next Sprint

1. Implement ingest auth + tenant claim enforcement.
2. Add payload size/event-count limits and standardized errors.
3. Add idempotency handling using `batch_id`.
4. Add readiness endpoint and sink health reporting.
5. Add Prometheus metrics for queue, flush, and sink failures.
