# Olopa Server Implementation Plan

## Scope

This plan covers only two services:

1. Rust ingest server (`app/ingest_server`)
2. Python control plane (`app/control_plane`)

SurrealDB is the primary graph + inference store. ClickHouse remains optional fallback compatibility on ingest until Surreal-only durability and performance are proven.

## Non-Goals (for now)

- Native `.so` rule execution and dynamic shared-library loading
- Replacing runtime-IR with another rule runtime
- Full multi-cluster federation

## Current Baseline (as of 2026-04-04)

Implemented already:

- HTTP ingest/read APIs in Rust with a bounded, partitioned flush pipeline
- Token auth + tenant scoping on ingest/read endpoints
- Persistence chain: SurrealDB (optional) -> ClickHouse (optional fallback) -> JSONL
- In-memory recent/summary indexes by tenant/host/kind
- Fsynced pre-acknowledgement WAL, restart replay, persistent idempotency, and safe compaction
- Request/rate limits, restricted CORS, production auth validation, readiness, and Prometheus metrics
- Jittered sink retries, circuit breakers, JSONL fallback, and dead-letter persistence

Known gaps still open:

- managed sink schema migrations and version gates
- OpenTelemetry trace export across ingest and control-plane calls
- end-to-end control-plane integration
- optional Kafka fan-out if future load tests justify it

---

## Target Architecture (Two-Server Boundary)

### Rust Ingest Server Owns

- ingest API and backpressure
- schema validation + normalization
- runtime-IR rule evaluation for hot-path detections
- durable telemetry persistence into SurrealDB
- alert stream to Python control plane

### Python Control Plane Owns

- graph/temporal detections requiring cross-host context
- GNN inference orchestration and model lifecycle
- fusion of signals (runtime-IR + graph + GNN)
- operator APIs (REST/WS), case workflows, routing
- watch/predicate push-down requests to Rust server

### Shared Contract

- SurrealDB schema + IDs + edge semantics
- alert envelope schema
- correlation keys (`tenant_id`, `host_id`, `entity_id`, `batch_id`)

---

## Delivery Principles

- Keep ingest hot path non-blocking on downstream analytics.
- Prefer at-least-once delivery + explicit dedup over implicit data loss.
- Add feature flags for each new path (`surreal_live_queries`, `gnn_inference`, `predicate_pushdown`).
- Every phase must include test additions + rollback strategy.

---

## Phase-by-Phase Plan

## Phase 0 - Ingest Safety and Contract Hardening

Goal: make current ingest reliable enough for downstream graph + ML work.

### Rust tasks

1. Add request/body safety controls.
   - Max request bytes
   - Max event count per family per batch
   - Strict field length/enum validation
2. Add per-tenant and per-host rate limiting.
   - Token bucket per principal
   - Clear `429`/throttle response contract
3. Add idempotency/dedup.
   - Key: `tenant_id + host_id + batch_id`
   - TTL cache + replay-safe ACK semantics
4. Add `GET /ready` with sink health and queue status.

### Python tasks

1. No major runtime additions; create basic health integration checks against Rust `/health` and `/ready`.

### Exit criteria

- Malformed or oversized payloads are rejected deterministically.
- Duplicate batch replay does not duplicate persisted rows.
- Rate-limit behavior is test-covered and observable.
- `/ready` reflects sink degradation states.

---

## Phase 1 - SurrealDB-First Durable Ingest

Goal: make SurrealDB the first-class storage path without losing fallback safety.

### Rust tasks

1. Formalize Surreal schema bootstrap/migration module.
   - tables, edge records, indexes
   - version marker (`schema_version` table)
2. Introduce durable WAL/spool before sink commit.
   - append accepted batches to local WAL
   - checkpoint only after successful sink write
   - replay on restart
3. Improve sink reliability controls.
   - retry with exponential backoff + jitter
   - sink circuit-breaker states
   - fallback order: Surreal -> ClickHouse -> JSONL
4. Add sink metrics.
   - per-sink success/failure/latency
   - queue depth and flush latency histograms

### Python tasks

1. Add Surreal connection pool + schema version check at startup.
2. Read-only baseline APIs for events/summary/health from Surreal.

### Exit criteria

- Crash/restart no longer loses ACKed data.
- Surreal sink failures do not collapse ingest throughput.
- Sink health and fallback behavior are visible in metrics and readiness.

---

## Phase 2 - Graph Model and Correlation Foundation

Goal: represent process/file/network activity as stable graph entities for cross-endpoint detection.

### Rust tasks

1. Normalize persistent entity IDs.
   - process, endpoint, file, host IDs deterministic per tenant scope
2. Write graph edges with dedup semantics.
   - avoid unbounded duplicate `RELATE` growth
   - use upsert/merge logic per edge key/time bucket
3. Add graph-ready event projection.
   - preserve raw event JSON
   - also write normalized graph projection fields

### Python tasks

1. Build graph query module with tested SurrealQL templates.
2. Add first correlation jobs:
   - suspicious spawn -> outbound connection
   - sensitive file access -> external egress
3. Build correlation cache keyed by entity/time window.

### Exit criteria

- Cross-host and cross-event correlations run from Python using Surreal graph data.
- Query latency and correctness meet baseline SLO in staging.
- Edge cardinality remains bounded under load tests.

---

## Phase 3 - Real-Time Signal Plane (Alerts + Streaming)

Goal: operationalize near-real-time detection loop between Rust and Python.

### Rust tasks

1. Add outbound alert stream API to control plane.
   - durable cursor/offset or replay window
   - lag detection and reconnect semantics
2. Emit runtime-IR detections as typed alert envelopes.
3. Optional: register limited Surreal live queries from Rust only for deterministic IOC patterns (feature-flagged).

### Python tasks

1. Implement alert receiver with reconnect + replay.
2. Build detection orchestrator that merges:
   - runtime-IR alerts from Rust
   - graph correlation signals from Python
3. Add dedup and suppression policy.

### Exit criteria

- No alert loss across transient disconnects (within replay window).
- Duplicate alerts are collapsed consistently.
- Alert latency from ingest to control plane is measured and within target.

---

## Phase 4 - GNN Integration (Assistive, Not Blocking)

Goal: introduce ML scoring as enrichment without making ingest correctness depend on ML.

### Python tasks

1. Build subgraph extractor from Surreal for `k`-hop neighborhoods.
2. Implement inference scheduler with concurrency + budget controls.
3. Add model scoring pipeline.
   - input feature transform
   - model inference
   - confidence calibration
4. Persist inference artifacts.
   - `gnn_score`, `gnn_label`, `gnn_ts`, optional embedding
5. Add adaptive thresholding and FP guardrails.

### Rust tasks

1. No mandatory hot-path change; only consume watch/predicate updates from Python if enabled.

### Exit criteria

- GNN signals appear as secondary confidence modifiers.
- Turning GNN off does not break detection pipeline.
- Precision/recall and alert-volume impact are observable.

---

## Phase 5 - Predicate Push-Down and Adaptive Telemetry

Goal: close the loop from high-level detection to focused data capture.

### Python tasks

1. Send watch predicates for risky entities with TTL and reason.
2. Keep audit trail of push-down actions.

### Rust tasks

1. Accept predicate updates via authenticated internal API.
2. Apply watch predicates to runtime filtering / telemetry fidelity controls.
3. Enforce expiration and capacity limits on active predicates.

### Exit criteria

- High-risk entities receive elevated telemetry coverage within seconds.
- Push-down path is auditable, bounded, and reversible.

---

## Phase 6 - Production Hardening and Scale

Goal: make the two-server system reliable under sustained attack load.

### Rust tasks

1. Multi-worker ingest sharding (tenant/host partitioning).
2. Memory/cpu guardrails and overload policy tiers.
3. Load tests for p95/p99 ingest latency + loss/dup guarantees.

### Python tasks

1. Horizontal worker model for orchestrator and background jobs.
2. Backfill/reindex tooling for Surreal schema upgrades.
3. Model drift monitoring and rollback automation.

### Exit criteria

- SLOs are met under defined load profile.
- Operational playbooks exist for sink outage, replay backlog, and model rollback.

---

## Cross-Phase Interfaces (Must Be Versioned)

1. Ingest batch schema (`schema_version`)
2. Alert envelope schema (`alert_version`)
3. Predicate push-down contract (`predicate_version`)
4. Surreal graph schema version (`graph_schema_version`)

Any incompatible change requires dual-read/dual-write transition for at least one phase.

---

## Suggested Immediate Execution Order (Next 4 Weeks)

1. Phase 0.1/0.2: request limits + rate limiting
2. Phase 0.3: idempotency + dedup
3. Phase 1.1/1.2: WAL/spool + replay
4. Phase 1.3: retry/circuit-breaker + readiness sink health
5. Phase 2.1: graph ID normalization + edge dedup strategy

This sequence de-risks data correctness first, then unlocks graph/GNN safely.
