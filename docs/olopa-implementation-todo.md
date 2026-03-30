# Olopa Implementation TODO

Actionable TODO derived from the current codebase state (agent, oilc, app/server, web).

## P0 - End-to-End Runtime Path (Ship First)

- [x] Replace `SimpleSender` with a real transport client from agent -> server.
  - Implemented in `agent/src/http_sender.rs` using HTTP POST to `/api/v1/ingest/batches`.
- [x] Unify wire schema between agent output and server ingest API (v1 adapter).
  - Agent payloads are now translated into server `IngestBatchRequest` JSON.
  - Follow-up: replace adapter parsing with a strict shared schema crate.
- [x] Replace server `persist_placeholder(...)` with real persistence (ClickHouse/Kafka path).
  - Implemented durable JSONL persistence in `app/server/src/telemetry.rs`.
  - Added optional ClickHouse HTTP sink (`INGEST_CLICKHOUSE_URL`) with JSONL fallback on insert failure.
  - Follow-up: add Kafka/queue fanout for decoupled high-throughput ingest.
- [x] Keep runtime-IR execution as the default path and fail loudly on schema mismatch.
  - Agent now fails startup when runtime-ir load/schema validation fails.
  - `SimpleRuleEngine` fallback is now opt-in only via `OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1`.

## P1 - Rule Engine and Compiler Correctness

- [ ] Lower MIR expressions beyond `MirExpr::Raw(...)` into executable ops.
- [ ] Expand runtime evaluator coverage for currently unsupported expression kinds.
- [ ] Replace hardcoded/special-case field semantics with generic typed field resolution.
  - Progress: domain/IP comparisons now use a generic typed comparator (no `.domain`-only special case).
  - Remaining: move field lookup/path aliasing itself to typed schema metadata instead of hardcoded matcher branches.
- [ ] Complete parser semantics for currently partial/unsupported top-level forms (`template`, `policy`) and remaining clause semantics.
- [ ] Fix flaky/failing EPL shared-object generation test (`generated_epl_shared_object_is_built`).
- [ ] Complete EPL generated FFI payload decode path (currently TODO in generated source).

## P2 - Kernel/Data Plane Hardening

- [ ] Implement TC egress policy enforcement path (beyond pass-through).
- [ ] Implement XDP threat policy logic (beyond pass-and-count).
- [ ] Emit/consume TC telemetry events where required for rule evaluation.
- [ ] Replace single global graph delta mutex with per-thread/per-core delta buffers.
- [ ] Improve graph merge path for production contention and memory behavior.

## P3 - Product Integration

- [ ] Wire web app panels to real backend data sources (currently static/demo-driven UI).
- [ ] Add API authn/authz and tenancy checks for ingest/stats endpoints.
- [ ] Add end-to-end integration tests: `oilc -> runtime-ir artifact -> agent eval -> server ingest`.
- [ ] Add CI workflows for deterministic checks/tests across `oilc`, `agent`, and `app/server`.
- [ ] Add observability surface: metrics/traces/log correlation across compiler, agent, server.

## P4 - Platform Targets (Roadmap Features)

- [ ] Integrate Memgraph-trigger execution path where required by graph rules.
- [ ] Add rule package/version lifecycle (load, reload, rollback) with compatibility checks.
