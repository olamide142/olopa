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

- [x] Lower MIR expressions beyond `MirExpr::Raw(...)` into executable ops.
  - `MirExpr` now carries typed executable variants (logical/comparison/string/membership/field/literal).
  - AST->MIR lowering in `oilc/src/mid/mod.rs` now emits typed MIR directly (no AST passthrough wrapper).
  - Downstream runtime-IR lowering and Cypher codegen now consume typed MIR expressions directly.
- [ ] Expand runtime evaluator coverage for currently unsupported expression kinds.
  - Progress: added end-to-end support for `matches` (`AST -> MIR -> runtime-ir -> agent evaluator`) with runtime wildcard (`*`, `?`) and grouped-alternation (`(a|b|c)`) handling.
- [ ] Replace hardcoded/special-case field semantics with generic typed field resolution.
  - Progress: domain/IP comparisons now use a generic typed comparator (no `.domain`-only special case).
  - Progress: runtime field lookup/path aliasing moved to a typed, declarative field-spec table (including suffix alias resolution like `n.dest.port`, `proc.pid`, `time.hour`) instead of one-off matcher branches.
  - Remaining: emit/consume schema-derived field metadata from compiler artifacts so runtime mapping is generated from schema (not static in agent code).
- [ ] Complete parser semantics for currently partial/unsupported top-level forms (`template`, `policy`) and remaining clause semantics.
- [x] Remove legacy compiled-shared-object backend path and references.
  - Deleted the legacy backend module and removed its dedicated CLI mode.
  - Removed dormant agent rule-engine implementation file tied to that path.

## P2 - Kernel/Data Plane Hardening

- [x] Implement TC egress policy enforcement path (beyond pass-through).
  - Added kernel-side TC policy enforcement map (`TC_EGRESS_POLICY`) in `agent/ebpf/src/tc.rs`.
  - TC program now parses IPv4+TCP/UDP egress tuple and returns `TC_ACT_SHOT` on deny policy match.
  - Added userspace map loader hook (`OLOPA_TC_DENY_RULES`) in `agent/agent/src/main.rs`.
- [ ] Implement XDP threat policy logic (beyond pass-and-count).
- [ ] Emit/consume TC telemetry events where required for rule evaluation.
- [x] Replace single global graph delta mutex with per-thread/per-core delta buffers.
  - Implemented shard-based delta buffering in `agent/agent/src/data/csr_graph.rs`.
  - Writer threads now map to stable delta shards (thread-local hint), and merge drains all shards before CSR rebuild.
- [ ] Improve graph merge path for production contention and memory behavior.

## P3 - Product Integration

- [ ] Wire web app panels to real backend data sources (currently static/demo-driven UI).
  - Progress: metrics/events/incidents panels now consume live `/api/v1/ingest/*` endpoints.
  - Progress: explicit backend/agent connection state is visible in topbar/sidebar/banner; UI freezes live visuals when offline.
  - Progress: introduced Python control-plane scaffold (`app/control_plane`) to host dashboard/control/compiler APIs while proxying ingest reads to Rust.
  - Remaining: replace static demo graph panel data with live graph/runtime-backed data.
- [ ] Add API authn/authz and tenancy checks for ingest/stats endpoints.
- [ ] Add end-to-end integration tests: `oilc -> runtime-ir artifact -> agent eval -> server ingest`.
- [ ] Add CI workflows for deterministic checks/tests across `oilc`, `agent`, and `app/server`.
- [ ] Add observability surface: metrics/traces/log correlation across compiler, agent, server.

## P4 - Platform Targets (Roadmap Features)

- [ ] Integrate Memgraph-trigger execution path where required by graph rules.
- [ ] Add rule package/version lifecycle (load, reload, rollback) with compatibility checks.
