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
  - Added optional SurrealDB HTTP SQL sink (`INGEST_SURREAL_URL`) with fallback to ClickHouse and then JSONL.
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
  - Progress: added end-to-end support for `null` literals (`AST -> MIR -> runtime-ir -> agent evaluator`) instead of lowering them to runtime `Unsupported`.
  - Progress: added end-to-end support for list literals in runtime expressions (including `contains` with list lhs), replacing another prior `Unsupported` lowering path.
  - Progress: added end-to-end support for arithmetic expressions (`+`, `-`, `*`, `/`, unary `-`) in `where`/predicate evaluation.
  - Progress: added end-to-end support for duration literals inside expressions (for example `event.ts_ns > 5m`) with runtime unit normalization.
  - Progress: added end-to-end support for callable expressions in runtime plans, including evaluator support for `count(...)` and `is_shell(...)`, and call-chain field projection (for example `host(...).baseline.domains`).
  - Progress: added runtime novelty helpers `rare(...)` and `unusual_for(...)` with stateful evaluation memory for first-seen value detection.
  - Progress: added aggregate callable evaluation support for `max(...)`, `min(...)`, `sum(...)`, `avg(...)`, and `distinct(...)` in runtime evaluator.
  - Progress: added stateful `rate(value, window)` callable support in runtime evaluator using per-key sliding-window counting.
- [ ] Replace hardcoded/special-case field semantics with generic typed field resolution.
  - Progress: domain/IP comparisons now use a generic typed comparator (no `.domain`-only special case).
  - Progress: runtime field lookup/path aliasing moved to a typed, declarative field-spec table (including suffix alias resolution like `n.dest.port`, `proc.pid`, `time.hour`) instead of one-off matcher branches.
  - Progress: compiler now emits `RuntimeProgram.fields` metadata derived from stdlib schema (+ synthetic runtime event fields), and agent consumes this metadata for field resolution with backward-compatible fallback for older artifacts.
  - Progress: added extractor bindings for additional schema fields from ingest events (`process.id`, `process.ppid`, `process.elevated`, `network.process_id`, `file.process_id`) with metadata-alias tests.
  - Progress: added extractor bindings for nested/derived schema fields (`user.uid`, `process.user.uid`, `process.parent.{pid,id}`, `host.risk_score`, `network.dest.is_internal`) with metadata-alias tests.
  - Progress: expanded fallback field metadata for older artifacts (no compiler `fields`) and kept `network.dest.domain` evaluator semantics compatible with IP-backed domain matching.
  - Remaining: extend runtime extractor bindings so more schema-emitted fields resolve to concrete event values (currently unknown fields safely evaluate as `null`).
- [ ] Complete remaining parser clause semantics.
  - Progress: parser now accepts `graph` and `around` rule-body clauses (with typed AST blocks), plus MIR source fallback derivation from body arms/source when `from` is omitted.
  - Progress: resolver/type-check now bind `graph`/`around` aliases into rule scope so `where` predicates can reference aliases (for example `p.pid`, `n.dest.port`) without unknown-identifier fallback.
- [x] Remove legacy compiled-shared-object backend path and references.
  - Deleted the legacy backend module and removed its dedicated CLI mode.
  - Removed dormant agent rule-engine implementation file tied to that path.

## P2 - Kernel/Data Plane Hardening

- [ ] Add end-to-end cgroup support in agent telemetry and policy evaluation.
  - Capture cgroup identity from eBPF events (stable id + optional path metadata where available).
  - Propagate cgroup fields through agent wire payloads to ingest storage.
  - Extend runtime field resolution so rules can reference cgroup-scoped context.
  - Add cgroup-targeted policy controls (allow/deny/rate limit) and tests for container workloads.
- [x] Add SQL query visibility via uprobes for process->table attribution.
  - Done: uprobes attached to `libpq` and MySQL client libraries with multi-distro library discovery (`agent/agent/src/probe_manager.rs`).
  - Done: normalized `db_query_events` family carries process identity, db engine/port, statement fingerprint, and operation kind end to end (agent -> ingest -> `recent`/`summary`).
  - Done: alert wire version 2 preserves SQL/TLS/DNS detail across the sender hop instead of collapsing it into `dst_vertex_id`.
  - Done: statement text is captured (`SqlEvent::query`) and redacted before use, so `database` and `tables` resolve without storing literal values (`agent/agent/src/sql_norm.rs`). Redaction runs first and the raw buffer dies at decode scope; `statement_fingerprint` now hashes the redacted form so a query shape groups across differing literals.
  - Done: hooked every client entry point that carries statement text — `PQexec`, `PQexecParams`, `mysql_real_query`. Previously only `PQexec` and `mysql_real_query` were hooked, so an application issuing parameterized queries produced no SQL telemetry at all.
  - Done: prepared statement lifecycle. `PQprepare`/`mysql_stmt_prepare` record statement text into the `PREPARED_STATEMENTS` LRU map without emitting; `PQexecPrepared`/`mysql_stmt_execute` emit an event carrying the recorded text. Each execution is counted once and attributed to its tables, and bound literal values are never seen at all. Records are keyed by connection handle plus name, since a statement name is scoped to a connection.
  - Known limits, all deliberate:
    - An execute whose prepare was missed (agent started after a connection pool prepared its statements, or an LRU eviction under >8192 live statements) still emits, with no text and no tables. Dropping it would hide real database activity.
    - libpq's async API (`PQsendQuery` and friends) is unhooked, because those are the internals of the `PQexec*` family and hooking both would double-count. A caller using the async API directly is not seen.
    - Statement capture truncates at 128 bytes, so a table named past that point is missed. Revisit if truncation shows up in practice.
    - The kernel-side prepared-statement path has not been exercised against a live verifier or a real database; it compiles and the programs and map are present in the object, but attach and load need a host with the client libraries and root.
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
- [x] Add API authn/authz and tenancy checks for ingest/stats endpoints.
  - Progress: added token-based API auth (`Authorization: Bearer ...` or `x-api-key`) via `INGEST_API_TOKENS` with global and tenant-scoped token support.
  - Progress: ingest write path now enforces tenant authorization (`POST /api/v1/ingest/batches` must match token scope).
  - Progress: read paths now enforce tenant scoping (`/api/v1/ingest/recent`, `/api/v1/ingest/summary`), and `/api/v1/ingest/stats` is restricted to global-scope tokens.
- [ ] Add end-to-end integration tests: `oilc -> runtime-ir artifact -> agent eval -> server ingest`.
  - Progress: added `agent::tests::e2e_rule_to_runtime_to_sender_to_ingest_runtime` to validate `oilc` compilation, runtime-ir evaluation, alert payload conversion via HTTP sender logic, and ingest API contract (`/api/v1/ingest/batches` + `/api/v1/ingest/recent`).
  - Note: test is `#[ignore]` by default because it requires local TCP bind + external ingest server process spawn (not available in restricted sandboxes).
- [x] Add CI workflows for deterministic checks/tests across `oilc`, `agent`, and `app/server`.
  - `.github/workflows/ci.yml` runs `oilc`, `agent`, and ingest-server suites plus the gated `e2e-runtime-to-ingest` job.
  - Follow-up: add lint/format gates and a load/perf smoke job.
- [ ] Add observability surface: metrics/traces/log correlation across compiler, agent, server.

## P4 - Platform Targets (Roadmap Features)

- [ ] Integrate Memgraph-trigger execution path where required by graph rules.
- [ ] Add rule package/version lifecycle (load, reload, rollback) with compatibility checks.
- [ ] Add SQL semantic policy support (example: block process X from reading table `finance` on DB Y).
  - Progress: runtime field model already resolves `sql.query_hash`, `sql.query_class`, and `sql.db_port`, so rules can match uprobe-derived SQL today.
  - Remaining: extend the field model with table-level entities (`db.query`, `db.table`, `db.operation`, `db.server`) once statement capture lands.
  - Add policy evaluation mode transitions: observe -> enforce for staged rollout safety.
  - Define enforcement strategy per engine path (client-library fail-close hook, DB proxy, or native DB plugin) with deterministic rollback.
