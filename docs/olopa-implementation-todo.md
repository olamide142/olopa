# Olopa Implementation TODO

Actionable TODO derived from the current codebase state (agent, oilc, ingest server,
control plane, web, and desktop).

## P0 - End-to-End Runtime Path (Ship First)

- [x] Replace `SimpleSender` with a real transport client from agent -> server.
  - Implemented in `agent/src/http_sender.rs` using HTTP POST to `/api/v1/ingest/batches`.
- [x] Unify wire schema between agent output and server ingest API (v1 adapter).
  - Agent payloads are now translated into server `IngestBatchRequest` JSON.
  - Scheduler-selected telemetry now uses a versioned typed event record before compression, preserving process, file, network, SQL, SSL, and DNS fields through the normal (non-alert) path. Legacy `evt ...` records remain readable.
  - Mixed compressed-batch regression coverage verifies SQL reaches `db_query_events`, SSL/DNS retain typed network protocols and attributes, and none of these families fall through to `process_exec_events`.
  - Follow-up: replace adapter parsing with a strict shared schema crate.
- [x] Replace server `persist_placeholder(...)` with real persistence (ClickHouse/Kafka path).
  - Implemented durable JSONL persistence in `app/ingest_server/src/telemetry.rs`.
  - Added optional ClickHouse HTTP sink (`INGEST_CLICKHOUSE_URL`) with JSONL fallback on insert failure.
  - Added optional SurrealDB HTTP SQL sink (`INGEST_SURREAL_URL`) with fallback to ClickHouse and then JSONL.
  - Follow-up: add Kafka/queue fanout for decoupled high-throughput ingest.
- [x] Keep runtime-IR execution as the default path and fail loudly on schema mismatch.
  - Agent now fails startup when runtime-ir load/schema validation fails.
  - `SimpleRuleEngine` fallback is now opt-in only via `OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1`.
- [x] Harden ingest delivery and service operation.
  - Accepted non-empty `batch_id` values are idempotent through a bounded persistent index keyed by tenant, host, and batch ID. Concurrent retries enqueue exactly once and duplicate acknowledgements are explicit.
  - Agent delivery complete: the active HTTP sender appends to a bounded fsynced spool before accepting a payload, preserves stable batch IDs across retries/restarts, recovers partial tails, compacts acknowledged records, and applies bounded exponential/server-directed backoff.
  - Server acceptance is fsynced to a versioned WAL before acknowledgement, replays after restart, checkpoints only after a durable sink, persists/compacts dedupe state atomically, and tolerates a torn tail.
  - Added request-body and tenant/host rate limits, production auth validation, restricted CORS, `/ready`, authenticated Prometheus counters/flush histograms, partitioned flush workers, exponential jittered sink retry, per-sink circuit breakers, and a fsynced dead-letter path for permanent failures.
  - Follow-up: add OpenTelemetry trace export and Kafka fan-out only when deployment scale requires decoupling beyond the WAL and partitioned workers.

## P1 - Rule Engine and Compiler Correctness

- [x] Lower MIR expressions beyond `MirExpr::Raw(...)` into executable ops.
  - `MirExpr` now carries typed executable variants (logical/comparison/string/membership/field/literal).
  - AST->MIR lowering in `oilc/src/mid/mod.rs` now emits typed MIR directly (no AST passthrough wrapper).
  - Downstream runtime-IR lowering and Cypher codegen now consume typed MIR expressions directly.
- [x] Expand runtime evaluator coverage for executable expression and function kinds.
  - Progress: added end-to-end support for `matches` (`AST -> MIR -> runtime-ir -> agent evaluator`) with runtime wildcard (`*`, `?`) and grouped-alternation (`(a|b|c)`) handling.
  - Progress: added end-to-end support for `null` literals (`AST -> MIR -> runtime-ir -> agent evaluator`) instead of lowering them to runtime `Unsupported`.
  - Progress: added end-to-end support for list literals in runtime expressions (including `contains` with list lhs), replacing another prior `Unsupported` lowering path.
  - Progress: added end-to-end support for arithmetic expressions (`+`, `-`, `*`, `/`, unary `-`) in `where`/predicate evaluation.
  - Progress: added end-to-end support for duration literals inside expressions (for example `event.ts_ns > 5m`) with runtime unit normalization.
  - Progress: added end-to-end support for callable expressions in runtime plans, including evaluator support for `count(...)` and `is_shell(...)`. Call-result member access is represented as a structured `project` expression, so arguments in chains such as `baseline.image(id).allowed_processes` and `host(id).baseline.domains` survive MIR/runtime-IR lowering.
  - Progress: added runtime novelty helpers `rare(...)` and `unusual_for(...)` with stateful evaluation memory for first-seen value detection.
  - Progress: added aggregate callable evaluation support for `max(...)`, `min(...)`, `sum(...)`, `avg(...)`, and `distinct(...)` in runtime evaluator.
  - Progress: added stateful `rate(value, window)` callable support in runtime evaluator using per-key sliding-window counting.
  - Progress: callable signatures from `callables.oil` now travel in runtime IR as typed metadata; the agent resolves executable functions through one registry and rejects unknown functions, arity drift, and compiler/runtime contract mismatches while loading an artifact instead of silently returning `null`.
  - Progress: added end-to-end `len(Str) -> Int` support, including the checked-in long-DNS-name rule path (`oilc` declaration/typecheck -> runtime IR contract -> agent evaluation).
  - Progress: callable execution now validates concrete argument and return values against the compiler-emitted contract. Builtin signature drift fails artifact loading, dynamically invalid values fail closed, entity/set/nullable contracts are checked recursively, and nested stateful arguments execute exactly once.
  - Function-system slice complete: callable declarations now support overload sets and recursive generic `Any` matching (`len(Str)` plus `len(Set<Any>)`), with deterministic contract emission and runtime overload selection.
  - Function-system slice complete: state keys are isolated by host and rule, with entity scope for `unusual_for` and window scope for `rate`. `OLOPA_CALLABLE_STATE_MAX_ENTRIES` bounds the shared state index; oldest keys are evicted.
  - Function-system slice complete: optional durable checkpoints use `OLOPA_CALLABLE_STATE_PATH` and `OLOPA_CALLABLE_STATE_CHECKPOINT_EVERY`. Snapshots are versioned, host-scoped, atomically replaced, restored at startup, and store realtime rate observations so reboot does not invalidate sliding windows.
  - Function-system slice complete: the runtime registry now executes lookup-backed extensions instead of advertising dead declarations. `intel.domains(feed)` reads the hot-reloaded intel store; `baseline.image(...)`, `baseline.workload(...)`, `host(...)`, and `user(...)` read structured version-1 lookup data from `OLOPA_RUNTIME_LOOKUP_PATH` and fail closed when an entry is absent. Workload keys use `namespace/name`; image profiles contain `allowed_processes`; host/user entries contain their schema baseline collections.
  - Function-system slice complete: rule-local `let` bindings execute sequentially, score bases/modifiers produce a runtime `score` binding, `require` gates matches, and the first matching conditional response branch controls enforcement actions.
  - Function-system slice complete: local, stdlib, and cross-file predicate bodies are expanded before runtime-IR emission; named sets become literal membership values, nested predicate calls are bounded against recursion, and `under` with a set preserves "any prefix" semantics.
  - All AST expression variants now lower to typed MIR. The remaining serialized `Unsupported` variant is a defensive compatibility shape and MIR validation blocks it from executable artifacts.
- [ ] Replace hardcoded/special-case field semantics with generic typed field resolution.
  - Progress: domain/IP comparisons now use a generic typed comparator (no `.domain`-only special case).
  - Progress: runtime field lookup/path aliasing moved to a typed, declarative field-spec table (including suffix alias resolution like `n.dest.port`, `proc.pid`, `time.hour`) instead of one-off matcher branches.
  - Progress: compiler now emits `RuntimeProgram.fields` metadata derived from stdlib schema (+ synthetic runtime event fields), and agent consumes this metadata for field resolution with backward-compatible fallback for older artifacts.
  - Progress: added extractor bindings for additional schema fields from ingest events (`process.id`, `process.ppid`, `process.elevated`, `network.process_id`, `file.process_id`) with metadata-alias tests.
  - Progress: added extractor bindings for nested/derived schema fields (`user.uid`, `process.user.uid`, `process.parent.{pid,id}`, `host.risk_score`, `network.dest.is_internal`) with metadata-alias tests.
  - Progress: expanded fallback field metadata for older artifacts (no compiler `fields`) and kept `network.dest.domain` evaluator semantics compatible with IP-backed domain matching.
  - Progress: every context currently captured by the agent now has typed bindings, including cgroup/container metadata, host identity, Secure Connect session state/peer counters, and tunneled network context. Schema-only fields that are not present in endpoint telemetry continue to fail closed as `null`.
  - Remaining: extend runtime extractor bindings so more schema-emitted fields resolve to concrete event values (currently unknown fields safely evaluate as `null`).
- [ ] Complete remaining parser clause semantics.
  - Progress: switched source tokenization and the typed stdlib schema parser to Rust Pest grammars. The stable token/AST contract remains as a compatibility adapter while clause-level AST construction migrates incrementally.
  - Progress: parser now accepts `graph` and `around` rule-body clauses (with typed AST blocks), plus MIR source fallback derivation from body arms/source when `from` is omitted.
  - Progress: resolver/type-check now bind `graph`/`around` aliases into rule scope so `where` predicates can reference aliases (for example `p.pid`, `n.dest.port`) without unknown-identifier fallback.
- [x] Remove legacy compiled-shared-object backend path and references.
  - Deleted the legacy backend module and removed its dedicated CLI mode.
  - Removed dormant agent rule-engine implementation file tied to that path.

## P2 - Kernel/Data Plane Hardening

- [x] Add end-to-end cgroup support in agent telemetry and policy evaluation.
  - Every probe records `bpf_get_current_cgroup_id`; userspace periodically resolves the cgroup-v2 inode hierarchy into path, container ID, and pod UID metadata.
  - Scheduler and alert wire v3 preserve cgroup identity and the HTTP adapter stores resolved metadata in family attributes.
  - Runtime fields cover `process.cgroup_id`, `process.container_id`, and the container cgroup/path/pod context.
  - TC policy supports specificity-aware per-process/per-cgroup/global allow and deny overrides plus token-bucket packet rate limits via `OLOPA_TC_POLICY_RULES`.
- [x] Add SQL query visibility via uprobes for process->table attribution.
  - Done: uprobes attached to `libpq` and MySQL client libraries with multi-distro library discovery (`agent/agent/src/probe_manager.rs`).
  - Done: normalized `db_query_events` family carries process identity, db engine/port, statement fingerprint, and operation kind end to end (agent -> ingest -> `recent`/`summary`).
  - Done: alert wire version 2 preserves SQL/TLS/DNS detail across the sender hop instead of collapsing it into `dst_vertex_id`.
  - Done: the budgeted scheduler path also preserves SQL/TLS/DNS details. `RealEventStore` retains the complete `IngestEvent`, emits a typed `event_v2` record, and the sender routes each family without relying on an alert match.
  - Done: statement text is captured (`SqlEvent::query`) and redacted before use, so `database` and `tables` resolve without storing literal values (`agent/agent/src/sql_norm.rs`). Redaction runs first and the raw buffer dies at decode scope; `statement_fingerprint` now hashes the redacted form so a query shape groups across differing literals.
  - Done: hooked every client entry point that carries statement text — `PQexec`, `PQexecParams`, `mysql_real_query`. Previously only `PQexec` and `mysql_real_query` were hooked, so an application issuing parameterized queries produced no SQL telemetry at all.
  - Done: prepared statement lifecycle. `PQprepare`/`mysql_stmt_prepare` record statement text into the `PREPARED_STATEMENTS` LRU map without emitting; `PQexecPrepared`/`mysql_stmt_execute` emit an event carrying the recorded text. Each execution is counted once and attributed to its tables, and bound literal values are never seen at all. Records are keyed by connection handle plus name, since a statement name is scoped to a connection.
  - Done: rules can act on tables. `db.tables` (`Set<Str>`) and `db.database` (`Str?`) are declared on the stdlib `SqlEvent` and wired to extractors, so `q.tables contains "ledger"` compiles and fires. Names come from the same `sql_norm::unpack_tables` split that fills the outbound `DbQueryEvent`, so a rule matches exactly the name the stored row shows.
  - Fixed along the way: no oilc-compiled SQL rule had ever fired. The stdlib names the SQL root `db`, so the compiler emits `db.query_class`, but only the `sql.*` spellings had extractors — every SQL field resolved to Null, including in the shipped `sql_suspicious_ops.oil` rules. `db.pid`/`db.uid`/`db.process_name` were unregistered for the same reason. Covered now by `oilc_compiled_sql_rules_resolve_their_fields_and_fire`, which drives the real compiler rather than hand-written IR — the gap every existing test missed.
  - Known limits, all deliberate:
    - An execute whose prepare was missed (agent started after a connection pool prepared its statements, or an LRU eviction under >8192 live statements) still emits, with no text and no tables. Dropping it would hide real database activity.
    - libpq's async API (`PQsendQuery` and friends) is unhooked, because those are the internals of the `PQexec*` family and hooking both would double-count. A caller using the async API directly is not seen.
    - Statement capture truncates at 128 bytes, so a table named past that point is missed. Revisit if truncation shows up in practice.
    - The kernel-side prepared-statement path has not been exercised against a live verifier or a real database; it compiles and the programs and map are present in the object, but attach and load need a host with the client libraries and root.
- [x] Register the remaining per-root process identity and derived DNS fields outside SQL.
  - Added event-family-scoped extractors for `ssl.pid`, `ssl.uid`, and `ssl.process_name`.
  - Completed the `DnsQuery` contract with process identity and `query_hash`, then wired `dns.domain.entropy` to runtime Shannon-entropy evaluation.
  - Fixed runtime-IR alias lowering so correlate-local paths such as `s.pid`, `q.pid`, and `p.pid` are emitted as their canonical schema paths instead of silently resolving to `Null` when a field suffix is shared by multiple roots.
- [x] Implement TC egress policy enforcement path (beyond pass-through).
  - Added kernel-side TC policy enforcement map (`TC_EGRESS_POLICY`) in `agent/ebpf/src/tc.rs`.
  - TC program now parses IPv4+TCP/UDP egress tuple and returns `TC_ACT_SHOT` on deny policy match.
  - Added userspace map loader hook (`OLOPA_TC_DENY_RULES`) in `agent/agent/src/main.rs`.
- [x] Implement XDP threat policy logic (beyond pass-and-count).
  - XDP parses bounded Ethernet/IPv4 headers, checks the `XDP_BLOCKLIST_V4` map, drops exact source-IP threats, and records pass/drop counters. Userspace loads `OLOPA_XDP_BLOCK_IPS` atomically at startup.
- [x] Emit/consume TC telemetry events where required for rule evaluation.
  - TC emits deny/rate-drop verdicts into the shared ring buffer; the agent decodes event type 7, evaluates runtime network predicates, and routes records to normalized network ingest with `protocol=tc` and verdict attributes.
- [x] Replace single global graph delta mutex with per-thread/per-core delta buffers.
  - Implemented shard-based delta buffering in `agent/agent/src/data/csr_graph.rs`.
  - Writer threads now map to stable delta shards (thread-local hint), and merge drains all shards before CSR rebuild.
- [x] Improve graph merge path for production contention and memory behavior.
  - Compact typed vertex allocation replaces the old modulo mapping (which aliased unrelated raw IDs), with an explicit `OLOPA_GRAPH_MAX_NODES` bound.
  - Snapshot rebuilds sort only new deltas and linearly merge them into the already ordered CSR arrays; repeated edges are coalesced using the newest metadata instead of growing forever.

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
- [x] Secure the control-plane API and establish the rule/deployment registry foundation.
  - Added explicit dev/JWT/service authentication; arbitrary API keys no longer become privileged service accounts.
  - Added hierarchical RBAC and immutable tenant binding across control status, ingest proxies, compiler, intel, rules, deployments, and audit reads.
  - Added real `oilc` diagnostics/runtime-IR persistence, invalid-rule rejection, immutable version numbering, deployment preflight, rollback transitions, and tenant-scoped idempotency.
  - Remaining control-plane work: external OIDC/JWKS, atomic audit coverage for every mutation, async jobs, and real agent-fleet rollout delivery.
- [x] Add end-to-end integration tests: `oilc -> runtime-ir artifact -> agent eval -> server ingest`.
  - `agent::tests::e2e_rule_to_runtime_to_sender_to_ingest_runtime` validates `oilc` compilation, runtime-ir evaluation, alert payload conversion via HTTP sender logic, and the ingest API contract (`/api/v1/ingest/batches` + `/api/v1/ingest/recent`).
  - The test is `#[ignore]` in the normal agent suite because it binds a local port and spawns the ingest server; CI runs it explicitly in the gated `e2e-runtime-to-ingest` job.
- [x] Add CI workflows for deterministic checks/tests across `oilc`, `agent`, and `app/ingest_server`.
  - `.github/workflows/ci.yml` runs `oilc`, `agent`, and ingest-server suites plus the gated `e2e-runtime-to-ingest` job.
  - Follow-up: add lint/format gates and a load/perf smoke job.
- [ ] Add observability surface: metrics/traces/log correlation across compiler, agent, server.

## P4 - Platform Targets (Roadmap Features)

- [ ] Run Olopa agents on Kubernetes with node-level collection and reconciled policy rollout.
  - Architecture decision: the eBPF sensor runs once per eligible Linux node as
    a DaemonSet; an optional unprivileged sidecar provides workload context but
    does not load kernel probes.
  - Delivery order: Helm/DaemonSet packaging, node-scoped pod enrichment,
    controller and policy CRDs, workload targeting/enforcement, then opt-in
    admission-based sidecar injection.
  - Detailed implementation phases and acceptance criteria:
    `docs/kubernetes/sidecar-controller-plan.md`.
- [ ] Integrate Memgraph-trigger execution path where required by graph rules.
- [x] Add rule package/version lifecycle (load, reload, rollback) with compatibility checks.
  - The agent fingerprints and validates replacement runtime-IR before atomic activation, retains the last good engine on rejection, supports explicit rollback signals, and publishes generation/fingerprint/rule-count/error deployment status.
- [x] Implement the Secure Connect agent subsystem behind a disabled-by-default feature flag.
  - Added validated `OLOPA_SC_*` configuration, mTLS control client, enrollment/session/heartbeat/rekey lifecycle, monotonic command replay protection, and restrictive state-transition enforcement.
  - WireGuard keypairs are generated locally; private material is passed to `wg` only over stdin and is zeroed on drop. No private key is written into persisted state or command arguments.
  - Profile routes, DNS, atomic nftables kill switch, policy expiry, quarantine/termination, reconnect backoff, posture, health counters, and `olopa status --verbose` output are wired.
  - Live tunnel/gateway validation still requires a privileged Linux host with `ip`, `wg`, `nft`, and `resolvectl`, plus a real WireGuard gateway plane.
- [x] Implement the Secure Connect control-plane orchestrator (`app/control_plane/control_server/secure_connect/`).
  - `/api/v1/secure-connect/*` implements the agent contract exactly: enroll, session start, heartbeat command channel, and rekey, plus operator APIs for enrollment tokens, gateways, profiles, devices, sessions, and risk signals.
  - Enrollment tokens are single-use JWTs (`jti` tracked, `exp <= 15m`) redeemed atomically against an mTLS certificate fingerprint that permanently binds the device; only public keys are ever stored.
  - Gateway allocation is region- and capacity-aware, tunnel addresses are stable per device, and gateways pull desired peer state from `/gateways/{id}/peers` (plan option A: external gateway plane).
  - The risk adapter maps alert severity to `elevated`/`restricted`/`quarantined`/`terminated`, auto-applies restrictive transitions, revokes key material, instruments propagation latency, and only relaxes `elevated -> healthy` after a cooldown — matching the endpoint's local relaxation guard.
  - Covered by `app/control_plane/tests/test_secure_connect.py`.
- [x] Subscribe the Secure Connect risk adapter to the detection stream and reap dead sessions.
  - A background worker reaps sessions whose profile expired without renewal (revoking keys so a dark device stops holding a gateway peer) and, when `CONTROL_SC_RISK_SUBSCRIBER_ENABLED=1`, polls ingested alert rows, buckets `risk_score` into severities, and drives every live session anchored to the alerting host through the risk state machine.
  - Alerts apply at most once per `(tenant, host, rule, event)` identity; a detection-stream outage is logged and retried without disturbing live tunnels.
  - `GET /api/v1/secure-connect/metrics` exposes the SLO counters: sessions by state, stale sessions, gateway utilization, command/revoke propagation latency percentiles, and enrollment token usage.
- [x] Ship Secure Connect telemetry and kernel-verified posture from the agent.
  - Tunnel/posture events ride the existing durable ingest spool as `sc_event` lines mapped into the `agent_heartbeat` family, so no second ingest surface was added.
  - Posture now sources probe attachment, capture/drop counters, firewall verdicts, ingest reachability, and rule counts from the live sensor's status snapshot; `kernel_verified_posture` is false when that snapshot is missing or stale.
  - `quarantine` and profile expiry are recoverable (kill switch stays applied while awaiting a new session); only `terminate` remains terminal.
- [x] Harden Secure Connect for production (multi-gateway failover, load testing, runbooks).
  - Gateways report reconciler liveness; one that goes silent stops receiving sessions and its live sessions migrate to a healthy gateway as a transparent profile refresh. Sessions with nowhere to go are left running rather than torn down.
  - `POST /gateways/{id}/status` drains or restores a gateway; `POST /gateways/{id}/failover` evacuates it on demand; the background worker does it automatically.
  - Fixed a latent agent bug the migration path exposed: `wg set` adds peers but never replaces them, so a gateway change left the old peer installed.
  - `app/control_plane/tools/sc_loadtest.py` drives virtual endpoints through the real contract and fails the run when an SLO target is missed.
  - Measured ceiling: SQLite serialises writers, so session establishment collapses past ~8 concurrent starts; PostgreSQL is required beyond a pilot. Enabling WAL + `synchronous=NORMAL` cut request latency ~100x and the control-plane suite from ~100s to ~4s.
  - Operator runbooks with game-day exercises: `docs/secure-connect/runbooks.md`.
- [x] Build the Secure Connect gateway plane reconciler (`app/secure_connect_gateway/`).
  - Pulls `GET /gateways/{id}/peers` and converges a WireGuard interface with `wg set`, removals first; peer removal is the revocation path.
  - Never touches interface configuration, never sees private keys, and never revokes on a failed poll — a control-plane outage leaves the peer set untouched.
  - Dependency-free Python with `--once`/`--dry-run` modes, a hardened systemd unit, and 17 tests.
- [x] Add SQL semantic policy support (example: block process X from reading table `finance` on DB Y).
  - Detection is complete: statement capture is redacted before use and runtime fields resolve query class, database, operation, and `db.tables`, so OIL rules can match uprobe-derived table access today.
  - Enforcement uses `agent/sql_guard`, an `LD_PRELOAD` client-library guard
    that obtains a synchronous Unix-socket verdict before calling supported
    libpq/libmysqlclient execution APIs. Detection-only uprobes never claim to
    cancel a query after the fact.
  - Added the OIL `block query <target>` action, peer-credential validation,
    bounded requests/workers/queues, prepared statement execution checks,
    observe -> enforce transitions, explicit fail-open/fail-closed behavior,
    and `allowed`/`would_block`/`blocked` telemetry.
  - `make sql-guard-smoke` verifies nine direct, async, parameterized, and
    prepared client API paths and proves a denial does not call the real symbol.
  - Operator guide and supported-client limits: `docs/sql-enforcement.md`.
  - Production qualification still requires live database validation for each
    distribution and client-library version added to the support matrix.
