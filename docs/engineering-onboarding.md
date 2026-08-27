# Olopa Engineering Onboarding

Read this end to end once. It describes **what is actually in the tree today**, how the
pieces talk to each other, and how to develop against them.

> A note on the other docs: several files in `docs/` (and the top of `agent/README.md`)
> describe the *target* architecture, including components that do not exist yet — the
> agentic firewall / MCP interceptor, OPA/Rego policy evaluation, the gRPC sender, and the
> AI risk scorer. They are design intent, not code. This document only describes code that
> compiles and runs. Section 9 lists the gap explicitly.

---

## 1. What Olopa is

A Linux endpoint security platform with four moving parts:

1. an **eBPF sensor** that captures kernel events (process, file, network, DNS, TLS, SQL),
2. a **rule language and compiler** (`oilc` / OIL) that turns human-written detections into
   an artifact the agent evaluates at runtime,
3. a **telemetry pipeline** that ships events to an ingest server and on to storage,
4. **Secure Connect**, a managed WireGuard (ZTNA) layer where detections from (1)+(2) can
   automatically restrict or revoke a user's network access.

The thing that makes the system more than the sum of those parts is the loop: kernel
evidence on a host drives network access decisions for the user of that host, and the
access decision is enforced in the kernel too (nftables kill switch + WireGuard).

---

## 2. Repository map

```
agent/                        Rust workspace — the endpoint agent
  agent/                      userspace daemon (bin: `olopa`)
    src/agent.rs              the orchestrator loop (ingest / scheduler / housekeeping)
    src/probe_manager.rs      attaches eBPF programs
    src/runtime_ir.rs         runtime-IR rule engine (evaluates compiled OIL)
    src/data/                 relevance scorer, MDKP scheduler, batcher/compressor, graph
    src/transport/            durable spool + HTTP ingest sender
    src/secure_connect/       managed WireGuard client (ZTNA)
    src/build.rs              compiles the eBPF crate and embeds the ELF in the binary
  ebpf/                       the eBPF programs themselves (no_std)
  common/                     types shared kernel <-> userspace

oilc/                         Rust — the OIL rule compiler (bin: `oilc`)
  src/oil_stdlib/src/         schema.oil, predicates.oil, builtins.oil, callables.oil
  src/parser/oil.pest         authoritative grammar
  src/{lexer,parser,resolver,typecheck,mid,runtime_ir.rs,codegen}/

app/ingest_server/            Rust (axum) — telemetry hot path
  src/telemetry.rs            wire types + in-memory index + flush workers
  src/durability.rs           write-ahead log and idempotency state

app/control_plane/            Python (FastAPI) — orchestration and product APIs
  control_server/routers/     auth, rules, deployments, audit, dashboard, docs, landing
  control_server/secure_connect/   the Secure Connect orchestrator
  control_server/models/      SQLAlchemy ORM models

app/secure_connect_gateway/   Python — WireGuard gateway reconciler (runs on gateways)

docker-compose.yml            local stack: clickhouse, surrealdb, ingest, control plane,
                              keycloak, caddy
```

**Two servers, deliberately.** The Rust ingest server owns the telemetry hot path; the
Python control plane owns orchestration and product workflows. The control plane *proxies*
ingest reads rather than touching the hot path. Keep it that way — it is the reason ingest
latency is not coupled to product feature work.

---

## 3. The four flows that matter

### Flow A — a kernel event becomes a stored row

```
eBPF probe (kprobe/tracepoint/uprobe/XDP/TC)
  └─> BPF ring buffer
        └─> agent.rs::ingest_once     drains everything available, never sleeps
              ├─> relevance scorer    scores the event
              ├─> event store         retains it for the scheduler
              ├─> graph + metrics     builds process/network context
              └─> rule engine         evaluates compiled OIL; a match emits an alert payload
                                      straight to the sender (alerts bypass the scheduler)
        └─> agent.rs::scheduler_tick  every 500ms: MDKP knapsack picks which retained
              │                       events to transmit under 5 resource budgets
              └─> batcher (zstd)  ─>  sender.send_or_spool()
                                        └─> durable spool (disk, survives restart)
                                              └─> HTTP POST /api/v1/ingest/batches
ingest_server
  └─> auth + tenant check + rate limit
        └─> durable acceptance (WAL + idempotency by batch_id)
              └─> flush workers ─> JSONL / ClickHouse / SurrealDB
                                └─> in-memory ring for /api/v1/ingest/recent
```

Housekeeping runs every 5s and writes `OLOPA_STATUS_PATH` (default
`/tmp/olopa/agent/status.json`) — that file is what `olopa status --verbose` prints, and
what Secure Connect posture reads to prove the sensor is alive.

### Flow B — an OIL rule becomes an enforced detection

```
rule.oil
  └─> oilc: schema+prelude load → lex (pest) → parse → resolve → typecheck
            → MIR → validate → runtime IR  [→ optional Cypher codegen]
  └─> runtime-ir.json artifact
        └─> agent reads OLOPA_RUNTIME_IR (default deployment path), fingerprints it,
            validates, and hot-swaps the engine atomically; the previous engine is kept
            so a bad artifact rolls back instead of taking detection offline
```

`POST /api/v1/control/compiler/compile` runs the same compiler server-side and returns
diagnostics plus the runtime IR. The rules/deployments APIs persist rule versions and
deployment state.

> **Gap to know:** the control plane records a deployment as active, but there is no fleet
> delivery channel yet. Getting the artifact onto a host is currently out-of-band (config
> management writing `OLOPA_RUNTIME_IR`). The agent's reload/rollback half is real.

### Flow C — a laptop gets VPN access (Secure Connect)

```
operator: POST /secure-connect/enrollment-tokens        single-use JWT, exp <= 15m, jti tracked
agent:    POST /secure-connect/enroll                   token + mTLS cert fingerprint -> device_id
agent:    POST /secure-connect/sessions/start           -> gateway assignment + tunnel profile
agent:    wg set / ip route / resolvectl / nft          brings the tunnel up, kill switch on
agent:    POST /secure-connect/sessions/{id}/heartbeat  every 15s: posture up, one command down
gateway:  GET  /secure-connect/gateways/{id}/peers      reconciler converges `wg` to this list
```

The agent generates its WireGuard keypair locally. The private key is passed to `wg` only
over stdin, never appears in an argument list or in persisted state, and is zeroed on drop.
The control plane stores public keys only.

### Flow D — a detection revokes access (the loop)

```
agent rule engine fires an alert
  └─> alert rides the normal telemetry stream to ingest
        └─> control-plane risk subscriber polls /api/v1/ingest/recent,
            filters rows with attrs.wire == "alert_binary",
            buckets risk_score into a severity
              └─> every live session anchored to that host_id is driven through
                  the risk state machine
                    └─> next heartbeat carries the command (restrict / quarantine /
                        terminate) with a fresh monotonic nonce
                          └─> agent applies routes or the kill switch within seconds
                    └─> gateway reconciler drops the peer on its next poll
```

Access states: `healthy -> elevated -> restricted -> quarantined -> terminated`.
Restrictive transitions are automatic. The **only** automatic relaxation is
`elevated -> healthy` after a cooldown. Everything else needs a new session — see §7.

---

## 4. Getting a development environment

### Prerequisites

| Need | For |
| --- | --- |
| Rust stable | `oilc`, ingest server, agent userspace |
| Rust nightly + `bpf-linker` | building the eBPF crate (`cargo +nightly install bpf-linker --force`) |
| Linux, kernel >= 5.8 | BPF ring buffer |
| root / `CAP_BPF`+`CAP_NET_ADMIN` | attaching probes, and Secure Connect's `ip`/`wg`/`nft` |
| Python 3.12 | control plane, gateway reconciler |
| `wg`, `ip`, `nft`, `resolvectl` | only if you touch Secure Connect on a real host |

You can do most work without a BPF-capable machine: `oilc`, the ingest server, the control
plane, and the gateway reconciler are all plain userspace.

### The local stack

```bash
docker compose up -d          # clickhouse, surrealdb, ingest, control plane, keycloak, caddy
```

| Service | Port |
| --- | --- |
| ingest server | 8000 |
| control plane | 8100 |
| ClickHouse | 8123 |
| SurrealDB | 8001 |
| Keycloak | 8080 (localhost only) |

### The Makefile

The root `Makefile` wraps everything below; `make` on its own prints the annotated target
list. The useful ones:

```bash
make up                 # the local stack above
make test               # oilc, ingest, control plane, gateway, both UI typechecks
make test-ci            # the same plus the agent suite (needs nightly + bpf-linker)
make ui-build           # both UI surfaces against the shared design tokens
make control-plane-dev  # uvicorn on :8100 with reload
```

`make test` deliberately excludes the agent suite so it runs on a machine without the
nightly toolchain. It also builds `oilc` in release and exports `OILC_BINARY_PATH` for the
control-plane compiler tests, which is the manual step described at the end of this section.

The raw commands are below, since it is worth knowing what the targets actually run.

### Per component

```bash
# oilc
cargo test --manifest-path oilc/Cargo.toml
cargo run --manifest-path oilc/Cargo.toml -- --source rule.oil --mode runtime-ir \
  --emit-runtime-ir /tmp/runtime-ir.json --diagnostics-format json

# agent (userspace only — no BPF needed for the test suite)
cargo test --manifest-path agent/Cargo.toml -p olopa
cargo check --manifest-path agent/Cargo.toml -p olopa
sudo ./target/debug/olopa --iface eth0 --probe-events exec,file,net   # `status` is the only subcommand
./target/debug/olopa status --verbose
./target/debug/olopa --print-effective-config

# ingest server
cargo test --manifest-path app/ingest_server/Cargo.toml

# control plane
cd app/control_plane
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/uvicorn control_server.main:app --port 8100 --reload

# gateway reconciler (no third-party deps)
cd app/secure_connect_gateway && python -m pytest -q
python reconciler.py --once --dry-run --verbose
```

The control-plane compiler tests shell out to `oilc`. Build it once and export
`OILC_BINARY_PATH=$PWD/oilc/target/release/oilc` to keep them off the `cargo run` path —
that is exactly what CI does.

### Auth while developing

The control plane fails closed: with `CONTROL_AUTH_REQUIRED=1` (the default) every endpoint
needs a credential and there is **no built-in default token**. For local work set
`CONTROL_DEV_TOKEN=<something>` and send `x-dev-token: <something>`, which grants admin on
tenant `default`. Alternatives: a `Bearer` HS256 JWT (needs `JWT_SECRET`) or a service token
from `CONTROL_SERVICE_TOKENS_JSON`.

---

## 5. Where to make a change

| Task | Start here |
| --- | --- |
| Add a syscall/probe | `agent/ebpf/src/*.rs`, then `probe_manager.rs`, then the event type in `common/` |
| Add a field rules can match on | `oilc/src/oil_stdlib/src/schema.oil` → `resolver/mod.rs` → `typecheck/mod.rs` → `agent/src/runtime_ir.rs` field resolution |
| Add an OIL syntax form | `oilc/src/parser/oil.pest` → `parser/mod.rs` → `ast/` → `mid/` → `runtime_ir.rs` |
| Change the agent→ingest wire | `agent/src/transport/http_sender.rs` **and** `app/ingest_server/src/telemetry.rs` together |
| Add a control-plane API | `control_server/routers/` (or a vertical package), register in `main.py`, add an RBAC guard and an audit event |
| Add an ORM table | `control_server/models/<name>.py`, export it in `models/__init__.py` (that is what `init_db()` walks) |
| Change Secure Connect behaviour | agent `src/secure_connect/` and control-plane `secure_connect/` — both sides enforce the contract, see §7 |
| Change gateway peer handling | `app/secure_connect_gateway/reconciler.py` |

---

## 6. Conventions

- **Comments explain why, not what.** Match the density of the file you are in.
- **Errors carry context.** Rust uses `anyhow` with `.context(...)`; the control plane
  raises `HTTPException` with a `{code, message, request_id}` envelope. Do not invent a
  second error shape.
- **Every mutating control-plane endpoint writes an audit event** (`log_audit_event`) and
  sits behind an RBAC guard (`require_viewer` / `_analyst` / `_operator` / `_admin`).
- **Everything is tenant-scoped.** Identity determines the tenant; a request that names a
  different one gets 403. Never take a tenant id from a request body as authority.
- **Fail closed.** No default credentials, no wildcard CORS, https-only URLs unless an
  explicit dev-only escape hatch is set.
- **Tests live next to the thing** (`#[cfg(test)] mod tests` in Rust,
  `app/*/tests/` in Python) and assert behaviour, not implementation.

---

## 7. Invariants that will bite you

These are load-bearing. Breaking one produces a subtle runtime failure, not a compile error.

**Agent — ring buffer**
Dispatch on the leading `kind` tag, **never** on payload length. Event sizes are not unique
(`NetEvent`/`SqlEvent`/`SslEvent` are all 48 bytes; `ExecEvent`/`DnsEvent` are both 112), so
a length-based chain silently misroutes events.

**Agent — the hot loop never sleeps on work**
`ingest_once` drains everything available before returning. Only when it processed zero
events does the loop sleep 1ms. Periodic ticks step from their previous target, not from
`now`, so cadence does not drift. Do not add an `.await` that can block inside the drain.

**Agent — rule artifact swaps are atomic with rollback**
A replacement runtime IR is fingerprinted and validated before activation, and the previous
engine is retained. Never activate an artifact you have not validated.

**Secure Connect — command nonces are strictly monotonic per session**
The server increments the nonce for every command it emits; the agent rejects a nonce that
does not advance, and rejects a state-changing response that omits one. A "quiet" heartbeat
must return nonce `0`, which the agent reads as "nothing to replay-check". If you add a
command path, allocate a nonce.

**Secure Connect — the endpoint refuses unconfirmed relaxations**
The agent will only accept `elevated -> healthy` as a loosening on a live session. If the
server sends any other relaxation the agent treats it as an attack and drops the tunnel.
This is why operator recovery of a restricted session goes through termination and a fresh
session rather than a downgrade in place.

**Secure Connect — private key handling**
Generated on the endpoint, passed to `wg` over stdin only, zeroed on drop, never persisted
and never in `argv`. The control plane stores public keys only. There is a test asserting
the private key never appears in a command line — keep it passing.

**Secure Connect — `terminate` is terminal, `quarantine` is not**
Terminate stops the worker and requires re-enrollment. Quarantine and profile expiry keep
the kill switch applied and wait for a new session.

**Gateway reconciler — never revoke on a failed poll**
If the control plane is unreachable the peer set stays exactly as it is. Cutting access
requires a *successful* poll that says the peer is gone; otherwise a control-plane outage
would black out the fleet.

**Ingest — batch ids are the idempotency key**
Acceptance is WAL-backed and deduplicated on `(tenant_id, host_id, batch_id)`. A resent
batch must be acknowledged, not stored twice.

**Control plane — `init_db()` only creates tables it can see**
It imports `control_server.models`, so a model missing from `models/__init__.py` silently
has no table.

**Control plane — SQLite serialises writers**
The store runs in WAL mode with `synchronous=NORMAL`; without those it fsyncs on every
commit and request latency goes up ~100x. Even so, one writer at a time is the ceiling:
session establishment collapses past ~8 concurrent starts. Keep write transactions short,
and use PostgreSQL for anything past a pilot. See
[`docs/secure-connect/runbooks.md`](./secure-connect/runbooks.md) section 1.

**Control plane — do not use SAVEPOINT on SQLite**
pysqlite does not implement it reliably. Structure code to avoid nested transactions;
the Secure Connect address allocator commits its lease separately for this reason.

---

## 8. Testing and CI

`.github/workflows/ci.yml` runs five jobs: `oilc-tests`, `control-plane-tests` (which also
runs the gateway reconciler suite), `agent-tests` (needs nightly + `bpf-linker`),
`ingest-server-tests`, and the gated `e2e-runtime-to-ingest`.

`make test-ci` runs the first four locally, command for command; `make e2e-test` runs the
fifth.

The e2e test `agent::tests::e2e_rule_to_runtime_to_sender_to_ingest_runtime` is
`#[ignore]`d by default because it binds a TCP port and spawns an ingest process. It is the
best single check that a wire change did not break the chain:

```bash
cargo test --manifest-path agent/Cargo.toml -p olopa \
  agent::tests::e2e_rule_to_runtime_to_sender_to_ingest_runtime -- --ignored --exact
```

Current counts: 174 agent, 68 control plane, 17 gateway, plus the `oilc` and ingest suites.

For capacity work there is a load-test harness that drives virtual endpoints through the
real Secure Connect contract and fails the run when an SLO target is missed:

```bash
python app/control_plane/tools/sc_loadtest.py --control-url http://127.0.0.1:8100 \
  --dev-token "$CONTROL_DEV_TOKEN" --devices 200 --concurrency 8 --duration 60
```

---

## 9. Implemented vs. designed

**Implemented**

- eBPF probes: fork, exec, file, net, DNS, TLS (libssl uprobes), SQL (libpq/libmysqlclient
  uprobes), XDP, TC; ring buffer delivery; probe selection via `--probe-events`
- `oilc` full pipeline through runtime IR, plus Cypher codegen
- Agent runtime: relevance scoring, MDKP scheduler, budget tracker, zstd batching, durable
  spool, HTTP ingest sender, runtime-IR engine with hot reload and rollback
- Ingest server: authenticated, rate-limited, WAL-durable acceptance; JSONL/ClickHouse/
  SurrealDB sinks; stats/recent/summary read APIs
- Control plane: auth (dev token / JWT / service tokens), RBAC, audit, rule registry and
  versioning, deployment state machine, server-side compilation
- Secure Connect: end to end — enrollment, sessions, policy, heartbeat command channel,
  rekey, revocation, risk state machine, detection-stream subscription, session reaper,
  metrics, and the gateway reconciler

**Designed but not built** (referenced in older docs — do not assume these exist)

- Agentic firewall: MCP/HTTP tool-call interception, dual-key approval, semantic DLP
- OPA/Rego policy evaluation
- gRPC/mTLS streaming sender (`transport/grpc_sender_spool.rs` is in-tree but not compiled
  in — `transport/mod.rs` does not declare it)
- AI risk scorer / anomaly baselines
- Fleet delivery of compiled rule bundles to agents
- External OIDC/JWKS identity integration (local HS256 JWT only today)

---

## 10. Glossary

| Term | Meaning |
| --- | --- |
| **OIL** | Olopa Intent Language — the rule DSL |
| **oilc** | its compiler |
| **runtime IR** | the JSON artifact the agent evaluates; `oilc`'s production output |
| **MIR** | mid-level IR inside `oilc`, between AST and runtime IR |
| **MDKP** | Multi-Dimensional Knapsack Problem — the 500ms transmit scheduler |
| **spool** | on-disk queue that holds telemetry when ingest is unreachable |
| **posture** | endpoint health facts sent with each Secure Connect heartbeat |
| **kill switch** | nftables ruleset that drops non-tunnel egress |
| **profile** | Secure Connect access policy compiled into a tunnel config |
| **session** | one Secure Connect tunnel lifetime |
| **command nonce** | monotonic counter making control commands replay-proof |

---

## 11. First week

1. `docker compose up -d`, then `curl -s localhost:8100/health` and
   `curl -s localhost:8000/health`.
2. Compile a rule from `oilc/src/rules/` with `--mode runtime-ir` and read the JSON.
3. Run the agent's test suite; open `agent/src/agent.rs` and follow one event from
   `ingest_once` to `send_or_spool`.
4. Run the control-plane suite; read `app/control_plane/tests/test_secure_connect.py` —
   it is the most complete description of the Secure Connect contract in the repo.
5. Run the gated e2e test.
6. Pick something from §9's "designed but not built" list and check its plan doc in `docs/`.
