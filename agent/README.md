Based on the full architecture documentation, here are the core features that **must exist** in the Olopa agent, organised by layer:

---


`cargo +nightly install bpf-linker --force`

## 🔵 1. eBPF / XDP Kernel Sensor Layer
The ground truth layer — cannot be bypassed by user-space, containers, or application code.

- **XDP Fast-Path Threat Filter** — runs at the NIC before the kernel TCP/IP stack; performs 5-tuple parsing, blacklist lookups, per-source rate limiting, and connection steering (DROP / REDIRECT to honeypot / PASS)
- **Kernel Tracepoint Probes** — eBPF programs attached to: `execve`, `openat`, `write`, `connect`, `accept`, and `fork` syscalls
- **Ring Buffer Architecture** — lock-free kernel-to-userspace event delivery using the Linux BPF ring buffer (kernel ≥ 5.8); drop counters when full

---

## 🟡 2. Rust Agent Daemon (Tokio)
The user-space brain — reads, scores, schedules, compresses, and transmits events.

- **Probe Manager** — loads and attaches eBPF programs; detects kernel features; handles graceful detach
- **Event Normaliser** — adds host/tenant IDs, converts timestamps to wall-clock
- **Relevance Scorer** — multi-factor scoring: severity, delta (change from baseline), recency, and context
- **OR Scheduler (MDKP)** — every 500ms solves a Multi-Dimensional Knapsack Problem to maximise security signal value under 5 simultaneous resource budgets (CPU, memory, I/O, network packets, bandwidth)
- **Budget Tracker with PI Controller** — real-time resource measurement with adaptive feedback
- **zstd Compressor** — dictionary-trained compression with adaptive level selection
- **Batcher** — bounded queue flushed by size, time, or count
- **Token-Bucket Rate Limiter** — bandwidth shaping
- **gRPC/mTLS Sender** — streaming telemetry with device-certificate mutual TLS and backpressure handling
- **Disk Spool Fallback** — persists events when the backend is unreachable

---

## 🟠 3. Agentic Firewall
Intercepts every AI agent tool call in real time before execution.

- **MCP Tool Call Interceptor** — STDIO/SSE proxy for Model Context Protocol tools
- **HTTP Transparent Proxy Adapter** — captures REST-based tool calls
- **Risk Scoring Engine** — 6-dimension risk model applied to every tool call
- **Policy DSL → OPA Rego Compiler** — human-readable policy rules compiled to Open Policy Agent
- **Sequence-Aware Action Graph** — tracks chains of actions across a session (e.g. read → classify → exfiltrate → egress) rather than judging individual events
- **Semantic DLP** — detects PII, credentials, and regulated data in tool call payloads
- **Dual-Key Approval Workflow** — high-risk actions require both policy gate approval and a human approval gate

---

## 🟢 4. Backend Platform

- **Python Ingest Gateway** — mTLS-authenticated, schema-validated, rate-limited async gateway with backpressure queue management
- **OPA Policy Engine** — evaluates tool-call sequences against cross-layer rules; supports allow/deny verdicts and approval gates
- **AI Risk Scorer** — adaptive trust scoring using LLM event history, threat intelligence, and anomaly models
- **ClickHouse Event Warehouse** — time-partitioned analytics store holding: `exec`, `file`, `net_events`, `tool_calls`, `policy_decisions`, `agent_heartbeats`, and cross-layer detection results

---

## 🔴 5. Detection Plane

- **Cross-Layer Detection Queries** — scheduled and streaming SQL over ClickHouse covering 7 initial attack chain detections
- **OWASP LLM Top 10 Full Coverage** — detection rules addressing all 10 LLM-specific threat categories
- **Adaptive Trust Scoring** — continuously updated per-agent/entity trust scores fed back into the policy engine
- **Alert Routing → Auto-Tightening** — detections feed back into the policy engine to automatically raise enforcement thresholds

---

## ⚪ 6. Security Model Requirements (non-negotiable hardening)

- Signed binaries with watchdog process
- Minimal Linux capabilities: `CAP_BPF + CAP_PERFMON + CAP_NET_RAW` only — no `CAP_SYS_ADMIN`
- `NoNewPrivileges=true` via systemd
- Signed policy packages with hash verification on load
- Memory ceiling of 150MB; CPU cgroup weight of 10/10,000

---

## 📊 7. Observability (must be present)

- **Prometheus metrics endpoint** covering: eBPF event/drop counts, scheduler selection/drop rates, budget utilisation, compression ratio, firewall decision counts, backend queue depth, and heartbeat age per host
- **OpenTelemetry tracing** — end-to-end latency from kernel event to ClickHouse commit
- **Grafana dashboard** — telemetry health + security posture

---

## Build and Run

Run these commands from `olopa/agent`.

### Integrated build system

- `olopa` now uses `agent/build.rs` to build `ebpf` automatically and embed it at compile-time.
- Default runtime path is embedded bytes via `include_bytes_aligned!`; no manual `OLOPA_EBPF_OBJECT` is required.
- `OLOPA_EBPF_OBJECT=/abs/path/to/olopa-ebpf` can still be used to override the embedded artifact at runtime.

### Compile individual crates

- Userspace agent:
  - `cargo check --manifest-path Cargo.toml -p olopa`
- Shared common crate:
  - `cargo check --manifest-path Cargo.toml -p olopa-common`
- eBPF crate (requires nightly + build-std for `core`):
  - `cargo +nightly check --manifest-path ebpf/Cargo.toml -Z build-std=core --target bpfel-unknown-none`

### Compile all (recommended)

- `cargo check --manifest-path Cargo.toml -p olopa`
  - This compiles userspace and triggers eBPF compilation through `build.rs`.

### Run sample userspace program

- The package builds a single userspace binary: `olopa`.
- `RUST_LOG=info cargo run --manifest-path Cargo.toml -p olopa -- --iface lo`
- Select probe groups with `--probe-events` (comma-separated): `fork,exec,file,net,xdp,tc`
  - Example (exec + net only): `RUST_LOG=info cargo run --manifest-path Cargo.toml -p olopa -- --iface lo --probe-events exec,net`
- Print resolved startup config (without starting probes): `cargo run --manifest-path Cargo.toml -p olopa -- --print-effective-config`
- Status view (with color + mascot bitmap):
  - `cargo run --manifest-path Cargo.toml -p olopa -- status --verbose`
  - Example (colors omitted here):
    ```text
    ● agent running pid=1241
    ● backend reachable 8ms rtt
    ─────────────────────────────
    cpu 3.2% / budget 5%
    mem 41 MB / ceiling 100MB
    bw 1.8 MB/s / limit 5%
    ─────────────────────────────
    probes attached
    execve openat connect
    write accept fork
    ─────────────────────────────
    events / 5s window
    124,872 captured
    124,218 transmitted
    654 dropped (budget)
    ─────────────────────────────
    firewall verdicts
    ALLOW 3,441
    DENY 2
    APPROVE 1
    ```
- Override runtime-ir or ingest target directly via CLI:
  - `cargo run --manifest-path Cargo.toml -p olopa -- --runtime-ir /etc/olopa/runtime-ir.json --ingest-url http://127.0.0.1:8000/api/v1/ingest/batches`
- Provide ingest auth when ingest API tokens are enabled:
  - `cargo run --manifest-path Cargo.toml -p olopa -- --ingest-api-token <token>`
  - `cargo run --manifest-path Cargo.toml -p olopa -- --ingest-api-key <key>`
- Control runtime status snapshot path:
  - `cargo run --manifest-path Cargo.toml -p olopa -- --status-path /tmp/olopa/agent/status.json`
- Userspace graph is dumped to `/tmp/olopa_graph.json` by default.
- Dump JSON includes topology (`nodes`, `edges`) and a rolling `events` list with fields like `event_type`, `span_id`, `parent_span_id`, `parent_id`, `pid`, `uid`, and timestamps.
- `nodes` now includes only active nodes (seen in edges/events), while `snapshot_nodes`/`snapshot_edges` expose raw CSR capacity/state.
- Event payload includes both original IDs (`source_id`, `target_id`) and normalized graph IDs (`graph_source_id`, `graph_target_id`) used for CSR indexing.
- `edges` now contains both merged graph edges (`edge_origin: "graph"`) and immediate event-derived edges (`edge_origin: "event"`) so visualizers always have live connections.
- Override dump path/interval with:
  - `RUST_LOG=info cargo run --manifest-path Cargo.toml -p olopa -- --iface lo --graph-dump-path /tmp/olopa_graph.json --graph-dump-interval-ms 500`
- Disable graph dump writes completely:
  - `RUST_LOG=info cargo run --manifest-path Cargo.toml -p olopa -- --no-graph-dump`
