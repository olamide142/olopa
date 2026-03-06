# Aya Runtime Security Agent

This directory contains a Rust + Aya runtime security agent:

- `agent-ebpf`: kernel eBPF tracepoint program.
- `agent`: userspace loader, policy manager, and response loop.

## Project structure

`agent/` (userspace)
- `src/main.rs`: process lifecycle and polling loop
- `src/cli.rs`: CLI definition
- `src/pathing.rs`: path resolution for packaged deployments
- `src/ebpf_runtime.rs`: load/attach helpers for tracepoints + cgroup programs
- `src/policy.rs`: JSON policy parsing and map population
- `src/response.rs`: violation processing and optional kill response

`agent-ebpf/` (kernel side)
- `src/main.rs`: policy maps, telemetry tracepoints, connect4/connect6 enforcement hooks

## What it does

The eBPF programs provide:

1. Telemetry tracepoints for process, file I/O, and socket I/O syscalls:
`execve`, `openat`, `openat2`, `read`, `write`, `close`, `unlinkat`, `renameat2`, `socket`, `bind`, `listen`, `accept4`, `connect`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`, `setsockopt`.
2. Network enforcement hooks via `cgroup_sock_addr`:
`connect4`, `connect6`.
3. Policy maps:
- `BLOCKED_IPV4`
- `BLOCKED_PORTS`
- `BLOCKED_TGIDS`
- `ALLOW_TGIDS`
4. Violation counter map:
- `VIOLATION_COUNTS` (per TGID)

When a connect event violates policy, eBPF denies it and increments `VIOLATION_COUNTS`.
Userspace can optionally kill offending processes once a threshold is reached.

## Prerequisites (Linux)

- Rust toolchain
- Nightly Rust toolchain (for `-Z build-std=core` eBPF build)
- `rust-src` component (`rustup component add rust-src --toolchain nightly`)
- `bpf-linker` (`cargo install bpf-linker`)
- root privileges to load eBPF programs
- `clang`/`llvm` tooling often required by your distro eBPF stack

## Build

From this `agent/` directory:

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly build -Z build-std=core -p agent-ebpf --release --target bpfel-unknown-none
cargo build -p agent --release
```

## Run

```bash
sudo ./target/release/agent \
  --ebpf ./target/bpfel-unknown-none/release/agent-ebpf \
  --cgroup /sys/fs/cgroup \
  --policy ./policy.json \
  --violation-threshold 20
```

Press `Ctrl+C` to stop.

## Policy file

Create `policy.json` (example provided at `policy.example.json`):

```json
{
  "blocked_ipv4": ["1.1.1.1", "8.8.8.8"],
  "blocked_ports": [22, 23, 445],
  "blocked_tgids": [1234],
  "allow_tgids": [1]
}
```

Notes:
- `blocked_ports` are matched using kernel socket port representation.
- `allow_tgids` overrides block lists.
- To enable active response: add `--kill-on-violation`.
