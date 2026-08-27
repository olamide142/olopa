# Olopa Command

The local operator workstation for Olopa: a Tauri desktop app for managing the agent,
authoring and simulating OIL policy, inspecting eBPF programs, watching kernel telemetry,
and driving the rule registry and Secure Connect.

It does **not** replace the web console (`app/control_plane/web`). The console is the
fleet's product surface; Command is the engineering surface for one machine, and it works
with no servers running at all.

```
Olopa Platform
├── Olopa Agent            endpoint runtime (Rust + eBPF)
├── Olopa Command          this app — desktop operator workstation
├── Control plane          orchestration, rule registry, Secure Connect
└── OIL                    the policy/detection language
```

## The boundary that matters

**Command is a client, never a supervisor.** The agent is an independent privileged daemon.
Quitting Command never stops protection; nothing in this app owns the agent's lifetime.
Every panel reads an artefact the agent or a server already publishes:

| Surface | Source | Needs a server? |
| --- | --- | --- |
| Agent, Overview, status bar | `OLOPA_STATUS_PATH` snapshot (rewritten every 5s) | no |
| Secure Connect (this device) | `OLOPA_SC_STATUS_PATH` health file | no |
| eBPF Explorer | `bpftool -j prog/map show` | no |
| OIL Studio, Simulator | the `oilc` crate, linked in-process | no |
| Logs, diagnostics bundle | `journalctl -u <unit>` | no |
| Telemetry | ingest `/api/v1/ingest/*` | ingest server |
| Registry, Secure Connect fleet | control plane `/api/v1/*` | control plane |

Lifecycle actions shell out to `systemctl` and are confirmed once in the UI. Command does
not escalate privileges: if an action needs root it fails with systemd's own message, shown
verbatim.

## The OIL compiler is linked in, not shelled out

`src-tauri` depends on the `oilc` crate by path. Its stdlib (`schema.oil`, `predicates.oil`,
`builtins.oil`, `callables.oil`) is embedded with `include_str!`, so Studio compiles OIL
with no `oilc` binary, no control plane, and no network. That is what makes compile-on-
keystroke viable, and it means the Execution Plan view is derived from the *real* runtime IR
rather than a second model of the language.

The **Simulator** evaluates `oilc`'s own `RuntimeExpr` trees, so it cannot drift from the
compiler. It deliberately declines what it cannot do honestly — joins, temporal windows,
warm-state callables (`unusual_for`, `rate`, baselines) and graph traversal need runtime
state a desktop replay does not have, so those rules are reported as **skipped with a
reason** instead of being approximated.

## Running it

```bash
cd app/command
npm install
npm run tauri dev          # or: npm run build && cargo build --manifest-path src-tauri/Cargo.toml
```

System dependencies are the standard Tauri v2 Linux set: `webkit2gtk-4.1`, `gtk3`,
`libsoup-3.0`.

Endpoints, snapshot paths, the systemd unit name and one credential are configured in
**Settings** and stored at `~/.config/olopa-command/settings.json`. HTTP is issued from
Rust, so neither server needs CORS and the credential never reaches page JavaScript.

### Seeing populated panels without a running agent

`fixtures/` holds example snapshots matching the agent's exact contract:

```bash
mkdir -p /tmp/olopa/agent
cp fixtures/agent-status.example.json    /tmp/olopa/agent/status.json
cp fixtures/secure-connect.example.json  /tmp/olopa/agent/secure-connect.json
```

These are handwritten fixtures, not recorded agent output. Delete them before trusting
anything the panels show. Note `generated_at_unix_ms` is fixed, so the Agent panel will
correctly flag the snapshot as stale.

## Workflow it is built around

The point of the app is one loop:

**see a suspicious event → draft a detection from it → compile → simulate → publish → deploy**

Telemetry's wand icon generates starter OIL from a real event and drops you into Studio with
it loaded. Studio and Simulator share one buffer, so "Simulate" is a navigation, not a copy.
Publishing posts to the control plane's rule registry, which recompiles server-side and
refuses anything without deployable runtime IR.

`⌘K` / `Ctrl+K` opens the command palette for navigation, agent lifecycle (confirmed), and
the diagnostic bundle.

## Layout

```
app/command/
  src/                     React 19 + Tailwind 4, dark-only operator theme
    panels/                one file per surface
    state/                 shared agent poller + OIL buffer
    lib/                   typed IPC bridge, filter language, event helpers
  src-tauri/src/
    agent.rs               status snapshots, systemd lifecycle, host facts
    oil.rs                 in-process compile + execution-plan derivation
    sim.rs                 runtime-IR evaluator (has tests)
    ebpf.rs                bpftool inventory
    remote.rs              ingest / control-plane HTTP
    diagnostics.rs         journal tail + bundle export
  fixtures/                example snapshots (handwritten)
```

## Not in this version

Investigation graph, attack timeline, network map with per-connection enforcement detail,
and natural-language rule generation. The eBPF panel shows map capacity but not live
occupancy, because the kernel does not expose occupancy and guessing it would be worse than
omitting it.
