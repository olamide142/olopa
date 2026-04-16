# OIL Rules: Authoring, Compilation, and Agent Rollout

This guide is a practical starting point for:

- writing OIL rules,
- compiling rules into runtime IR,
- loading those rules on agents,
- operating token-based agent ingestion.

It also calls out what is implemented today vs the intended fleet rollout model.

## 1) Write OIL Rules

Start with one rule per file while onboarding users.

Example:

```oil
rule "suspicious_shell_outbound" {
  from endpoint.process, network.flow

  correlate
    process.spawn as p
    with network.connect as n on n.process_id == p.id

  where
    p.name in ["bash", "sh", "zsh"]
    and n.direction == "outbound"
    and n.dest.port in [22, 4444, 8080]

  respond
    alert high "suspicious shell outbound activity"
    open case "Shell outbound network activity"
}
```

Reference docs:

- grammar: `docs/oilc/grammar.md`
- compiler internals: `docs/oilc/howitworks.md`

## 2) Compile Rules (CLI)

Validate one file or a directory of `.oil` files:

```bash
cargo run --manifest-path oilc/Cargo.toml -- \
  --source oilc/src/rules \
  --mode check
```

Emit runtime IR artifact for agents:

```bash
cargo run --manifest-path oilc/Cargo.toml -- \
  --source oilc/src/rules \
  --mode runtime-ir \
  --emit-runtime-ir /tmp/runtime-ir.json \
  --diagnostics-format json
```

Notes:

- A single input emits one `RuntimeProgram` JSON object.
- Multiple inputs emit a multi-unit artifact (`version` + `units[]`).
- Agent runtime supports both formats.

## 3) Compile Rules (Control Plane API)

The control plane exposes:

- `POST /api/v1/control/compiler/compile`

Example:

```bash
curl -sS -X POST http://127.0.0.1:8100/api/v1/control/compiler/compile \
  -H 'content-type: application/json' \
  -d '{
    "source_path": "/home/olamide/dev/olopa/oilc/src/rules",
    "mode": "runtime-ir",
    "emit_runtime_ir": "/tmp/runtime-ir.json"
  }'
```

Response includes `ok`, `exit_code`, `stdout`, `stderr`, and parsed `stdout_json` when available.

## 4) Add Compiled Rules to Agents (Implemented Today)

Current implementation is file-based loading at agent startup.

1. Compile and produce `runtime-ir.json`.
2. Distribute artifact to each agent host.
3. Place it at `/etc/olopa/runtime-ir.json` (default), or set `OLOPA_RUNTIME_IR`.
4. Restart the agent process/service.

Key runtime behavior:

- Default runtime IR path: `/etc/olopa/runtime-ir.json`.
- If runtime IR is invalid/missing, agent startup fails by default.
- Optional fallback is available with `OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1`.

## 5) Agent Auth Token Onboarding (Ingest API)

Ingest server token model is controlled by `INGEST_API_TOKENS`.

Format:

- `token-a` for global scope
- `token-b:tenant-alpha` for one tenant
- `token-c:tenant-a|tenant-b` for multiple tenants
- `token-d:*` for global scope

Example ingest server config:

```bash
export INGEST_API_TOKENS="ops-global-token,agent-acme-token:acme"
```

Example agent config:

```bash
export OLOPA_INGEST_URL="http://127.0.0.1:8000/api/v1/ingest/batches"
export OLOPA_INGEST_TENANT_ID="acme"
export OLOPA_INGEST_API_TOKEN="agent-acme-token"
```

Quick verification:

```bash
curl -sS -H "Authorization: Bearer ops-global-token" \
  http://127.0.0.1:8000/api/v1/ingest/stats

curl -sS -H "Authorization: Bearer agent-acme-token" \
  "http://127.0.0.1:8000/api/v1/ingest/recent?tenant_id=acme&limit=20"
```

## 6) Fleet Rollout Model

### Implemented now

- Rules are compiled into runtime IR.
- Runtime IR is loaded locally by each agent process.
- Agents continue telemetry ingestion through `/api/v1/ingest/batches` while evaluating loaded rules.

### Intended target flow (product direction)

1. Agent is enrolled with control plane using an auth token.
2. User submits rule changes in control plane.
3. Control plane compiles OIL to runtime IR.
4. Control plane distributes the new runtime IR to all enrolled/targeted agents.
5. Agents acknowledge new rule version and continue ingesting telemetry without fleet-wide downtime.

## 7) Current Gaps to Track

In this repository today, these capabilities are not yet implemented end-to-end:

- control-plane agent enrollment/registration API,
- control-plane managed runtime IR distribution to all agents,
- versioned rollout/rollback orchestration across agent fleet.

Use this document as the baseline workflow until those control-plane deployment features are added.
