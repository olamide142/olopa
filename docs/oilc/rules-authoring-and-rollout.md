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

## 8) Testable Rule Collection

`oilc/src/rules/testable/` holds one rule per file, each self-contained and
individually runnable:

```bash
cargo run --manifest-path oilc/Cargo.toml -- \
  --source oilc/src/rules/testable/<rule>.oil --mode check
```

`scripts/rule_smoke.py` runs the subset of these rules that the ingest
server's central correlation engine can evaluate end to end — compile, load
into the engine, post a positive fixture and confirm a matching alert, post
a negative fixture and confirm no alert:

```bash
python scripts/rule_smoke.py                 # all rules
python scripts/rule_smoke.py --rule <name>    # one rule
```

Two real evaluator gaps were found and fixed while building this collection:

- `dns.*` and `ssl.*` rule sources fell through a silent catch-all in
  `CompiledRule::compile` (`app/ingest_server/src/correlation/engine.rs`) and
  were miscategorized as process events — routed to `EventFamily::Net` now,
  since that's genuinely where SSL/DNS telemetry lands on the wire.
- `x in org.threat_intel.*` had no backing store in the ingest server at
  all — `intel.domains`/external-set membership always evaluated to
  nothing. Fixed via `app/ingest_server/src/correlation/threat_intel.rs`,
  a Redis-backed cache mirroring the agent's `IntelStore` (see
  `docs/mvp.md` or the intel_sync section of this repo for the Redis
  distribution model).

The 9 rules this covers, and how each is tested:

| Rule | Feature area | Test path |
|---|---|---|
| `mvp_exec_seen` | Process & shell | HTTP smoke (`rule_smoke.py`) |
| `root_ssh_write_by_non_root_process` | Process & shell | HTTP smoke |
| `outbound_to_specific_website` | Network | HTTP smoke |
| `ssl_large_single_encrypt_call` | Network/SSL | HTTP smoke + `correlation::tests::ssl_domain_routes_to_net_family_and_resolves_operation_and_data_len` |
| `dns_c2_domain_lookup` | Network/DNS | agent-layer only (`agent::tests::dns_c2_domain_lookup_resolves_threat_intel_membership_and_fires`) — see below |
| `credential_access_followed_by_egress` | Credential access | HTTP smoke |
| `lateral_movement_after_credential_harvest` | Lateral movement | HTTP smoke |
| `block_untrusted_finance_reads` | SQL guard | HTTP smoke |
| `sql_privilege_grant_from_unprivileged_proc` | SQL guard | HTTP smoke |
| `unexpected_secure_connect_gateway_access` | Secure Connect | agent-layer only (`agent::tests::matches_unexpected_secure_connect_gateway_access`) |

`dns_c2_domain_lookup` is technically reachable through the ingest server too
after the threat-intel fix above (see
`correlation::tests::threat_intel_domain_membership_resolves_through_eval_call`),
but `rule_smoke.py` doesn't exercise it there — doing so would mean seeding
Redis with a throwaway IOC via a real `intel_sync` run or a direct write,
which adds a live dependency to a fixture-driven smoke script for coverage
the agent-layer test already gives deterministically.

### Excluded from the collection — real gaps, not oversights

**Container/Kubernetes rules** (`shell_spawn_in_container.oil`,
`launch_of_priviledge_container.oil`, `unexpected_process_in_container.oil`):
reference `container.runtime`, `k8s.admission`, `identity.session`, and
`k8s.workload` domains that have no event source, wire schema field, or
runtime field extractor in *either* evaluator (checked
`app/ingest_server/src/correlation/engine.rs`'s domain routing and
`agent/agent/src/runtime_ir.rs`'s canonical field table). This isn't a
routing bug like DNS/SSL — there's no container/k8s telemetry capture
subsystem to route to. Building one (container runtime metadata collection,
a Kubernetes admission integration, an identity/session provider) is a
separate, larger feature, not a rule-testing gap.

**Most `secure_connect/` rules** (`prod_access_requires_clean_device.oil`,
`revoke_session_on_critical_host_signal.oil`,
`secure_connect_graph_risk_chain.oil`): use OIL language constructs
(`match ... then`, `verify require`, `graph { ... }` traversal blocks) or a
domain (`endpoint.alert`) that no runtime evaluator implements — confirmed
by `grep`ing both engines for `graph`/`match...then`/`verify`/`endpoint.alert`
handling, which found none. `prod_access_requires_clean_device.oil` at least
parses and resolves (it would compile to IR that no evaluator can act on);
`revoke_session_on_critical_host_signal.oil` and
`secure_connect_graph_risk_chain.oil` don't even parse today —
`cargo run --manifest-path oilc/Cargo.toml -- --source oilc/src/rules --mode check`
fails both with `unknown/unsupported clause` and `expected graph entity type`
errors respectively. Also currently broken the same way, unrelated to this
work: `duration_expression_examples.oil`, `launch_of_priviledge_container.oil`
(also a container/k8s rule, see below), and
`stress_test/mir_expr_score_branching.oil`.

`secure_connect_scope_violation.oil` is a narrower case: running
`oilc --mode check` on it (see `oilc/src/rules/testable/secure_connect_scope_violation.oil`'s
header comment) surfaces compiler warnings that `n.dest_domain`,
`n.process_name`, `sc.session_id`, and `sc.scope` are unresolved fields on
their respective entities — likely typos in the original rule text
(`dest_domain` vs. the real `dest.domain`, `sc.session_id` vs. the real
`sc.id`) mixed with at least one genuinely missing field (`scope` has no
extractor anywhere). Kept in `testable/` with its warnings intact as
documentation of the bug, but excluded from both the HTTP smoke collection
and the agent-layer Rust tests since it cannot be made to fire without
either fixing the rule text or extending the field table — a decision for
whoever owns that rule, not something to silently work around here.
