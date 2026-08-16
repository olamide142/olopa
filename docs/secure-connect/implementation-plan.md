# Olopa Secure Connect (WireGuard) Implementation Plan

## 0) Implementation status

Phases 0-4 are implemented. Where the delivered design departs from this plan,
the reason is recorded inline below.

| Component | Location | State |
| --- | --- | --- |
| Endpoint runtime | `agent/agent/src/secure_connect/` | Implemented |
| Orchestrator | `app/control_plane/control_server/secure_connect/` | Implemented |
| Gateway plane | `app/secure_connect_gateway/` | Implemented (option A reconciler) |

Deviations from the plan as written:

- **Persistence is SQLAlchemy, not SurrealDB.** The control plane runs on
  SQLite/SQLAlchemy, so the graph edges in section 6 are foreign keys on
  `sc_session`, and the section 9 live query is a polling subscriber over the
  ingest alert stream (`risk_subscriber.py`). The correlation semantics are
  unchanged: alerts anchored to a host drive every live session on that host.
- **Operator relaxations are narrower than section 5 implies.** The endpoint
  refuses any unconfirmed relaxation locally, and it only accepts
  `elevated -> healthy`. Recovering a restricted or quarantined session
  therefore goes through termination and a fresh session rather than an
  operator-confirmed downgrade in place.
- **Pydantic schemas live in `schemas.py`,** not `models.py`, because ORM models
  belong under the existing `control_server/models/` package.

Phase 5 is implemented: gateway health reporting, drain/failover with transparent
session migration, a load-test harness (`app/control_plane/tools/sc_loadtest.py`),
and operator runbooks with measured capacity limits
([`runbooks.md`](./runbooks.md)).

The load test surfaced the real capacity ceiling: **SQLite serialises writers, so
session establishment collapses past roughly 8 concurrent starts.** Enrollment and
heartbeat scale fine. Production deployments beyond a pilot must run PostgreSQL —
see runbook section 1. Two fixes came out of that measurement: SQLite now runs in
WAL mode with `synchronous=NORMAL` (a ~100x latency improvement, and the reason the
control-plane test suite dropped from ~100s to ~4s), and the address allocator no
longer relies on SAVEPOINT, which pysqlite does not implement reliably.

## 1) Goal

Build a dedicated **Secure Connect** subsystem so the `olopa` agent can function as a managed, zero-trust VPN client for employee access, with centralized server-side orchestration in the control plane.

This is intentionally separate from telemetry ingest so VPN availability and policy orchestration do not depend on ingest hot-path behavior.

## 2) Why this should be a separate part of the agent

The current agent is optimized for eBPF telemetry capture, local rule/runtime evaluation, and event shipping. A managed VPN client introduces a different responsibility set:

- tunnel lifecycle management,
- credential/session lifecycle,
- route and DNS policy enforcement,
- interactive access posture controls,
- fast revocation and rekey.

Keeping this as a separate subsystem avoids coupling VPN reliability to telemetry pipelines and keeps failure domains smaller.

## 3) Current architecture fit (what changes vs what stays)

### Existing components (stay in place)

- `agent/agent`: endpoint runtime (probes, runtime rule eval, ingest sender)
- `app/ingest_server` (`olopa-ingest`): telemetry ingest/read hot path
- `app/control_plane`: orchestration APIs and product workflows

### New logical subsystem

- `Secure Connect` in `olopa` agent (endpoint VPN runtime)
- `Secure Connect Orchestrator` in Python control plane (server-side authority)
- optional `Secure Connect Gateway` plane (WireGuard endpoints / relays)

### Ownership boundary

| Area | Owner |
| --- | --- |
| WireGuard tunnel up/down, local routes, DNS, kill switch | agent (`olopa`) |
| Device enrollment, identity binding, key/cert issuance, policy assignment, revocation | control plane |
| Telemetry transport ingest (`/api/v1/ingest/*`) | `olopa-ingest` |
| Cross-endpoint risk correlation and adaptive access decisions | control plane |

## 4) Target architecture

```text
[olopa agent]
  |- sensor + runtime engine (existing)
  |- secure_connect runtime (new)
      |- wg interface manager
      |- policy applier (routes, dns, acl)
      |- posture reporter
      |- orchestration client
              |
              | mTLS + signed control messages
              v
[Python control plane]
  |- secure_connect orchestrator (new)
      |- enrollment + identity binding
      |- peer/session lifecycle
      |- policy compiler (access profile -> wg + acl)
      |- risk adapter (ingest alerts/correlation -> access state)
      |- audit trail
              |
              v
[WireGuard gateway plane]
  |- regional gateways / relays
  |- optional egress segmentation

[olopa-ingest]
  |- unchanged hot path
  |- stores secure_connect posture + tunnel events as telemetry
```

## 5) High-level runtime model

1. Device enrollment: agent receives one-time enrollment token and registers endpoint identity.
2. Session bootstrap: control plane issues short-lived tunnel credentials + gateway assignment.
3. Tunnel establish: agent brings up WireGuard interface and applies route/DNS policy.
4. Continuous posture loop: agent reports health/posture; control plane can push updates.
5. Risk-adaptive control: detections from ingest + control-plane correlation can downgrade/lock session.
6. Rekey/revoke: control plane rotates keys or tears down access immediately.

State transitions to more restrictive access are automatic; transitions to less restrictive access require operator confirmation, except controlled cooldown (`elevated -> healthy`) after clean posture.

## 6) Data model (control plane)

Use existing server persistence strategy (SurrealDB-first where practical) and keep schema tenant-scoped.

### Core entities

- `sc_device`
  - `id`, `tenant_id`, `host_id`, `user_id`, `device_fingerprint`, `state`
- `sc_enrollment`
  - `id`, `tenant_id`, `token_hash`, `expires_at`, `used_at`, `issued_by`
- `sc_gateway`
  - `id`, `region`, `public_key`, `public_endpoint`, `status`, `capacity`
- `sc_profile`
  - `id`, `tenant_id`, `name`, `allowed_cidrs`, `dns_policy`, `split_tunnel`, `risk_policy`
- `sc_session`
  - `id`, `tenant_id`, `device_id`, `gateway_id`, `profile_id`, `started_at`, `expires_at`, `state`
- `sc_key_material`
  - `id`, `session_id`, `key_id`, `issued_at`, `expires_at`, `revoked_at`
- `sc_audit_event`
  - `id`, `tenant_id`, `actor`, `action`, `target`, `result`, `reason`, `ts`

### Required graph edges (SurrealDB)

These edges make risk correlation and enforcement a single traversal instead of cross-system joins:

- `sc_device -> bound_to -> user`
- `sc_session -> for_device -> sc_device`
- `sc_session -> via_gateway -> sc_gateway`
- `sc_session -> governed_by -> sc_profile`
- `sc_session -> anchored_to -> host` (critical cross-domain bridge to detection graph)

Reference SurrealQL:

```surrealql
RELATE sc_device:$device -> bound_to -> user:$user
  SET bound_at = time::now(), binding_type = "enrollment";

RELATE sc_session:$session -> for_device -> sc_device:$device;
RELATE sc_session:$session -> via_gateway -> sc_gateway:$gateway;
RELATE sc_session:$session -> governed_by -> sc_profile:$profile;
RELATE sc_session:$session -> anchored_to -> host:$host
  SET anchor_ts = time::now();
```

## 7) API contract (control plane)

All endpoints require auth + tenant scope.

### Enrollment and bootstrap

- `POST /api/v1/secure-connect/enrollment-tokens`
  - create one-time enrollment token
- `POST /api/v1/secure-connect/enroll`
  - token exchange for device registration
- `POST /api/v1/secure-connect/sessions/start`
  - issue tunnel config (gateway, peer config, profile)

Enrollment token contract (required):

- signed JWT with `tenant_id`, `user_id`, `jti`, `device_hint`, `exp <= 15m`
- `jti` tracked server-side for single-use enforcement
- redemption requires mTLS device cert; cert public key becomes device binding material
- token consume + `sc_device` creation occurs in one DB transaction (atomic success/fail)

### Session lifecycle

- `POST /api/v1/secure-connect/sessions/{id}/heartbeat`
  - agent liveness/posture update
- `POST /api/v1/secure-connect/sessions/{id}/rekey`
  - rotate session keys with no-gap cutover (new peer registered before endpoint flips keys)
- `POST /api/v1/secure-connect/sessions/{id}/terminate`
  - immediate session teardown

### Policy and fleet operations

- `GET /api/v1/secure-connect/devices`
- `GET /api/v1/secure-connect/sessions`
- `POST /api/v1/secure-connect/profiles`
- `POST /api/v1/secure-connect/profiles/{id}/assign`
- `POST /api/v1/secure-connect/devices/{id}/quarantine`

## 8) Agent subsystem design

Create a dedicated module in the agent:

```text
agent/agent/src/secure_connect/
  mod.rs
  config.rs
  orchestrator_client.rs
  session_manager.rs
  wireguard_manager.rs
  policy_applier.rs
  posture.rs
  health.rs
```

### Responsibilities

- `orchestrator_client`: talks to control-plane secure-connect APIs.
- `session_manager`: state machine (`idle -> enrolling -> connecting -> healthy -> elevated -> restricted -> quarantined -> terminated`).
- `wireguard_manager`: creates interface and peer config; generates endpoint keypairs locally; private key never leaves endpoint process.
- `policy_applier`: route table, DNS resolver policy, kill-switch behavior with atomic application guarantees.
- `posture`: emits baseline self-reported posture first, then adds eBPF-verified facts from sensor/event-window integration.
- `health`: emits status for `olopa status --verbose`.

### WireGuard key lifecycle contract

- Agent generates WireGuard keypairs locally and only publishes public keys.
- Control plane stores/distributes public keys only, never private endpoint material.
- Rekey flow: agent submits new public key, control plane updates gateway peer, gateway acknowledges, then agent flips to new private key.
- Revoke flow: control plane removes peer + sends terminate command; agent applies kill switch within 2 seconds target.

### Non-goals for first implementation

- Mesh peer-to-peer between endpoints.
- Full SD-WAN traffic engineering.
- Data-plane packet inspection inside VPN component (existing sensor pipeline already handles telemetry).
- L7 application proxy mode (network-level ZTNA only for initial releases).
- MDM SDK integrations as posture dependencies.

## 9) Control-plane orchestrator design

Add server module in control plane:

```text
app/control_plane/control_server/secure_connect/
  __init__.py
  router.py
  models.py
  service.py
  allocator.py
  key_manager.py
  risk_adapter.py
  audit.py
```

### Responsibilities

- Device identity binding and enrollment token management.
- Gateway allocation (region/capacity-aware).
- Key lifecycle (issue, rotate, revoke).
- Policy compile/distribution from profile to endpoint config.
- Risk adapter that consumes detection signals and adjusts session state via an explicit transition engine.
- Full auditability for every mutating operation.

### Risk state machine (required)

States:

- `HEALTHY`
- `ELEVATED`
- `RESTRICTED`
- `QUARANTINED`
- `TERMINATED`

Transition policy:

- Restrictive transitions are automatic (`alert_medium/high/critical`).
- Relaxing transitions require operator confirmation, except `ELEVATED -> HEALTHY` after cooldown + clean posture window.
- `TERMINATED` is terminal and requires re-enrollment.

Action mapping:

- `ELEVATED`: step-up auth, tighter heartbeat cadence.
- `RESTRICTED`: safe-CIDR policy only, reconfirm auth.
- `QUARANTINED`: kill switch on, revoke keys, security paging.
- `TERMINATED`: clear peer config and invalidate device enrollment posture.

Correlation trigger:

- Register SurrealDB live query for active sessions anchored to hosts with unresolved `CRITICAL` alerts.
- On match, force transition to `QUARANTINED` and emit audit event.

Reference SurrealQL pattern:

```surrealql
LIVE SELECT sc_session.*
FROM sc_session
WHERE ->anchored_to->host
  <-has_process<-process
  ->triggered_alert->(alert WHERE severity = "CRITICAL" AND resolved = false) != none
AND sc_session.state NOT IN ["QUARANTINED", "TERMINATED"];
```

## 10) Gateway plane options

### Option A (recommended first)

Use managed/dedicated WireGuard gateways outside this repo; Olopa control plane orchestrates peers and policies only.

Why first:

- faster delivery,
- avoids overloading current two-server build,
- still enables enterprise VPN workflow.

### Option B (later)

Add an `olopa-gateway` service managed alongside ingest/control plane when custom L7 enforcement at gateway is needed.

## 11) Policy model

Profiles should be intent-driven and map to deterministic endpoint behavior:

- `access_mode`: `split_tunnel` | `full_tunnel`
- `allowed_cidrs`: internal destinations
- `dns_policy`: resolvers + domain restrictions
- `session_ttl`
- `rekey_interval`
- `risk_actions`:
  - `observe`
  - `step_up_auth`
  - `restrict_to_safe_cidrs`
  - `quarantine`
  - `terminate`

### Posture facts model

Phase 1-2 heartbeat payloads prioritize delivery reliability and include baseline self-reported facts (`os_version`, `agent_version`, disk encryption, local health checks). After revocation reliability is proven (Phase 3), add eBPF-verified posture facts sourced from sensor windows:

- probe health integrity
- unsigned execution detection status
- shell-from-network detection status
- credential-path access indicators
- process-tree integrity status
- unexpected kernel module load counters

This split keeps early rollout simple while preserving the long-term differentiator (kernel-verified posture vs self-report only).

## 12) Security controls

- One-time enrollment JWTs (15m max TTL) with `jti` replay protection and single-use semantics.
- Enrollment token bound to issuing `tenant_id` and `user_id`; not redeemable cross-tenant/user.
- Enrollment exchange requires mTLS device certificate; resulting public key/fingerprint permanently binds to `sc_device`.
- Token redemption and enrollment state update are atomic in SurrealDB transaction boundaries.
- Short-lived tunnel credentials with forced rekey.
- Tenant-bound identity on every request and every secure-connect command.
- Message signing / nonce checks for control commands.
- Default-deny kill switch on session loss (configurable safety mode).
- Immediate revocation path (SLO <= 10 seconds, engineering target <= 3 seconds end-to-end).
- Strong audit logging for enrollment, policy changes, session terminations.

## 13) Observability and SLOs

### Agent metrics

- tunnel state (`up/down/degraded`)
- handshake age
- bytes tx/rx
- reconnect count
- policy apply latency
- revoke apply latency
- kill-switch apply latency
- posture freshness age

### Control-plane metrics

- enroll success/failure rate
- session start latency
- gateway capacity utilization
- rekey success/failure
- revoke propagation latency
- risk transition latency (`alert -> restricted/quarantined`)
- live-query trigger to action latency

### Initial SLO targets

- session establish p95: <= 8s
- policy push apply p95: <= 5s
- revoke propagation p95: <= 10s
- revoke propagation target (engineering): <= 3s
- monthly orchestrator API availability: >= 99.9%

## 14) Phase-by-phase implementation plan

### Phase 0: Contracts and scaffolding

Scope:

- define secure-connect API schemas,
- create agent/control-plane module scaffolds,
- add feature flags and config plumbing.

Deliverables:

- OpenAPI spec for `/api/v1/secure-connect/*`
- agent config keys (`OLOPA_SC_*`)
- control-plane route stubs + auth guards

Exit criteria:

- endpoints return deterministic schema (even if stubbed),
- agent starts with secure-connect feature disabled by default.

### Phase 1: Enrollment + session bootstrap MVP

Scope:

- token-based enrollment with mTLS-bound device identity,
- session start endpoint,
- WireGuard interface up/down from agent.

Deliverables:

- working `enroll -> start session -> tunnel up` flow
- session persisted with tenant/device linkage
- atomic token redemption + device creation path

Exit criteria:

- at least one test tenant can connect through assigned gateway,
- failed auth/token reuse is rejected and audited.

### Phase 2: Policy application + heartbeats

Scope:

- apply profile-driven routes and DNS,
- periodic heartbeat/posture reporting (baseline self-reported facts first),
- admin APIs for sessions/devices.

Deliverables:

- policy profile create/assign APIs
- agent heartbeat loop with backoff
- status integration in CLI output

Exit criteria:

- profile updates are applied without agent restart,
- stale sessions are detected and marked degraded.

### Phase 3: Rekey, revocation, and kill switch

Scope:

- key rotation scheduling,
- immediate revoke path,
- deterministic kill-switch behavior.

Deliverables:

- rekey endpoint and agent rekey handler
- terminate/quarantine action path
- revoke latency instrumentation

Exit criteria:

- revoked session loses access within SLO target,
- engineering target path demonstrates <= 3s in controlled environments,
- rekey does not interrupt healthy session beyond allowed threshold.

### Phase 4: Risk-adaptive orchestration

Scope:

- integrate ingestion/control detections into access decisions,
- add eBPF-verified posture facts to heartbeat scoring,
- enforce risk actions (`restrict`, `quarantine`, `terminate`).

Deliverables:

- `risk_adapter` consuming alert stream/correlation output
- policy transition engine with audit trail
- SurrealDB live-query correlation from detection graph to active sessions

Exit criteria:

- demo: suspicious behavior triggers automatic access restriction,
- false-positive safeguards (cooldown and manual override) are in place.

### Phase 5: Production hardening

Scope:

- scale tests,
- multi-gateway balancing,
- disaster recovery and rollback playbooks.

Deliverables:

- load-tested session orchestration
- gateway failover strategy
- operator runbooks

Exit criteria:

- capacity and failover tests meet reliability targets,
- on-call playbooks verified in game-day exercises.

## 15) How this integrates with current Olopa architecture

### `olopa-ingest` impact

- no control-plane ownership shift,
- remains telemetry hot path,
- stores secure-connect telemetry events (`sc_session_event`, posture metrics) as standard event families.
- canary fast-path rules also treat unexpected gateway-IP access attempts as high-priority detection input.
- no new gRPC ingress surface required; existing telemetry stream carries secure-connect event types.

### Python control-plane impact

- gains a new vertical (`secure_connect`) for identity/session/policy orchestration,
- subscribes secure-connect risk adapter to existing alert stream fan-out,
- registers live queries that map host/process alerts to active secure-connect sessions,
- continues to own cross-endpoint correlation and fleet-level decisions.

### Agent impact

- new subsystem runs alongside existing sensor/rule pipelines,
- secure-connect failures do not crash telemetry pipeline,
- telemetry from secure-connect feeds existing detection/correlation workflows,
- WireGuard private keys are generated and retained locally on endpoint.

## 16) Risks and mitigations

- Risk: control-plane outage strands access changes.
  - Mitigation: last-known-good policy cache in agent with explicit expiry.
- Risk: key compromise.
  - Mitigation: short-lived keys, aggressive rekey, fast revoke.
- Risk: route/DNS misconfiguration causes lockout.
  - Mitigation: canary rollout per profile and break-glass bypass profile.
- Risk: tight coupling with ingest causes contention.
  - Mitigation: separate APIs and workers for secure-connect orchestration.

## 17) Immediate next implementation tasks

1. Create secure-connect API schema and route stubs in control plane.
2. Add agent module scaffolding and config parser for `OLOPA_SC_*`.
3. Implement enrollment token issuance/exchange with JWT `jti` tracking, mTLS cert binding, and atomic redemption.
4. Implement minimal WireGuard session bring-up/teardown behind feature flag with local-only private key generation.
5. Implement profile-driven routes/DNS and baseline heartbeat posture payload.
6. Add basic `olopa status --verbose` secure-connect health block + revoke latency metrics.
