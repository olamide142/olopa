# Control Plane Plan

## 1) Purpose

This document is the execution plan for the Python FastAPI control plane (`app/control_plane`).

Goals:

- define what the control plane owns,
- define implementation order,
- define concrete procedures and done criteria,
- cover missing features needed for production.

## 2) Ownership Boundaries

| Area | Control Plane Owns | Other Service Owns |
| --- | --- | --- |
| Ingest hot path | dashboard-facing proxy, orchestration decisions | Rust ingest write/read hot path |
| Rule lifecycle | authoring APIs, validation/compile orchestration, versioning, deploy workflow | `oilc` compile engine |
| Runtime operations | incidents, agent fleet desired-state, settings, audit trails | agent runtime enforcement |
| Auth and tenancy | user/service auth, RBAC, tenant scoping | upstream IdP / mTLS infra |
| Reporting | KPI APIs, exports, scheduled reports | raw telemetry storage |

## 3) Current Baseline

Implemented now:

- `GET /health`
- `GET /api/v1/control/status`
- ingest proxy endpoints (`/api/v1/ingest/*`, `/api/v1/dashboard/ingest/*`)
- `POST /api/v1/control/compiler/compile`
- explicit dev/JWT/service-token authentication with tenant-bound identities,
- hierarchical RBAC guards on control, ingest-proxy, compiler, intel, rule,
  deployment, and audit APIs,
- persistent tenant-scoped rules, immutable rule versions, deployments, and
  audit events,
- real `oilc` diagnostics/runtime-IR compilation for rule validation and
  persistence,
- deployment transition and rollback validation with tenant-scoped
  idempotency keys,
- Secure Connect orchestrator (`/api/v1/secure-connect/*`): single-use
  mTLS-bound enrollment, gateway/address allocation, profile compilation,
  heartbeat command channel with monotonic nonces, rekey, revocation, the
  risk-adaptive access state machine, a background reaper plus detection-stream
  risk subscriber, and SLO metrics.

Missing now:

- external OIDC/JWKS identity-provider integration and key rotation,
- atomic audit writes for every remaining mutation (compiler and intel sync),
- asynchronous compiler/deployment jobs and real agent-fleet rollout delivery,
- incident and fleet management,
- robust observability and reliability controls.

## 4) Delivery Structure

### Phase 0: Security and Control Foundations

Objective:

- secure all control-plane endpoints,
- establish tenant boundaries and auditability.

#### Epic 0.1 Authentication

Implementation procedure:

1. Add auth dependency in FastAPI and central `RequestContext`.
2. Support modes: dev token, JWT/OIDC user token, service token/mTLS identity mapping.
3. Add `GET /api/v1/auth/whoami`.
4. Standardize auth error response shape.

Done criteria:

- all non-health endpoints require auth,
- integration tests cover valid/invalid/expired token paths.

#### Epic 0.2 Authorization and Tenancy

Implementation procedure:

1. Define roles: `viewer`, `analyst`, `operator`, `admin`.
2. Publish permission matrix by endpoint/action.
3. Enforce tenant filtering in request context and query layer.
4. Add endpoint guards/decorators and deny-by-default fallback.

Done criteria:

- explicit permission guard on each endpoint,
- cross-tenant access attempts fail in tests.

#### Epic 0.3 Audit Logging

Implementation procedure:

1. Add `audit_events` schema (`actor`, `tenant`, `action`, `target`, `result`, `request_id`, `timestamp`).
2. Emit audit events for all mutating operations.
3. Add `GET /api/v1/audit/events` with pagination and RBAC.

Done criteria:

- every mutation has an audit event,
- audit retrieval endpoint is available and access controlled.

Phase exit criteria:

- secure-by-default control plane,
- tenant isolation verified,
- complete mutation audit trail.

### Phase 1: Rule Lifecycle and OIL Product Surface

Objective:

- make rules first-class resources with safe promotion and rollback.

#### Epic 1.1 Rule Registry and Versioning

Implementation procedure:

1. Add entities: `rule`, `rule_version`, `rule_bundle`.
2. Add APIs: create/list/get rules, create/list/get versions.
3. Store metadata (`owner`, `changelog`, `hash`, `created_at`).
4. Make versions immutable.

Done criteria:

- rule history is immutable and queryable,
- API supports full CRUD for metadata and create-only for versions.

#### Epic 1.2 Validate/Compile/Test APIs

Implementation procedure:

1. Keep compile endpoint; normalize diagnostics envelope.
2. Add `POST /api/v1/rules/validate` (lint/parse/typecheck).
3. Add `POST /api/v1/rules/test` (fixtures + expected assertions).
4. Persist compile/test artifacts by `rule_version_id`.

Done criteria:

- each rule version has stored diagnostics and artifact references,
- validation/test can run independently of deployment.

#### Epic 1.3 Deployment, Promotion, Rollback

Implementation procedure:

1. Add `deployment` entity with state machine.
2. Add APIs: create deployment, get status, rollback deployment.
3. Add preflight gates: compatibility checks, environment readiness, idempotency key.
4. Add rollout strategy fields (`direct`, `canary`) and failure policy.

Done criteria:

- rollback is one API call and audited,
- invalid state transitions are blocked by server logic.

#### Epic 1.4 IDE Backend Support

Implementation procedure:

1. Add APIs for templates, snippets, examples.
2. Add diagnostics mapping format (line/col/span/severity/code).
3. Add draft autosave/recovery APIs.
4. Add version diff endpoint.

Done criteria:

- frontend can build editor workflows without embedding compiler behavior client-side.

Phase exit criteria:

- versioned rule lifecycle is operational from draft to rollback.

### Phase 2: Operations (Incidents, Fleet, Settings)

Objective:

- provide operational control features required by SOC/platform teams.

#### Epic 2.1 Incident Management

Implementation procedure:

1. Add entities: `incident`, `timeline_event`, `assignment`, `comment`.
2. Add APIs: create/list/get/update/assign/escalate/close.
3. Add alert-to-incident correlation and dedupe key.
4. Add SLA fields and overdue status logic.

Done criteria:

- incidents can be managed end-to-end with timeline history.

#### Epic 2.2 Agent Fleet Management

Implementation procedure:

1. Add entities: `agent`, `agent_group`, `heartbeat`, `desired_state`.
2. Add APIs: register, list, cordon/drain, target-version update.
3. Add assignment rules: policy/rule bundles by group/tag.
4. Add drift detection (`desired` vs `reported`).

Done criteria:

- fleet can be managed at group level, not host-by-host.

#### Epic 2.3 Settings Management

Implementation procedure:

1. Define typed settings schema with validation.
2. Split secret references from non-secret settings.
3. Add staged update + preview + rollback.
4. Emit audit event for each settings mutation.

Done criteria:

- settings changes are safe, reversible, and auditable.

Phase exit criteria:

- incident and fleet operations usable for day-to-day production workflows.

### Phase 3: Productization (Graph, Reporting, Integrations)

Objective:

- deliver mature analytics/reporting and external integration surface.

#### Epic 3.1 Graph Visualization Backend

Implementation procedure:

1. Define query contract (`nodes`, `edges`, `filters`, `cursor`).
2. Add `POST /api/v1/graph/query` with server-side filter validation.
3. Add presets: process tree, host timeline, incident neighborhood.
4. Add query caching and response size guards.

Done criteria:

- graph panel uses real backend query APIs.

#### Epic 3.2 Dashboard Reporting and Exports

Implementation procedure:

1. Add KPI endpoints (detection volume, MTTR, rule hit rate, fleet health).
2. Add time-series aggregation APIs with tenant scope.
3. Add export endpoints (CSV/JSON) with RBAC and audit logging.
4. Add scheduled report jobs and delivery channels.

Done criteria:

- dashboard and reports are generated from stable APIs with SLO targets.

#### Epic 3.3 Notifications and Integrations

Implementation procedure:

1. Add webhooks and Slack/Teams integrations.
2. Add retries, exponential backoff, and dead-letter queue.
3. Add signature verification for outbound webhook deliveries.

Done criteria:

- deployments/incidents can notify external systems reliably.

Phase exit criteria:

- product reporting and integration flows are production-ready.

## 5) Cross-Cutting Requirements (apply to all phases)

### 5.1 API Contract Standards

- standard error envelope (`code`, `message`, `details`, `request_id`),
- idempotency keys for mutating endpoints,
- pagination/filter/sort conventions,
- explicit API versioning and deprecation policy.

### 5.2 Async Job System

- background queue for compile/test/deploy/report jobs,
- job model with statuses and progress,
- `GET /api/v1/jobs/{id}` status endpoint.

### 5.3 Observability and SRE

- structured logs with request and trace IDs,
- metrics (`latency`, `errors`, `queue_depth`, `dependency_health`),
- distributed tracing across control plane -> compiler -> ingest,
- readiness/liveness probes.

### 5.4 Reliability and Disaster Recovery

- schema migration strategy with rollback,
- backup/restore process for control-plane state,
- multi-instance-safe job scheduling (leader election or external scheduler).

### 5.5 Security Hardening

- rate limiting and abuse protection,
- payload size limits and strict input validation,
- secret manager integration,
- dependency and container image scanning in CI.

### 5.6 Testing and CI/CD

- unit tests (auth/policy/validation),
- integration tests (compile/test/deploy/rollback),
- contract tests for ingest proxy behavior,
- CI gates for lint, typing, tests, security checks.

## 6) Missing Features Checklist

- [ ] Authentication and identity provider integration (local JWT and fixed
  service identities implemented; external OIDC/JWKS remains)
- [x] RBAC and tenant-aware authorization
- [ ] Mutation audit logs and query API (rule/deployment mutations covered;
  remaining mutations need atomic audit writes)
- [x] Rule registry and immutable versioning
- [ ] Rule validate/test APIs with artifact persistence (real validation and
  runtime IR persistence implemented; fixture execution remains provisional)
- [ ] Deployment state machine with rollback (validated persisted state and
  idempotency implemented; real fleet delivery/canary execution remains)
- [ ] IDE backend endpoints (templates/drafts/diff)
- [x] Secure Connect orchestration (enrollment, sessions, policy, rekey,
  revocation, risk transitions, detection-stream subscription, session reaping,
  SLO metrics, and the gateway reconciler in `app/secure_connect_gateway/`;
  multi-gateway failover and scale testing remain)
- [ ] Incident management APIs and SLA workflows
- [ ] Agent fleet desired-state management
- [ ] Typed settings lifecycle with rollback
- [ ] Graph query backend
- [ ] Dashboard KPI and export APIs
- [ ] Notification integrations and delivery reliability
- [ ] Async job system with status API
- [ ] Standardized API error and idempotency model (error envelope and
  deployment idempotency implemented; expand idempotency to other mutations)
- [ ] Full observability and SRE runbook coverage
- [ ] DR/backup strategy and restore drills
- [ ] CI quality and security gates

## 7) First 2 Sprints (Concrete Plan)

Sprint 1:

1. Implement auth dependency + `whoami`.
2. Implement RBAC guard helpers on all existing endpoints.
3. Add audit event model and write events for compile endpoint.
4. Add standardized error envelope and request IDs.

Sprint 2:

1. Add rule + rule_version schema and create/list/get APIs.
2. Add validate endpoint with normalized diagnostics.
3. Add deployment entity and minimal create/status/rollback API.
4. Add integration tests for auth + rule lifecycle happy path.

## 8) Definition of Done

A feature is done only when all are true:

- API implemented and documented in OpenAPI examples,
- authz and tenancy checks in place,
- audit emission for mutations,
- metrics/logs/traces added,
- automated tests added,
- rollback or failure handling defined,
- merged with migration plan if schema changed.
