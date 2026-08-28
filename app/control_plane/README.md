# Olopa Python Control Plane

This service is the **Python control server** for:
- dashboard/control APIs,
- compiler trigger endpoints,
- orchestration workflows.

The Rust server remains the ingest hot path for:
- agent telemetry ingestion,
- ingest stats/recent/summary storage and retrieval.

## Why two servers

- Rust handles high-throughput ingest and low-latency telemetry operations.
- Python handles product/control workflows that need rapid iteration.

## Run

```bash
cd app/control_plane
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn control_server.main:app --host 0.0.0.0 --port 8100
```

The container image uses the repository root as its Docker build context because
the React console imports shared tokens from `app/design` and the service loads
`app/intel_sync`. From the repository root:

```bash
docker build -f app/control_plane/Dockerfile -t olopa-control-plane .
```

## Environment

- `CONTROL_HOST` (default `0.0.0.0`)
- `CONTROL_PORT` (default `8100`)
- `RUST_INGEST_BASE_URL` (default `http://127.0.0.1:8000`)
- `INGEST_SERVER_URL` (optional alias for `RUST_INGEST_BASE_URL`; useful in Railway service-to-service routing)
- `RUST_REQUEST_TIMEOUT_S` (default `3.0`)
- `COMPILER_TIMEOUT_S` (default `20`)
- `OILC_MANIFEST_PATH` (default `<repo>/oilc/Cargo.toml`)
- `OILC_BINARY_PATH` (recommended built `oilc` executable; bypasses Cargo on requests)
- `AGENT_DOWNLOAD_URL` (optional upstream URL for `/downloads/agent/latest`)
- `AGENT_BINARY_PATH` (optional local file path for `/downloads/agent/latest`)
- `CONTROL_AUTH_REQUIRED` (default `true`; set false only for isolated development)
- `CONTROL_DEV_TOKEN` (optional explicit local-development administrator token)
- `CONTROL_DEV_TOKEN_ISSUANCE_ENABLED` (default `false`; enables admin-only JWT minting)
- `JWT_SECRET` (required to issue or accept local HS256 JWTs)
- `JWT_ISSUER` / `JWT_AUDIENCE` (optional JWT claim validation)
- `CONTROL_SERVICE_TOKENS_JSON` (service token to fixed user/tenant/roles mapping)
- `RUST_INGEST_API_TOKEN` (credential forwarded only to the Rust ingest service)
- `CONTROL_COMPILER_SOURCE_ROOT` (optional allowed root for server-side OIL source paths)
- `CONTROL_SC_CLIENT_CERT_HEADER` (default `x-olopa-client-cert-fingerprint`; header the TLS
  terminator uses to forward the verified mTLS client-certificate fingerprint)
- `CONTROL_SC_ALLOW_UNBOUND_ENROLLMENT` (default `false`; drops the mTLS device binding, local
  development only — pairs with the agent's `OLOPA_SC_ALLOW_UNBOUND_ENROLLMENT`)
- `CONTROL_SC_HEARTBEAT_GRACE_SECS` (default `90`; heartbeat age after which a session is stale)
- `CONTROL_SC_ELEVATED_COOLDOWN_SECS` (default `900`; clean window before `elevated -> healthy`)
- `CONTROL_SC_WORKER_ENABLED` (default `true`; background session reaper + risk subscriber)
- `CONTROL_SC_WORKER_INTERVAL_SECS` (default `15`)
- `CONTROL_SC_RISK_SUBSCRIBER_ENABLED` (default `false`; requires a reachable ingest server —
  polls the alert stream and enforces risk actions on matching sessions)
- `CONTROL_SC_ALERT_POLL_LIMIT` (default `500`; ingest rows read per tick)
- `CONTROL_SC_RISK_CRITICAL_SCORE` / `_HIGH_SCORE` / `_MEDIUM_SCORE` (default `0.9`/`0.7`/`0.4`;
  alert `risk_score` thresholds that map to severities)
- `CONTROL_SC_GATEWAY_GRACE_SECS` (default `120`; how long a gateway may go without a
  reconciler heartbeat before it stops receiving sessions and its own are migrated away)
- `CONTROL_SC_AUTO_FAILOVER_ENABLED` (default `true`)
- `SQLITE_BUSY_TIMEOUT_S` (default `10`; how long a blocked SQLite writer waits before
  failing — bounds request latency under write contention)

## Endpoints

This process only serves the dashboard SPA and JSON APIs — landing, docs, and
`install.sh` are static files under `site/`, served directly by Caddy (see
[Caddy Routing](#caddy-routing) below).

- `GET /`, `/fleet`, `/incidents`, `/graph`, `/oil`, `/compiler`, `/rules`,
  `/deployments`, `/install` (dashboard SPA shell — client-side router takes over)
- `GET /app` (legacy redirect to `/`)
- `GET /downloads/agent/latest` (agent binary download/redirect)
- `GET /health`
- `GET /api/v1/control/status`
- `GET /api/v1/ingest/stats` (proxy to Rust ingest)
- `GET /api/v1/ingest/summary` (proxy to Rust ingest)
- `GET /api/v1/ingest/recent?limit=100` (proxy to Rust ingest)
- `GET /api/v1/dashboard/ingest/*` (alias of ingest proxy endpoints)
- `POST /api/v1/control/compiler/compile`

### Secure Connect (managed WireGuard / ZTNA)

Server-side authority for the agent's `secure_connect` subsystem. The agent generates its
WireGuard keypair locally and publishes only the public key; the control plane never sees
endpoint private material.

Agent-facing:

- `POST /api/v1/secure-connect/enroll` (unauthenticated by design — the one-time enrollment
  JWT plus the mTLS client certificate are the credential)
- `POST /api/v1/secure-connect/sessions/start`
- `POST /api/v1/secure-connect/sessions/{id}/heartbeat`
- `POST /api/v1/secure-connect/sessions/{id}/rekey`

Operator-facing:

- `POST /api/v1/secure-connect/enrollment-tokens` (single-use, `exp <= 15m`, `jti` tracked)
- `POST|GET /api/v1/secure-connect/gateways`, `GET /gateways/{id}/peers` (desired peer state
  for an external gateway to reconcile), `POST /gateways/{id}/heartbeat` (reconciler
  liveness), `POST /gateways/{id}/status` (drain/restore), `POST /gateways/{id}/failover`
- `POST|GET|PUT /api/v1/secure-connect/profiles`, `POST /profiles/{id}/assign`
- `GET /api/v1/secure-connect/devices`, `POST /devices/{id}/quarantine`
- `GET /api/v1/secure-connect/sessions`, `POST /sessions/{id}/terminate`, `POST /sessions/{id}/state`
- `POST /api/v1/secure-connect/risk-signals` (manual/external detection input)
- `GET /api/v1/secure-connect/metrics` (fleet counters behind the SLOs: sessions by state,
  gateway utilization, command/revoke propagation latency, enrollment token usage)

Access states are `healthy -> elevated -> restricted -> quarantined -> terminated`.
Restrictive transitions are automatic; the only automatic relaxation is `elevated -> healthy`
after the cooldown window. Every other relaxation needs a new session, because the endpoint
refuses unconfirmed relaxations locally.

A background worker runs two jobs on `CONTROL_SC_WORKER_INTERVAL_SECS`:

- the **reaper** closes sessions whose profile expired without renewal and revokes their
  keys, so a device that goes dark stops holding a gateway peer entry;
- the **risk subscriber** (opt-in) reads alert rows from the ingest stream, buckets each
  alert's `risk_score` into a severity, and drives every live session anchored to the
  alerting host through the risk state machine. Alerts are applied at most once, and a
  detection-stream outage never disturbs existing tunnels.

A gateway that stops sending reconciler heartbeats stops receiving new sessions, and its
live sessions are migrated onto a healthy gateway — transparently, as a profile refresh.
Sessions with nowhere to go are left running rather than torn down. Gateways that have
never reported are treated as reachable, so deployments without a reconciler keep working.

The gateway plane itself is external — see `app/secure_connect_gateway/`, which reconciles a
WireGuard interface against `GET /gateways/{id}/peers`.

Operator procedures, measured capacity limits, and game-day exercises:
[`docs/secure-connect/runbooks.md`](../../docs/secure-connect/runbooks.md). Load test with
`python tools/sc_loadtest.py --help`.

## Caddy Routing

Deployment uses a single [`Caddyfile`](./Caddyfile) with host-based rules. Landing and
docs are fully static — Caddy serves them straight from [`site/`](./site) and this
process never sees the request:
- `console.olopa.io` proxies everything to the FastAPI process — the dashboard SPA
  (built from `web/` into `control_server/webdist`) and all `/api/**` routes
- `docs.olopa.io` is served entirely from `site/{quickstart,agent/config,oil,secure-connect}/`
  by Caddy's `file_server`; `/` redirects to `/quickstart/`
- `olopa.io` / `www.olopa.io` serves `site/index.html` at `/` plus `site/install.sh`
  and `site/assets/`, also via `file_server`. Two routes still hit the backend:
  `/downloads/agent/latest` (resolves `AGENT_BINARY_PATH`/`AGENT_DOWNLOAD_URL` at
  runtime) and `/health`
- `olopa.io/app*` and `olopa.io/api*` redirect to `console.olopa.io`
- `releases.olopa.io` is expected to be served directly by object storage/CDN (not by control-plane Caddy)

To add or edit a landing/docs page, edit the file under `site/` directly — there's no
build step and FastAPI has no route for it.

### Compile endpoint body

```json
{
  "source": "rule \"x\" { ... }",
  "mode": "runtime-ir"
}
```

Client-selected output paths are rejected. You can pass `source_path` instead of
inline source only when the resolved file is beneath `CONTROL_COMPILER_SOURCE_ROOT`.
