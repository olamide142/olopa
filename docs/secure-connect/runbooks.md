# Secure Connect Operator Runbooks

On-call procedures for the managed WireGuard (ZTNA) plane. Every command here is
real and runnable against the shipped API.

Set these once per session:

```bash
export CONTROL_URL=https://control.example.com
export AUTH='-H authorization:Bearer <operator-token>'   # or: -H x-dev-token:<token>
export SC="$CONTROL_URL/api/v1/secure-connect"
```

---

## 1. Capacity and measured limits

Measured with `app/control_plane/tools/sc_loadtest.py` against a single uvicorn
worker on SQLite (WAL, `synchronous=NORMAL`), 40 virtual endpoints per run:

| Concurrent session starts | Establish p50 | Establish p95 | Outcome |
| --- | --- | --- | --- |
| 2 | 13 ms | 558 ms | healthy, ~49 starts/s |
| 8 | 50 ms | 490 ms | healthy, ~48 starts/s |
| 24 | — | — | **collapse**: 35/40 requests time out |

Enrollment and heartbeat hold much shorter write transactions and stayed healthy
at every level tested (60–176 enrollments/s).

**The ceiling is the database, not the orchestrator.** SQLite permits one writer
at a time, and session establishment holds the write lock across several
statements. Past roughly 8 concurrent establishments, writers queue until they
exceed `SQLITE_BUSY_TIMEOUT_S` and fail.

What this means operationally:

- A fleet reconnecting all at once (mass agent restart, control-plane restart)
  will exceed this. The agent's exponential backoff spreads the retry storm, but
  do not plan for more than ~8 concurrent establishments on SQLite.
- **Any production deployment beyond a pilot must run PostgreSQL**
  (`DATABASE_URL=postgresql+psycopg://...`). The ORM layer is portable; the
  SQLite-specific PRAGMAs in `control_server/db.py` are applied only when the URL
  is SQLite.
- Steady-state heartbeat load is far cheaper than establishment. A fleet of N
  devices at the default 15s cadence generates N/15 requests per second; 3,000
  devices is 200 heartbeats/s, which is within reach of a single worker but
  should be validated on your own hardware with the load test.

Re-measure before any capacity commitment:

```bash
python app/control_plane/tools/sc_loadtest.py \
  --control-url "$CONTROL_URL" --dev-token "$CONTROL_DEV_TOKEN" \
  --devices 500 --concurrency 8 --duration 120
```

It exits non-zero when an SLO target is missed, so it can gate a release.

---

## 2. Revoke one device now

Fastest path when a laptop is lost or an employee is offboarded.

```bash
curl -sS -X POST "$SC/devices/$DEVICE_ID/quarantine" $AUTH \
  -H 'content-type: application/json' \
  -d '{"reason":"lost device INC-1234"}'
```

What happens, in order:

1. The device is marked `quarantined` and every live session is driven to
   `quarantined`; session keys are revoked immediately.
2. The endpoint receives the `quarantine` command on its next heartbeat
   (≤ 15s by default) and applies the nftables kill switch.
3. The gateway reconciler drops the peer on its next poll
   (≤ `OLOPA_GW_INTERVAL_SECS`, default 15s).

**Worst-case propagation is heartbeat interval + gateway poll interval.** Server-side
key revocation is immediate; the two intervals govern how fast the endpoint and
the gateway stop honouring the tunnel.

Verify:

```bash
curl -sS "$SC/sessions?device_id=$DEVICE_ID" $AUTH | jq '.[].state'
curl -sS "$SC/gateways/$GATEWAY_ID/peers" $AUTH | jq '.[].device_id'
```

To force it faster, drop the peer on the gateway by hand and let the reconciler
converge afterwards:

```bash
ssh $GATEWAY_HOST 'wg set olopa-gw0 peer <public-key> remove'
```

Quarantine is recoverable: the endpoint keeps the kill switch on and waits for a
new session. To end access permanently, terminate the session instead — that is
terminal and requires re-enrollment.

---

## 3. Drain a gateway for maintenance

Planned work, no user impact.

```bash
# 1. Stop new assignment. Live tunnels keep running.
curl -sS -X POST "$SC/gateways/$GATEWAY_ID/status" $AUTH \
  -H 'content-type: application/json' \
  -d '{"status":"draining","reason":"kernel upgrade CHG-42"}'

# 2. Move the existing sessions off.
curl -sS -X POST "$SC/gateways/$GATEWAY_ID/failover" $AUTH | jq
```

The failover response reports `migrated_sessions` and `stranded_sessions`.
**Stranded sessions are left running** — if no healthy gateway has capacity, the
orchestrator will not tear a tunnel down to satisfy a drain. If you see
stranded > 0, add capacity and re-run the failover.

Migration is transparent to the user: the endpoint gets a profile refresh with
the new gateway endpoint, key, and tunnel address, removes the old peer, and
installs the new one. The session id does not change.

Restore when done:

```bash
curl -sS -X POST "$SC/gateways/$GATEWAY_ID/status" $AUTH \
  -H 'content-type: application/json' -d '{"status":"online","reason":"CHG-42 complete"}'
```

---

## 4. Gateway hard failure

A gateway host is gone or unreachable.

**Automatic handling.** If `CONTROL_SC_AUTO_FAILOVER_ENABLED=1` (the default),
the background worker notices within `CONTROL_SC_GATEWAY_GRACE_SECS` (default
120s) that the reconciler stopped reporting, and migrates its live sessions to a
healthy gateway. Nothing is required from you.

**Confirm it happened:**

```bash
curl -sS "$SC/gateways" $AUTH | jq '.[] | {name, status, reachable, last_seen_at}'
curl -sS "$SC/metrics" $AUTH | jq '{live_sessions, gateways}'
```

**If it did not**, the usual reason is that no other gateway had capacity in the
tenant. Register or restore one, then force the migration:

```bash
curl -sS -X POST "$SC/gateways/$DEAD_GATEWAY_ID/status" $AUTH \
  -H 'content-type: application/json' -d '{"status":"offline","reason":"host lost"}'
curl -sS -X POST "$SC/gateways/$DEAD_GATEWAY_ID/failover" $AUTH | jq
```

**A gateway that never ran a reconciler is treated as reachable, not dead** — so
deployments without the reconciler keep working. That also means they get no
automatic failover. Run the reconciler on every gateway you want covered.

---

## 5. Control-plane outage

Endpoints do *not* lose access immediately, by design.

- The agent keeps the tunnel up and retries with exponential backoff.
- Once `OLOPA_SC_POLICY_TTL_SECS` (default 300s) passes with no successful
  control contact, the agent applies the kill switch and quarantines itself.
  This is the fail-closed boundary: an endpoint may not run on stale policy
  indefinitely.
- The gateway reconciler holds its current peer set. **A control-plane outage
  never revokes access on its own** — revocation requires a successful poll that
  says the peer is gone.

Priority during an outage is therefore restoring the control plane before the
policy TTL expires fleet-wide. If you cannot, expect endpoints to drop into
quarantine and reconnect once the control plane returns.

---

## 6. Suspected key compromise

```bash
# Rotate one session's keys without dropping the tunnel.
# (Normally automatic on the profile's rekey_interval_secs.)
curl -sS "$SC/sessions/$SESSION_ID" $AUTH | jq '{state, profile_version, last_rekey_at}'

# Cut access for the affected device, then re-enroll it.
curl -sS -X POST "$SC/devices/$DEVICE_ID/quarantine" $AUTH \
  -H 'content-type: application/json' -d '{"reason":"key compromise INC-1234"}'
```

If the *gateway's* key is compromised, replace the gateway: register a new one,
drain and fail over the old one (section 3), then delete the old gateway's
peers. Endpoints pick up the new gateway public key through the profile refresh.

Endpoint private keys never leave the device and are never stored by the control
plane, so a control-plane compromise does not expose tunnel private material —
but it does expose the ability to *issue* access, so rotate `JWT_SECRET` and all
service tokens, and audit `secure_connect.*` events:

```bash
curl -sS "$CONTROL_URL/api/v1/audit/events?action=secure_connect.&page_size=200" $AUTH | jq
```

---

## 7. Rollback

Secure Connect has no schema migrations of its own yet (`init_db()` creates
tables on startup), so rollback is a deploy rollback:

1. Disable the risk subscriber first if the new version changed risk behaviour:
   `CONTROL_SC_RISK_SUBSCRIBER_ENABLED=0`, restart.
2. Roll the control plane back to the previous image.
3. Live sessions survive: the agent keeps its tunnel across a control-plane
   restart as long as the outage is under the policy TTL.

To disable the subsystem entirely without touching endpoints, set
`CONTROL_SC_WORKER_ENABLED=0` — reaping and failover stop, the API stays up.

To disable it on an endpoint, unset `OLOPA_SC_ENABLED` and restart the agent.
Telemetry is unaffected: Secure Connect failures never stop the sensor.

---

## 8. Backup and restore

**What to back up**

| Data | Where | Why |
| --- | --- | --- |
| Control-plane DB | `DATABASE_URL` (SQLite file, or Postgres) | devices, sessions, profiles, gateways, leases, audit |
| `JWT_SECRET` | secret store | every issued token and enrollment JWT depends on it |
| Service tokens | `CONTROL_SERVICE_TOKENS_JSON` | agent and gateway credentials |
| Gateway WireGuard keys | gateway hosts | rotating them forces every endpoint to refresh |

SQLite backup — use the online API, not `cp`, so you get a consistent snapshot
while the server is running:

```bash
sqlite3 /path/control_plane.db ".backup '/backups/control_plane-$(date +%F).db'"
```

**Restore drill** (run it quarterly, it is the only way to know the backup works):

1. Restore the DB to a staging control plane with the same `JWT_SECRET`.
2. Point one test agent at it (`OLOPA_SC_CONTROL_URL`).
3. Confirm the device is already enrolled — it should start a session without a
   new enrollment token, because `sc_devices` came back with the backup.
4. Confirm `GET /gateways/{id}/peers` returns the expected set.

Device enrollment state is the part that hurts to lose: without it every
endpoint needs a fresh single-use enrollment token.

---

## 9. Game-day exercises

Run these against staging. Each has a defined pass condition.

| Exercise | Action | Pass condition |
| --- | --- | --- |
| Revocation SLO | Quarantine a device, timestamp the request | Endpoint kill switch applied within heartbeat interval + 3s; `last_command_latency_ms` in `/metrics` reflects it |
| Gateway drain | Drain and fail over a gateway with ≥ 10 live sessions | `stranded_sessions == 0`, no user-visible drop, sessions report the new `gateway_id` |
| Gateway hard kill | `systemctl stop olopa-sc-gateway` and firewall the host | Auto-failover migrates within `CONTROL_SC_GATEWAY_GRACE_SECS` + worker interval |
| Control-plane outage | Stop the control plane for 2× the policy TTL | Endpoints quarantine themselves, gateways retain peers, everything recovers on restart |
| Capacity | `sc_loadtest.py --devices 500 --concurrency 8` | Exit code 0; establish p95 ≤ 8s |
| Restore | Section 8 drill | Enrolled device reconnects with no new token |

Record the observed numbers each time. The table in section 1 is a measurement,
not a guarantee — re-derive it on your own hardware.
