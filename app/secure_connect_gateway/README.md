# Olopa Secure Connect Gateway Reconciler

Runs on a WireGuard gateway host and keeps its peer set equal to what the Olopa
control plane authorises. This is the "option A" gateway plane: gateways stay
plain WireGuard, and the control plane orchestrates peers and policy only.

## What it does

Every tick it:

1. pulls `GET /api/v1/secure-connect/gateways/{id}/peers` from the control plane,
2. reads the local peer set from `wg show <iface> dump`,
3. applies the difference with `wg set` — removals first, then additions,
4. reports liveness with `POST /gateways/{id}/heartbeat`.

Step 4 is what keeps the gateway in rotation. A gateway that stops reporting for
`CONTROL_SC_GATEWAY_GRACE_SECS` (default 120s) stops receiving new sessions, and the
control plane migrates its live sessions onto a healthy gateway. A failed heartbeat is
logged but never fatal — the gateway keeps serving traffic regardless.

Peer removal *is* the revocation path: when the control plane quarantines,
terminates, or rekeys a session, the old public key disappears from the peer
list and this agent drops it from the interface.

## What it deliberately does not do

- **It never touches interface configuration.** Private key, listen port, and
  addresses are provisioned by you (`wg-quick`, cloud-init, whatever you use).
  The reconciler only manages `peer` entries.
- **It never handles endpoint private keys.** Endpoints generate their own; only
  public keys ever cross the wire.
- **It never revokes on failure.** If the control plane is unreachable, the
  current peer set stays exactly as it is. Cutting access requires a *successful*
  poll that says the peer is gone, so a control-plane outage cannot black out a
  fleet.

## Setup

Register the gateway first (admin credentials):

```bash
curl -sS -X POST "$CONTROL_URL/api/v1/secure-connect/gateways" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "name": "eu-west-1a",
        "region": "eu-west",
        "public_key": "'"$(wg show olopa-gw0 public-key)"'",
        "public_endpoint": "198.51.100.7:51820",
        "client_cidr": "10.90.0.0/16",
        "dns_servers": ["10.90.0.53"],
        "capacity": 5000
      }'
```

The `client_cidr` is the pool the control plane allocates endpoint tunnel
addresses from; the gateway keeps the first host address (`10.90.0.1`) for its
own interface.

Then write `/etc/olopa/secure-connect-gateway.env`:

```sh
OLOPA_GW_CONTROL_URL=https://control.example.com
OLOPA_GW_GATEWAY_ID=<id returned by the registration call>
OLOPA_GW_TENANT_ID=acme
OLOPA_GW_API_TOKEN=<service token with the operator role>
OLOPA_GW_INTERFACE=olopa-gw0
OLOPA_GW_INTERVAL_SECS=15
```

Install and start:

```bash
install -D -m 0755 reconciler.py /opt/olopa/secure_connect_gateway/reconciler.py
install -D -m 0644 olopa-sc-gateway.service /etc/systemd/system/olopa-sc-gateway.service
systemctl enable --now olopa-sc-gateway
```

## Operating

```bash
# Show what would change without touching the interface.
python3 reconciler.py --once --dry-run --verbose

# One-shot reconcile (useful from a deploy pipeline).
python3 reconciler.py --once
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `OLOPA_GW_CONTROL_URL` | — | Control-plane base URL (https required) |
| `OLOPA_GW_GATEWAY_ID` | — | Gateway id from registration |
| `OLOPA_GW_TENANT_ID` | — | Tenant scope for the peer query |
| `OLOPA_GW_API_TOKEN` | — | Bearer token with the operator role |
| `OLOPA_GW_INTERFACE` | `olopa-gw0` | WireGuard interface to manage |
| `OLOPA_GW_INTERVAL_SECS` | `15` | Poll interval |
| `OLOPA_GW_TIMEOUT_SECS` | `10` | Control-plane request timeout |
| `OLOPA_GW_DRY_RUN` | `0` | Log the plan instead of applying it |
| `OLOPA_GW_ALLOW_INSECURE_HTTP` | `0` | Permit an `http://` control URL (local dev only) |

Revocation latency is bounded by `OLOPA_GW_INTERVAL_SECS`. The endpoint's own
kill switch engages within seconds of the control-plane command, so the gateway
poll interval governs how quickly the *server side* peer entry disappears — set
it at or below your revocation SLO.

## Tests

```bash
python3 -m pytest app/secure_connect_gateway/tests
```

The reconciler has no third-party dependencies; the tests run on a stock Python 3
install.
