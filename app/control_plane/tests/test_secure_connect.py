"""Integration tests for the Secure Connect (ZTNA) orchestrator.

These exercise the exact wire contract the Rust agent implements in
`agent/agent/src/secure_connect`, including the invariants it enforces locally:
monotonic command nonces, no unconfirmed relaxations, and well-formed profiles.
"""

import base64
import dataclasses
import os
import tempfile
import time
import uuid
from datetime import timedelta
from pathlib import Path

# Environment must be configured before control_server is imported. `setdefault`
# keeps this module compatible with a sibling test module that already set it.
if not os.environ.get("DATABASE_URL"):
    _db_file = Path(tempfile.gettempdir()) / "test_secure_connect.db"
    _db_file.unlink(missing_ok=True)
    os.environ["DATABASE_URL"] = f"sqlite:///{_db_file}"

os.environ.setdefault("CONTROL_AUTH_REQUIRED", "1")
os.environ.setdefault("CONTROL_DEV_TOKEN", "test-dev-secret")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-that-is-long-and-random")
os.environ.setdefault("CONTROL_DEV_TOKEN_ISSUANCE_ENABLED", "1")

import httpx
import pytest
from sqlalchemy import select

from control_server.db import SessionLocal, init_db
from control_server.main import app
from control_server.models.secure_connect import (
    SecureConnectGateway,
    SecureConnectKeyMaterial,
    SecureConnectSession,
    utc_now,
)
from control_server.secure_connect import allocator, risk_subscriber, service, worker
from control_server.secure_connect import router as router_module

init_db()

DEV_HEADERS = {"x-dev-token": os.environ["CONTROL_DEV_TOKEN"]}
CERT_HEADER = "x-olopa-client-cert-fingerprint"
CERT_FINGERPRINT = "sha256:aa11bb22cc33dd44"
AGENT_HEADERS = {**DEV_HEADERS, CERT_HEADER: CERT_FINGERPRINT}

BASE = "/api/v1/secure-connect"


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def wg_key(seed: int) -> str:
    """A syntactically valid base64 Curve25519 public key."""
    return base64.b64encode(bytes([seed % 256] * 32)).decode()


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class Tenant:
    """An isolated tenant with its own admin and agent credentials.

    Gateways are registered `dedicated`, so they bind to the creating tenant and
    are invisible to every other one. Tests that assert on gateway *selection*
    need that isolation — the suite shares one database, so without it they see
    every gateway any other test created.
    """

    def __init__(self, name: str, admin: dict, agent: dict) -> None:
        self.name = name
        self.admin = admin
        self.agent = agent


DEFAULT_TENANT = Tenant("default", DEV_HEADERS, AGENT_HEADERS)


async def isolated_tenant(client) -> Tenant:
    name = unique("tenant")
    resp = await client.post(
        "/api/v1/auth/token",
        json={
            "user_id": f"admin@{name}",
            "tenant_id": name,
            "roles": ["admin"],
            "expires_in_minutes": 60,
        },
        headers=DEV_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    admin = {"authorization": f"Bearer {resp.json()['access_token']}"}
    return Tenant(name, admin, {**admin, CERT_HEADER: CERT_FINGERPRINT})


async def create_gateway(client, tenant: Tenant = DEFAULT_TENANT, **overrides) -> dict:
    body = {
        "name": unique("gw"),
        "region": "eu-west",
        "public_key": wg_key(9),
        "public_endpoint": "198.51.100.7:51820",
        "client_cidr": "10.90.0.0/24",
        "dns_servers": ["10.90.0.53"],
        "capacity": 100,
        "dedicated": True,
        **overrides,
    }
    resp = await client.post(f"{BASE}/gateways", json=body, headers=tenant.admin)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def create_profile(client, tenant: Tenant = DEFAULT_TENANT, **overrides) -> dict:
    body = {
        "name": unique("profile"),
        "access_mode": "split_tunnel",
        "region": "eu-west",
        "allowed_cidrs": ["10.20.0.0/16"],
        "safe_cidrs": ["10.20.9.0/24"],
        "bypass_cidrs": ["198.51.100.7/32"],
        "dns_servers": ["10.20.0.53"],
        "session_ttl_secs": 3600,
        "rekey_interval_secs": 900,
        **overrides,
    }
    resp = await client.post(f"{BASE}/profiles", json=body, headers=tenant.admin)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def mint_token(
    client, profile_id=None, ttl_minutes=15, tenant: Tenant = DEFAULT_TENANT
) -> str:
    resp = await client.post(
        f"{BASE}/enrollment-tokens",
        json={
            "user_id": "employee@example.com",
            "device_hint": "laptop",
            "profile_id": profile_id,
            "ttl_minutes": ttl_minutes,
        },
        headers=tenant.admin,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["token"]


async def enroll(
    client,
    token,
    *,
    fingerprint=None,
    headers=None,
    key_seed=1,
    tenant: Tenant = DEFAULT_TENANT,
) -> httpx.Response:
    return await client.post(
        f"{BASE}/enroll",
        json={
            "enrollment_token": token,
            "tenant_id": tenant.name,
            "host_id": unique("host"),
            "user_id": "employee@example.com",
            "device_fingerprint": fingerprint or unique("fp"),
            "wireguard_public_key": wg_key(key_seed),
            "posture": {"agent_version": "0.1.0", "os_version": "Ubuntu 24.04"},
        },
        headers=tenant.agent if headers is None else headers,
    )


async def start_session(
    client, device_id, *, key_seed=2, host_id=None, tenant: Tenant = DEFAULT_TENANT
) -> httpx.Response:
    return await client.post(
        f"{BASE}/sessions/start",
        json={
            "tenant_id": tenant.name,
            "device_id": device_id,
            "host_id": host_id or unique("host"),
            "wireguard_public_key": wg_key(key_seed),
            "posture": {"agent_version": "0.1.0"},
        },
        headers=tenant.agent,
    )


async def heartbeat(
    client,
    session_id,
    device_id,
    *,
    profile_version=1,
    nonce=0,
    state="healthy",
    tenant: Tenant = DEFAULT_TENANT,
):
    return await client.post(
        f"{BASE}/sessions/{session_id}/heartbeat",
        json={
            "tenant_id": tenant.name,
            "device_id": device_id,
            "session_id": session_id,
            "state": state,
            "posture": {"agent_version": "0.1.0"},
            "profile_version": profile_version,
            "last_command_nonce": nonce,
            "last_handshake_unix": int(time.time()),
            "bytes_tx": 4096,
            "bytes_rx": 8192,
        },
        headers=tenant.agent,
    )


async def connected_device(
    client, *, host_id=None, tenant: Tenant = DEFAULT_TENANT, **profile_overrides
):
    """Full happy path: gateway + profile + enrollment + live session."""
    await create_gateway(client, tenant)
    profile = await create_profile(client, tenant, **profile_overrides)
    token = await mint_token(client, profile_id=profile["id"], tenant=tenant)
    enrolled = await enroll(client, token, tenant=tenant)
    assert enrolled.status_code == 200, enrolled.text
    device_id = enrolled.json()["device_id"]
    started = await start_session(client, device_id, host_id=host_id, tenant=tenant)
    assert started.status_code == 200, started.text
    return profile, device_id, started.json()


# -- Auth and enrollment -------------------------------------------------------


@pytest.mark.parametrize(
    "path,method",
    [
        (f"{BASE}/devices", "get"),
        (f"{BASE}/sessions", "get"),
        (f"{BASE}/profiles", "get"),
        (f"{BASE}/gateways", "get"),
        (f"{BASE}/enrollment-tokens", "post"),
        (f"{BASE}/risk-signals", "post"),
    ],
)
async def test_secure_connect_endpoints_require_authentication(client, path, method):
    kwargs = {"json": {"user_id": "x", "severity": "low", "host_id": "h"}} if method == "post" else {}
    resp = await getattr(client, method)(path, **kwargs)
    assert resp.status_code == 401


async def test_enrollment_requires_client_certificate(client):
    token = await mint_token(client)
    resp = await enroll(client, token, headers={})
    assert resp.status_code == 401
    assert resp.json()["code"] == "DEVICE_CERT_REQUIRED"


async def test_enrollment_token_is_single_use(client):
    token = await mint_token(client)
    fingerprint = unique("fp")

    first = await enroll(client, token, fingerprint=fingerprint)
    assert first.status_code == 200, first.text

    replay = await enroll(client, token, fingerprint=fingerprint)
    assert replay.status_code == 401
    assert replay.json()["code"] == "ENROLLMENT_TOKEN_CONSUMED"


async def test_ordinary_bearer_token_is_not_an_enrollment_token(client):
    """A control-plane API JWT must not be redeemable for a device identity."""
    issued = await client.post(
        "/api/v1/auth/token",
        json={"user_id": "attacker", "tenant_id": "default", "roles": ["admin"]},
        headers=DEV_HEADERS,
    )
    if issued.status_code != 200:
        pytest.skip("dev token issuance is disabled in this environment")

    resp = await enroll(client, issued.json()["access_token"])
    assert resp.status_code == 401
    assert resp.json()["code"] == "ENROLLMENT_TOKEN_INVALID"


async def test_enrollment_rebinds_only_matching_certificates(client):
    fingerprint = unique("fp")
    first = await enroll(client, await mint_token(client), fingerprint=fingerprint)
    assert first.status_code == 200

    other_cert = await enroll(
        client,
        await mint_token(client),
        fingerprint=fingerprint,
        headers={**DEV_HEADERS, CERT_HEADER: "sha256:deadbeef"},
    )
    assert other_cert.status_code == 403
    assert other_cert.json()["code"] == "DEVICE_BINDING_MISMATCH"


# -- Session bootstrap ---------------------------------------------------------


async def test_session_start_issues_a_usable_tunnel_profile(client):
    profile, device_id, started = await connected_device(client)

    assert started["state"] == "healthy"
    assert started["command_nonce"] == 0
    tunnel = started["profile"]
    assert tunnel["interface_address"].startswith("10.90.0.")
    assert tunnel["interface_address"].endswith("/32")
    # .1 stays with the gateway itself.
    assert not tunnel["interface_address"].startswith("10.90.0.1/")
    assert tunnel["gateway_endpoint"] == "198.51.100.7:51820"
    assert tunnel["allowed_cidrs"] == ["10.20.0.0/16"]
    assert tunnel["dns_servers"] == ["10.20.0.53"]
    assert tunnel["profile_version"] == 1
    assert tunnel["expires_at_unix"] > int(time.time())


async def test_session_start_requires_a_matching_tenant(client):
    _, device_id, _ = await connected_device(client)
    resp = await client.post(
        f"{BASE}/sessions/start",
        json={
            "tenant_id": "someone-else",
            "device_id": device_id,
            "host_id": "host",
            "wireguard_public_key": wg_key(3),
            "posture": {},
        },
        headers=AGENT_HEADERS,
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "TENANT_MISMATCH"


async def test_session_start_rejects_a_malformed_public_key(client):
    await create_gateway(client)
    profile = await create_profile(client)
    enrolled = await enroll(client, await mint_token(client, profile_id=profile["id"]))
    device_id = enrolled.json()["device_id"]

    resp = await client.post(
        f"{BASE}/sessions/start",
        json={
            "tenant_id": "default",
            "device_id": device_id,
            "host_id": "host",
            "wireguard_public_key": "not-base64!!",
            "posture": {},
        },
        headers=AGENT_HEADERS,
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_WIREGUARD_KEY"


async def test_reconnect_keeps_the_same_tunnel_address(client):
    _, device_id, first = await connected_device(client)
    second = await start_session(client, device_id, key_seed=5)
    assert second.status_code == 200
    assert second.json()["profile"]["interface_address"] == first["profile"]["interface_address"]
    assert second.json()["session_id"] != first["session_id"]

    sessions = await client.get(
        f"{BASE}/sessions", params={"device_id": device_id}, headers=DEV_HEADERS
    )
    states = {item["id"]: item["state"] for item in sessions.json()}
    assert states[first["session_id"]] == "terminated"
    assert states[second.json()["session_id"]] == "healthy"


# -- Heartbeat and policy push -------------------------------------------------


async def test_quiet_heartbeat_returns_no_command(client):
    _, device_id, started = await connected_device(client)
    resp = await heartbeat(client, started["session_id"], device_id)
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"] == "none"
    assert body["desired_state"] is None
    # A zero nonce tells the agent there is nothing to replay-check.
    assert body["command_nonce"] == 0


async def test_profile_update_reaches_a_live_session_without_restart(client):
    profile, device_id, started = await connected_device(client)

    updated = await client.put(
        f"{BASE}/profiles/{profile['id']}",
        json={
            "name": profile["name"],
            "access_mode": "split_tunnel",
            "region": "eu-west",
            "allowed_cidrs": ["10.20.0.0/16", "10.30.0.0/16"],
            "safe_cidrs": ["10.20.9.0/24"],
            "bypass_cidrs": ["198.51.100.7/32"],
            "dns_servers": ["10.20.0.53"],
            "session_ttl_secs": 3600,
            "rekey_interval_secs": 900,
        },
        headers=DEV_HEADERS,
    )
    assert updated.status_code == 200, updated.text

    resp = await heartbeat(client, started["session_id"], device_id)
    body = resp.json()
    assert body["action"] == "refresh_profile"
    assert body["profile"]["allowed_cidrs"] == ["10.20.0.0/16", "10.30.0.0/16"]
    assert body["profile"]["profile_version"] == 2
    assert body["command_nonce"] > started["command_nonce"]


async def test_profile_version_drift_triggers_a_refresh(client):
    _, device_id, started = await connected_device(client)
    resp = await heartbeat(client, started["session_id"], device_id, profile_version=0)
    body = resp.json()
    assert body["action"] == "refresh_profile"
    assert body["profile"]["profile_version"] == 1


async def test_heartbeat_rejects_a_foreign_device(client):
    _, device_id, started = await connected_device(client)
    _, other_device, _ = await connected_device(client)

    resp = await heartbeat(client, started["session_id"], other_device)
    assert resp.status_code == 403
    assert resp.json()["code"] == "SESSION_DEVICE_MISMATCH"


async def test_commands_carry_strictly_increasing_nonces(client):
    profile, device_id, started = await connected_device(client)
    nonce = started["command_nonce"]

    for _ in range(3):
        await client.post(
            f"{BASE}/profiles/{profile['id']}/assign",
            json={"device_ids": [device_id]},
            headers=DEV_HEADERS,
        )
        body = (await heartbeat(client, started["session_id"], device_id, nonce=nonce)).json()
        assert body["command_nonce"] > nonce
        nonce = body["command_nonce"]


# -- Rekey ---------------------------------------------------------------------


async def test_rekey_rotates_the_peer_key_and_advances_the_nonce(client):
    _, device_id, started = await connected_device(client)
    session_id = started["session_id"]

    command = (await heartbeat(client, session_id, device_id, profile_version=0)).json()
    nonce = command["command_nonce"]

    resp = await client.post(
        f"{BASE}/sessions/{session_id}/rekey",
        json={
            "tenant_id": "default",
            "device_id": device_id,
            "wireguard_public_key": wg_key(77),
            "last_command_nonce": nonce,
        },
        headers=AGENT_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["command_nonce"] > nonce
    assert body["profile"]["profile_version"] > started["profile"]["profile_version"]

    detail = (await client.get(f"{BASE}/sessions/{session_id}", headers=DEV_HEADERS)).json()
    peers = await client.get(
        f"{BASE}/gateways/{detail['gateway_id']}/peers", headers=DEV_HEADERS
    )
    keys = {peer["public_key"] for peer in peers.json() if peer["session_id"] == session_id}
    # Exactly one unrevoked key per session: the new one.
    assert keys == {wg_key(77)}


# -- Risk-adaptive access ------------------------------------------------------


async def test_critical_alert_quarantines_the_session(client):
    _, device_id, started = await connected_device(client)
    session_id = started["session_id"]

    signal = await client.post(
        f"{BASE}/risk-signals",
        json={
            "device_id": device_id,
            "severity": "critical",
            "reason": "credential access on host",
            "alert_id": "alert-1",
        },
        headers=DEV_HEADERS,
    )
    assert signal.status_code == 200, signal.text
    body = signal.json()
    assert body["target_state"] == "quarantined"
    assert body["transitioned_sessions"] == 1

    command = (await heartbeat(client, session_id, device_id)).json()
    assert command["action"] == "quarantine"
    assert command["desired_state"] == "quarantined"
    assert command["command_nonce"] > 0

    detail = (await client.get(f"{BASE}/sessions/{session_id}", headers=DEV_HEADERS)).json()
    assert detail["state"] == "quarantined"
    # Propagation latency is instrumented for the revoke SLO.
    assert detail["last_command_latency_ms"] is not None


async def test_high_alert_restricts_to_safe_cidrs(client):
    profile, device_id, started = await connected_device(client)

    signal = await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "high", "reason": "suspicious exec"},
        headers=DEV_HEADERS,
    )
    assert signal.json()["target_state"] == "restricted"

    command = (await heartbeat(client, started["session_id"], device_id)).json()
    assert command["action"] == "restrict"
    assert command["desired_state"] == "restricted"
    assert command["profile"]["allowed_cidrs"] == profile["safe_cidrs"]


async def test_restrict_escalates_to_quarantine_without_safe_cidrs(client):
    _, device_id, started = await connected_device(client, safe_cidrs=[])
    signal = await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "high", "reason": "suspicious exec"},
        headers=DEV_HEADERS,
    )
    # An empty route set would be rejected by the endpoint, so access is cut
    # instead of half-applied.
    assert signal.json()["target_state"] == "quarantined"


async def test_detections_never_relax_access(client):
    _, device_id, started = await connected_device(client)
    await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "high", "reason": "suspicious exec"},
        headers=DEV_HEADERS,
    )
    relax = await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "low", "reason": "informational"},
        headers=DEV_HEADERS,
    )
    assert relax.json()["transitioned_sessions"] == 0

    detail = (
        await client.get(f"{BASE}/sessions/{started['session_id']}", headers=DEV_HEADERS)
    ).json()
    assert detail["state"] == "restricted"


async def test_operator_cannot_silently_relax_a_restricted_session(client):
    _, device_id, started = await connected_device(client)
    await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "high", "reason": "suspicious exec"},
        headers=DEV_HEADERS,
    )

    resp = await client.post(
        f"{BASE}/sessions/{started['session_id']}/state",
        json={"desired_state": "healthy", "reason": "analyst cleared the alert"},
        headers=DEV_HEADERS,
    )
    assert resp.status_code == 409
    assert resp.json()["code"] == "RELAXATION_REQUIRES_NEW_SESSION"


async def test_elevated_returns_to_healthy_after_cooldown(client, monkeypatch):
    _, device_id, started = await connected_device(client)
    session_id = started["session_id"]

    monkeypatch.setattr(
        router_module,
        "settings",
        dataclasses.replace(router_module.settings, sc_elevated_cooldown_secs=0),
    )

    await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "medium", "reason": "anomalous login"},
        headers=DEV_HEADERS,
    )
    elevated = (await heartbeat(client, session_id, device_id)).json()
    assert elevated["desired_state"] == "elevated"
    assert elevated["action"] == "none"

    cooled = (
        await heartbeat(client, session_id, device_id, nonce=elevated["command_nonce"])
    ).json()
    assert cooled["desired_state"] == "healthy"
    assert cooled["command_nonce"] > elevated["command_nonce"]


# -- Operator fleet actions ----------------------------------------------------


async def test_quarantining_a_device_blocks_new_sessions(client):
    _, device_id, started = await connected_device(client)

    resp = await client.post(
        f"{BASE}/devices/{device_id}/quarantine",
        json={"reason": "lost laptop"},
        headers=DEV_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert [item["state"] for item in resp.json()] == ["quarantined"]

    retry = await start_session(client, device_id, key_seed=8)
    assert retry.status_code == 403
    assert retry.json()["code"] == "DEVICE_NOT_ACTIVE"


async def test_terminated_sessions_are_terminal(client):
    _, device_id, started = await connected_device(client)
    session_id = started["session_id"]

    resp = await client.post(
        f"{BASE}/sessions/{session_id}/terminate",
        json={"reason": "offboarded"},
        headers=DEV_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "terminated"

    command = (await heartbeat(client, session_id, device_id)).json()
    assert command["action"] == "terminate"
    assert command["desired_state"] == "terminated"

    rekey = await client.post(
        f"{BASE}/sessions/{session_id}/rekey",
        json={
            "tenant_id": "default",
            "device_id": device_id,
            "wireguard_public_key": wg_key(31),
            "last_command_nonce": command["command_nonce"],
        },
        headers=AGENT_HEADERS,
    )
    assert rekey.status_code == 409
    assert rekey.json()["code"] == "SESSION_NOT_LIVE"


async def test_session_without_a_profile_is_refused(client):
    await create_gateway(client)
    # No profile assigned and no tenant default exists for this device.
    enrolled = await enroll(client, await mint_token(client))
    resp = await start_session(client, enrolled.json()["device_id"])
    assert resp.status_code == 409
    assert resp.json()["code"] == "NO_PROFILE_ASSIGNED"


async def test_mutations_are_audited(client):
    _, device_id, started = await connected_device(client)
    await client.post(
        f"{BASE}/sessions/{started['session_id']}/terminate",
        json={"reason": "audit check"},
        headers=DEV_HEADERS,
    )

    events = await client.get(
        "/api/v1/audit/events",
        params={"action": "secure_connect.", "page_size": 200},
        headers=DEV_HEADERS,
    )
    assert events.status_code == 200, events.text
    actions = {record["action"] for record in events.json()["items"]}
    assert "secure_connect.session.start" in actions
    assert "secure_connect.session.terminate" in actions


# -- Background worker: reaping ------------------------------------------------


async def test_expired_sessions_are_reaped_and_keys_revoked(client):
    _, device_id, started = await connected_device(client)
    session_id = started["session_id"]

    db = SessionLocal()
    try:
        record = db.get(SecureConnectSession, session_id)
        record.expires_at = utc_now() - timedelta(hours=2)
        db.commit()

        reaped = worker.reap_expired_sessions(db, grace_secs=0)
        assert session_id in reaped

        live_keys = db.scalars(
            select(SecureConnectKeyMaterial).where(
                SecureConnectKeyMaterial.session_id == session_id,
                SecureConnectKeyMaterial.revoked_at.is_(None),
            )
        ).all()
        assert live_keys == []
    finally:
        db.close()

    detail = (await client.get(f"{BASE}/sessions/{session_id}", headers=DEV_HEADERS)).json()
    assert detail["state"] == "terminated"
    assert "expired" in (detail["close_reason"] or "")


async def test_reaper_leaves_renewed_sessions_alone(client):
    _, device_id, started = await connected_device(client)
    db = SessionLocal()
    try:
        assert worker.reap_expired_sessions(db, grace_secs=0) == []
    finally:
        db.close()

    detail = (
        await client.get(f"{BASE}/sessions/{started['session_id']}", headers=DEV_HEADERS)
    ).json()
    assert detail["state"] == "healthy"


# -- Background worker: detection-stream subscription --------------------------


def alert_row(host_id, risk_score, *, rule_id="rule-1", ts_ns=1, tenant_id="default"):
    """One ingest row shaped exactly like the agent's alert wire mapping."""
    return {
        "tenant_id": tenant_id,
        "host_id": host_id,
        "batch_id": "batch-1",
        "event_kind": "process_exec",
        "ingested_at_unix_ms": 1,
        "event": {
            "pid": 10,
            "attrs": {
                "wire": "alert_binary",
                "rule_id": rule_id,
                "rule_name": "credential_access",
                "risk_score": f"{risk_score:.6f}",
                "ts_ns": str(ts_ns),
                "vertex_id": "1",
                "dst_vertex_id": "2",
            },
        },
    }


def test_risk_score_buckets_map_to_severities():
    thresholds = (0.9, 0.7, 0.4)
    assert risk_subscriber.severity_for_risk_score(0.95, thresholds) == "critical"
    assert risk_subscriber.severity_for_risk_score(0.75, thresholds) == "high"
    assert risk_subscriber.severity_for_risk_score(0.5, thresholds) == "medium"
    assert risk_subscriber.severity_for_risk_score(0.1, thresholds) == "low"


def test_only_alert_rows_are_extracted():
    rows = [
        alert_row("host-a", 0.95),
        {"host_id": "host-b", "event": {"attrs": {"wire": "event_v2"}}},
        {"host_id": "host-c", "event": "not-a-dict"},
    ]
    extracted = risk_subscriber.extract_alerts(rows)
    assert len(extracted) == 1
    assert extracted[0]["host_id"] == "host-a"


async def test_alert_stream_quarantines_the_alerting_host(client, monkeypatch):
    host_id = unique("host")
    _, device_id, started = await connected_device(client, host_id=host_id)

    async def fake_fetch(base_url, api_token, limit, timeout_s):
        return [alert_row(host_id, 0.97)]

    monkeypatch.setattr(risk_subscriber, "fetch_recent_rows", fake_fetch)

    db = SessionLocal()
    deduper = risk_subscriber.AlertDeduper()
    try:
        result = await risk_subscriber.poll_once(
            db,
            deduper,
            base_url="http://ingest.invalid",
            api_token="",
            limit=100,
            timeout_s=1.0,
            thresholds=(0.9, 0.7, 0.4),
        )
    finally:
        db.close()

    assert result["alerts"] == 1
    assert result["transitions"] == 1

    detail = (
        await client.get(f"{BASE}/sessions/{started['session_id']}", headers=DEV_HEADERS)
    ).json()
    assert detail["state"] == "quarantined"

    # The endpoint is told to cut access on its next heartbeat.
    command = (await heartbeat(client, started["session_id"], device_id)).json()
    assert command["action"] == "quarantine"


async def test_alert_stream_applies_each_alert_once(client, monkeypatch):
    host_id = unique("host")
    _, device_id, started = await connected_device(client, host_id=host_id)

    async def fake_fetch(base_url, api_token, limit, timeout_s):
        return [alert_row(host_id, 0.75, rule_id="rule-repeat")]

    monkeypatch.setattr(risk_subscriber, "fetch_recent_rows", fake_fetch)
    deduper = risk_subscriber.AlertDeduper()

    async def poll():
        db = SessionLocal()
        try:
            return await risk_subscriber.poll_once(
                db,
                deduper,
                base_url="http://ingest.invalid",
                api_token="",
                limit=100,
                timeout_s=1.0,
                thresholds=(0.9, 0.7, 0.4),
            )
        finally:
            db.close()

    first = await poll()
    second = await poll()
    assert first["applied"] == 1
    # The ingest window still contains the row; it must not re-fire.
    assert second["applied"] == 0


async def test_alert_stream_outage_is_survivable(client, monkeypatch):
    async def failing_fetch(base_url, api_token, limit, timeout_s):
        raise httpx.ConnectError("ingest unreachable")

    monkeypatch.setattr(risk_subscriber, "fetch_recent_rows", failing_fetch)

    db = SessionLocal()
    try:
        result = await risk_subscriber.poll_once(
            db,
            risk_subscriber.AlertDeduper(),
            base_url="http://ingest.invalid",
            api_token="",
            limit=100,
            timeout_s=1.0,
            thresholds=(0.9, 0.7, 0.4),
        )
    finally:
        db.close()
    assert result == {"rows": 0, "alerts": 0, "applied": 0, "transitions": 0}


def test_deduper_is_bounded():
    deduper = risk_subscriber.AlertDeduper(capacity=2)
    assert deduper.is_new("a")
    assert deduper.is_new("b")
    assert deduper.is_new("c")
    assert len(deduper) == 2
    # "a" aged out of the window and is accepted again.
    assert deduper.is_new("a")


# -- Multi-gateway balancing and failover --------------------------------------


async def connected_in(client, tenant, gateway_overrides=None, **profile_overrides):
    """Gateway + profile + device + live session inside one isolated tenant."""
    gateway = await create_gateway(client, tenant, **(gateway_overrides or {}))
    profile = await create_profile(client, tenant, **profile_overrides)
    token = await mint_token(client, profile_id=profile["id"], tenant=tenant)
    device_id = (await enroll(client, token, tenant=tenant)).json()["device_id"]
    started = (await start_session(client, device_id, tenant=tenant)).json()
    return gateway, profile, device_id, started


async def test_gateway_heartbeat_marks_the_gateway_reachable(client):
    tenant = await isolated_tenant(client)
    gateway = await create_gateway(client, tenant)

    resp = await client.post(
        f"{BASE}/gateways/{gateway['id']}/heartbeat",
        json={"observed_peers": 3, "reconciler_version": "1.0.0"},
        headers=tenant.admin,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["gateway_id"] == gateway["id"]

    listed = (await client.get(f"{BASE}/gateways", headers=tenant.admin)).json()[0]
    assert listed["reachable"] is True
    assert listed["observed_peers"] == 3
    assert listed["reconciler_version"] == "1.0.0"


async def test_a_silent_gateway_stops_receiving_sessions(client):
    """A gateway whose reconciler went quiet must not be assigned new work."""
    tenant = await isolated_tenant(client)
    silent = await create_gateway(client, tenant)

    db = SessionLocal()
    try:
        record = db.get(SecureConnectGateway, silent["id"])
        record.last_seen_at = utc_now() - timedelta(hours=1)
        db.commit()

        with pytest.raises(allocator.AllocationError) as exc:
            allocator.select_gateway(
                db, tenant.name, "eu-west", reachability_grace_secs=60
            )
        assert exc.value.code == "NO_GATEWAY_CAPACITY"
    finally:
        db.close()


async def test_a_gateway_that_never_reported_is_still_usable(client):
    """Deployments without a reconciler must keep working."""
    tenant = await isolated_tenant(client)
    created = await create_gateway(client, tenant)
    db = SessionLocal()
    try:
        gateway = allocator.select_gateway(
            db, tenant.name, "eu-west", reachability_grace_secs=60
        )
        assert gateway.id == created["id"]
        assert gateway.last_seen_at is None
    finally:
        db.close()


async def test_draining_a_gateway_stops_new_sessions_but_keeps_live_ones(client):
    tenant = await isolated_tenant(client)
    gateway, profile, _, started = await connected_in(client, tenant)

    drained = await client.post(
        f"{BASE}/gateways/{gateway['id']}/status",
        json={"status": "draining", "reason": "kernel upgrade"},
        headers=tenant.admin,
    )
    assert drained.status_code == 200
    assert drained.json()["status"] == "draining"

    # The running tunnel is untouched.
    detail = (
        await client.get(f"{BASE}/sessions/{started['session_id']}", headers=tenant.admin)
    ).json()
    assert detail["state"] == "healthy"

    # And the drained gateway is no longer a candidate.
    db = SessionLocal()
    try:
        with pytest.raises(allocator.AllocationError):
            allocator.select_gateway(db, tenant.name, profile["region"])
    finally:
        db.close()


async def test_failover_migrates_a_session_to_a_healthy_gateway(client):
    tenant = await isolated_tenant(client)
    failing, _, device_id, started = await connected_in(client, tenant)
    session_id = started["session_id"]

    healthy = await create_gateway(
        client,
        tenant,
        client_cidr="10.91.0.0/24",
        public_key=wg_key(21),
        public_endpoint="198.51.100.21:51820",
    )

    resp = await client.post(
        f"{BASE}/gateways/{failing['id']}/failover", headers=tenant.admin
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["migrated_sessions"] == 1
    assert resp.json()["stranded_sessions"] == 0

    detail = (
        await client.get(f"{BASE}/sessions/{session_id}", headers=tenant.admin)
    ).json()
    assert detail["gateway_id"] == healthy["id"]
    assert detail["state"] == "healthy"
    assert detail["assigned_address"].startswith("10.91.0.")

    # The endpoint learns about the move as an ordinary profile refresh.
    command = (
        await heartbeat(client, session_id, device_id, tenant=tenant)
    ).json()
    assert command["action"] == "refresh_profile"
    assert command["profile"]["gateway_endpoint"] == "198.51.100.21:51820"
    assert command["profile"]["gateway_public_key"] == wg_key(21)
    assert command["profile"]["interface_address"].startswith("10.91.0.")

    # Key material follows the session; the old gateway keeps none.
    old_peers = await client.get(
        f"{BASE}/gateways/{failing['id']}/peers", headers=tenant.admin
    )
    new_peers = await client.get(
        f"{BASE}/gateways/{healthy['id']}/peers", headers=tenant.admin
    )
    assert [p for p in old_peers.json() if p["session_id"] == session_id] == []
    assert [p["session_id"] for p in new_peers.json() if p["session_id"] == session_id] == [
        session_id
    ]


async def test_failover_strands_rather_than_kills_when_there_is_nowhere_to_go(client):
    """A total gateway outage must not become a fleet-wide teardown."""
    tenant = await isolated_tenant(client)
    only, _, _, started = await connected_in(client, tenant)

    resp = await client.post(
        f"{BASE}/gateways/{only['id']}/failover", headers=tenant.admin
    )
    assert resp.status_code == 200
    assert resp.json()["migrated_sessions"] == 0
    assert resp.json()["stranded_sessions"] == 1

    detail = (
        await client.get(f"{BASE}/sessions/{started['session_id']}", headers=tenant.admin)
    ).json()
    assert detail["state"] == "healthy"
    assert detail["gateway_id"] == only["id"]


async def test_worker_failover_evacuates_offline_gateways(client):
    tenant = await isolated_tenant(client)
    failing, _, _, started = await connected_in(client, tenant)

    healthy = await create_gateway(
        client,
        tenant,
        client_cidr="10.92.0.0/24",
        public_key=wg_key(23),
        public_endpoint="198.51.100.23:51820",
    )
    await client.post(
        f"{BASE}/gateways/{failing['id']}/status",
        json={"status": "offline", "reason": "host lost"},
        headers=tenant.admin,
    )

    db = SessionLocal()
    try:
        migrated, stranded = service.failover_sessions(db, reachability_grace_secs=120)
    finally:
        db.close()
    assert migrated >= 1

    detail = (
        await client.get(f"{BASE}/sessions/{started['session_id']}", headers=tenant.admin)
    ).json()
    assert detail["gateway_id"] == healthy["id"]


async def test_least_loaded_gateway_wins_at_equal_health(client):
    tenant = await isolated_tenant(client)
    first = await create_gateway(client, tenant, capacity=50)
    second = await create_gateway(
        client,
        tenant,
        capacity=50,
        client_cidr="10.93.0.0/24",
        public_key=wg_key(25),
        public_endpoint="198.51.100.25:51820",
    )
    profile = await create_profile(client, tenant)

    placements = []
    for index in range(2):
        token = await mint_token(client, profile_id=profile["id"], tenant=tenant)
        device_id = (
            await enroll(client, token, key_seed=40 + index, tenant=tenant)
        ).json()["device_id"]
        session_id = (
            await start_session(client, device_id, key_seed=50 + index, tenant=tenant)
        ).json()["session_id"]
        detail = (
            await client.get(f"{BASE}/sessions/{session_id}", headers=tenant.admin)
        ).json()
        placements.append(detail["gateway_id"])

    # Two devices, two equal gateways: the second lands on the emptier one.
    assert set(placements) == {first["id"], second["id"]}


# -- Observability -------------------------------------------------------------


async def test_metrics_report_fleet_state_and_slo_counters(client):
    _, device_id, started = await connected_device(client)
    await client.post(
        f"{BASE}/risk-signals",
        json={"device_id": device_id, "severity": "critical", "reason": "metrics"},
        headers=DEV_HEADERS,
    )
    await heartbeat(client, started["session_id"], device_id)

    resp = await client.get(f"{BASE}/metrics", headers=DEV_HEADERS)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["tenant_id"] == "default"
    assert body["sessions_by_state"]["quarantined"] >= 1
    assert body["devices_by_state"]["active"] >= 1
    assert body["enrollment_tokens_consumed"] >= 1
    assert body["command_latency_ms"]["count"] >= 1
    assert any(gateway["capacity"] == 100 for gateway in body["gateways"])
