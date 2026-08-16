"""Comprehensive integration tests for control plane authn, RBAC, audit, rule registry, and deployments."""

import os
import tempfile
import time
from pathlib import Path

import jwt
# Setup temp DB environment BEFORE importing control_server modules
db_file = Path(tempfile.gettempdir()) / "test_control_plane.db"
db_file.unlink(missing_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"
os.environ["CONTROL_AUTH_REQUIRED"] = "1"
os.environ["CONTROL_DEV_TOKEN"] = "test-dev-secret"
os.environ["CONTROL_DEV_TOKEN_ISSUANCE_ENABLED"] = "1"
os.environ["JWT_SECRET"] = "test-only-jwt-secret-that-is-long-and-random"
os.environ["CONTROL_SERVICE_TOKENS_JSON"] = """{
  "test-service-secret": {
    "user_id": "ingest-reader",
    "tenant_id": "tenant-service",
    "roles": ["viewer"]
  }
}"""

import pytest
import httpx

from control_server.main import app
from control_server.db import init_db

init_db()


@pytest.fixture
async def client():
    """Exercise the ASGI app without TestClient's cross-thread portal."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as async_client:
        yield async_client

DEV_HEADERS = {"x-dev-token": "test-dev-secret"}


# -- Auth & Identity Tests -----------------------------------------------------

async def test_whoami_unauthenticated_fails(client):
    resp = await client.get("/api/v1/auth/whoami")
    assert resp.status_code == 401
    data = resp.json()
    assert data["code"] == "UNAUTHORIZED"


async def test_whoami_with_dev_token(client):
    resp = await client.get("/api/v1/auth/whoami", headers=DEV_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == "dev-admin"
    assert data["tenant_id"] == "default"
    assert "admin" in data["roles"]
    assert "rules:write" in data["permissions"]


async def test_arbitrary_api_key_is_rejected(client):
    resp = await client.get(
        "/api/v1/auth/whoami",
        headers={"x-api-key": "anything"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "UNAUTHORIZED"


async def test_configured_service_identity_is_tenant_bound(client):
    headers = {"x-api-key": "test-service-secret"}
    resp = await client.get("/api/v1/auth/whoami", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == "tenant-service"
    assert resp.json()["roles"] == ["viewer"]

    mismatch = await client.get(
        "/api/v1/auth/whoami",
        headers={**headers, "x-tenant-id": "another-tenant"},
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["code"] == "TENANT_MISMATCH"


async def test_token_generation_requires_admin_authentication(client):
    resp = await client.post(
        "/api/v1/auth/token",
        json={
            "user_id": "self-issued-admin",
            "tenant_id": "default",
            "roles": ["admin"],
        },
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "path,method",
    [
        ("/api/v1/control/status", "get"),
        ("/api/v1/ingest/stats", "get"),
        ("/api/v1/ingest/summary", "get"),
        ("/api/v1/ingest/recent", "get"),
        ("/api/v1/intel/status", "get"),
        ("/api/v1/intel/sync", "post"),
        ("/api/v1/control/compiler/compile", "post"),
    ],
)
async def test_control_endpoints_require_authentication(client, path, method):
    kwargs = {"json": {"source": "rule x {}"}} if method == "post" else {}
    resp = await getattr(client, method)(path, **kwargs)
    assert resp.status_code == 401


async def test_compiler_rejects_server_and_output_paths(client):
    source_path = await client.post(
        "/api/v1/control/compiler/compile",
        headers=DEV_HEADERS,
        json={"source_path": "/etc/passwd"},
    )
    assert source_path.status_code == 400
    assert source_path.json()["code"] == "SOURCE_PATH_DISABLED"

    output_path = await client.post(
        "/api/v1/control/compiler/compile",
        headers=DEV_HEADERS,
        json={"source": "rule x {}", "emit_runtime_ir": "/tmp/output.json"},
    )
    assert output_path.status_code == 400
    assert output_path.json()["code"] == "UNSAFE_OUTPUT_PATH"


async def test_compiler_returns_controlled_runtime_ir(client):
    resp = await client.post(
        "/api/v1/control/compiler/compile",
        headers=DEV_HEADERS,
        json={
            "source": 'rule "compile_api" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.pid > 0\n  respond alert high\n}',
            "mode": "runtime-ir",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is True
    assert payload["runtime_ir"]["version"] == 1
    assert payload["runtime_ir"]["rules"][0]["name"] == "compile_api"


async def test_token_generation_and_jwt_auth(client):
    # 1. Generate JWT token
    token_req = {
        "user_id": "analyst-alice",
        "tenant_id": "tenant-acme",
        "roles": ["analyst"],
        "expires_in_minutes": 60,
    }
    gen_resp = await client.post(
        "/api/v1/auth/token",
        json=token_req,
        headers=DEV_HEADERS,
    )
    assert gen_resp.status_code == 200
    token_data = gen_resp.json()
    token = token_data["access_token"]

    # 2. Authenticate using Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    whoami_resp = await client.get("/api/v1/auth/whoami", headers=headers)
    assert whoami_resp.status_code == 200
    ctx = whoami_resp.json()
    assert ctx["user_id"] == "analyst-alice"
    assert ctx["tenant_id"] == "tenant-acme"
    assert ctx["roles"] == ["analyst"]

    mismatch_resp = await client.get(
        "/api/v1/auth/whoami",
        headers={**headers, "x-tenant-id": "tenant-other"},
    )
    assert mismatch_resp.status_code == 403
    assert mismatch_resp.json()["code"] == "TENANT_MISMATCH"


async def test_expired_jwt_is_rejected(client):
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "expired-user",
            "tenant_id": "tenant-acme",
            "roles": ["viewer"],
            "iat": now - 120,
            "exp": now - 60,
        },
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )
    resp = await client.get(
        "/api/v1/auth/whoami",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "TOKEN_EXPIRED"


# -- RBAC Tests ----------------------------------------------------------------

async def test_rbac_role_guard_restriction(client):
    # Generate viewer token (lacks operator role required for deployments)
    gen_resp = await client.post(
        "/api/v1/auth/token",
        json={
            "user_id": "viewer-bob",
            "tenant_id": "tenant-acme",
            "roles": ["viewer"],
        },
        headers=DEV_HEADERS,
    )
    token = gen_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Viewer attempting mutation operation should be forbidden (403)
    deploy_req = {
        "rule_version_id": "fake-version-id",
        "environment": "production",
    }
    resp = await client.post(
        "/api/v1/deployments",
        json=deploy_req,
        headers=headers,
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "FORBIDDEN"


# -- Rule Registry & Versioning Tests ------------------------------------------

async def test_rule_lifecycle_create_version_validate_test(client):
    headers = DEV_HEADERS

    valid_oil = 'rule "detect_interactive_bash" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.name == "bash"\n  respond alert high\n}'

    # 1. Validate rule
    val_resp = await client.post(
        "/api/v1/rules/validate",
        json={"content": valid_oil},
        headers=headers,
    )
    assert val_resp.status_code == 200

    # 2. Create rule
    create_req = {
        "name": "detect_interactive_bash",
        "description": "Flags bash process execution",
        "content": valid_oil,
        "changelog": "Initial baseline",
    }
    rule_resp = await client.post(
        "/api/v1/rules",
        json=create_req,
        headers=headers,
    )
    assert rule_resp.status_code == 201
    rule_data = rule_resp.json()
    rule_id = rule_data["id"]
    assert rule_data["name"] == "detect_interactive_bash"
    assert rule_data["version_count"] == 1
    assert rule_data["latest_version"]["version"] == 1

    cross_tenant = await client.get(
        f"/api/v1/rules/{rule_id}",
        headers={"x-api-key": "test-service-secret"},
    )
    assert cross_tenant.status_code == 404

    # 3. Create version 2
    ver_req = {
        "content": 'rule "detect_interactive_bash" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.name == "bash" or p.name == "sh"\n  respond alert high\n}',
        "changelog": "Added sh binary matching",
    }
    ver_resp = await client.post(
        f"/api/v1/rules/{rule_id}/versions",
        json=ver_req,
        headers=headers,
    )
    assert ver_resp.status_code == 201
    ver_data = ver_resp.json()
    assert ver_data["version"] == 2

    # 4. Get rule details and verify version count updated to 2
    get_resp = await client.get(f"/api/v1/rules/{rule_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["version_count"] == 2

    # 5. Test rule with fixtures
    test_req = {
        "content": valid_oil,
        "fixtures": [{"event_type": "process_exec", "comm": "bash"}]
    }
    test_resp = await client.post(
        "/api/v1/rules/test",
        json=test_req,
        headers=headers,
    )
    assert test_resp.status_code == 200
    assert test_resp.json()["matched"] is True


async def test_invalid_rule_is_not_persisted(client):
    create_resp = await client.post(
        "/api/v1/rules",
        headers=DEV_HEADERS,
        json={
            "name": "invalid_rule_must_not_persist",
            "content": 'rule "broken" { from endpoint.process where }',
        },
    )
    assert create_resp.status_code == 422
    assert create_resp.json()["code"] == "RULE_INVALID"

    list_resp = await client.get("/api/v1/rules", headers=DEV_HEADERS)
    assert list_resp.status_code == 200
    assert not any(
        rule["name"] == "invalid_rule_must_not_persist"
        for rule in list_resp.json()
    )


# -- Deployment State Machine & Rollback Tests ----------------------------------

async def test_deployment_create_and_rollback(client):
    headers = DEV_HEADERS

    valid_oil = 'rule "deployable_rule" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.pid > 0\n  respond alert informational\n}'

    # 1. Create a rule and version first
    rule_resp = await client.post(
        "/api/v1/rules",
        json={
            "name": "deployable_rule",
            "content": valid_oil,
        },
        headers=headers,
    )
    rule_data = rule_resp.json()
    version_id = rule_data["latest_version"]["id"]

    # 2. Deploy rule version
    deploy_resp = await client.post(
        "/api/v1/deployments",
        json={
            "rule_version_id": version_id,
            "environment": "production",
            "strategy": "direct",
            "idempotency_key": "deployable-rule-production-v1",
        },
        headers=headers,
    )
    assert deploy_resp.status_code == 201
    dep_data = deploy_resp.json()
    dep_id = dep_data["id"]
    assert dep_data["status"] == "active"

    idempotent_resp = await client.post(
        "/api/v1/deployments",
        json={
            "rule_version_id": version_id,
            "environment": "production",
            "strategy": "direct",
            "idempotency_key": "deployable-rule-production-v1",
        },
        headers=headers,
    )
    assert idempotent_resp.status_code == 201
    assert idempotent_resp.json()["id"] == dep_id

    conflicting_resp = await client.post(
        "/api/v1/deployments",
        json={
            "rule_version_id": version_id,
            "environment": "staging",
            "strategy": "direct",
            "idempotency_key": "deployable-rule-production-v1",
        },
        headers=headers,
    )
    assert conflicting_resp.status_code == 409
    assert conflicting_resp.json()["code"] == "IDEMPOTENCY_KEY_REUSE"

    # 3. Rollback deployment
    rollback_resp = await client.post(
        f"/api/v1/deployments/{dep_id}/rollback",
        headers=headers,
    )
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["status"] == "rolled_back"

    # 4. Attempting to rollback an already rolled back deployment should fail (400)
    repeat_resp = await client.post(
        f"/api/v1/deployments/{dep_id}/rollback",
        headers=headers,
    )
    assert repeat_resp.status_code == 400


# -- Audit Logging Tests -------------------------------------------------------

async def test_audit_event_logging(client):
    headers = DEV_HEADERS

    # Retrieve audit events generated by previous mutations
    audit_resp = await client.get("/api/v1/audit/events", headers=headers)
    assert audit_resp.status_code == 200
    data = audit_resp.json()
    assert data["total"] > 0
    actions = [item["action"] for item in data["items"]]
    assert "rule.create" in actions
    assert "deployment.create" in actions
    assert "deployment.rollback" in actions
