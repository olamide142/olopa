"""Comprehensive integration tests for control plane authn, RBAC, audit, rule registry, and deployments."""

import os
import tempfile
from pathlib import Path

# Setup temp DB environment BEFORE importing control_server modules
db_file = Path(tempfile.gettempdir()) / "test_control_plane.db"
db_file.unlink(missing_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"
os.environ["CONTROL_AUTH_REQUIRED"] = "1"
os.environ["CONTROL_DEV_TOKEN"] = "test-dev-secret"

import pytest
from fastapi.testclient import TestClient

from control_server.main import app
from control_server.db import init_db

init_db()
client = TestClient(app)

DEV_HEADERS = {"x-dev-token": "test-dev-secret"}


# -- Auth & Identity Tests -----------------------------------------------------

def test_whoami_unauthenticated_fails():
    resp = client.get("/api/v1/auth/whoami")
    assert resp.status_code == 401
    data = resp.json()
    assert data["code"] == "UNAUTHORIZED"


def test_whoami_with_dev_token():
    resp = client.get("/api/v1/auth/whoami", headers=DEV_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == "dev-admin"
    assert data["tenant_id"] == "default"
    assert "admin" in data["roles"]
    assert "rules:write" in data["permissions"]


def test_token_generation_and_jwt_auth():
    # 1. Generate JWT token
    token_req = {
        "user_id": "analyst-alice",
        "tenant_id": "tenant-acme",
        "roles": ["analyst"],
        "expires_in_minutes": 60,
    }
    gen_resp = client.post("/api/v1/auth/token", json=token_req)
    assert gen_resp.status_code == 200
    token_data = gen_resp.json()
    token = token_data["access_token"]

    # 2. Authenticate using Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    whoami_resp = client.get("/api/v1/auth/whoami", headers=headers)
    assert whoami_resp.status_code == 200
    ctx = whoami_resp.json()
    assert ctx["user_id"] == "analyst-alice"
    assert ctx["tenant_id"] == "tenant-acme"
    assert ctx["roles"] == ["analyst"]


# -- RBAC Tests ----------------------------------------------------------------

def test_rbac_role_guard_restriction():
    # Generate viewer token (lacks operator role required for deployments)
    gen_resp = client.post("/api/v1/auth/token", json={
        "user_id": "viewer-bob",
        "tenant_id": "tenant-acme",
        "roles": ["viewer"],
    })
    token = gen_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Viewer attempting mutation operation should be forbidden (403)
    deploy_req = {
        "rule_version_id": "fake-version-id",
        "environment": "production",
    }
    resp = client.post("/api/v1/deployments", json=deploy_req, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["code"] == "FORBIDDEN"


# -- Rule Registry & Versioning Tests ------------------------------------------

def test_rule_lifecycle_create_version_validate_test():
    headers = DEV_HEADERS

    valid_oil = 'rule "detect_interactive_bash" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.binary.name == "bash"\n  respond alert high\n}'

    # 1. Validate rule
    val_resp = client.post("/api/v1/rules/validate", json={
        "content": valid_oil
    }, headers=headers)
    assert val_resp.status_code == 200

    # 2. Create rule
    create_req = {
        "name": "detect_interactive_bash",
        "description": "Flags bash process execution",
        "content": valid_oil,
        "changelog": "Initial baseline",
    }
    rule_resp = client.post("/api/v1/rules", json=create_req, headers=headers)
    assert rule_resp.status_code == 201
    rule_data = rule_resp.json()
    rule_id = rule_data["id"]
    assert rule_data["name"] == "detect_interactive_bash"
    assert rule_data["version_count"] == 1
    assert rule_data["latest_version"]["version"] == 1

    # 3. Create version 2
    ver_req = {
        "content": 'rule "detect_interactive_bash" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.binary.name == "bash" or p.binary.name == "sh"\n  respond alert high\n}',
        "changelog": "Added sh binary matching",
    }
    ver_resp = client.post(f"/api/v1/rules/{rule_id}/versions", json=ver_req, headers=headers)
    assert ver_resp.status_code == 201
    ver_data = ver_resp.json()
    assert ver_data["version"] == 2

    # 4. Get rule details and verify version count updated to 2
    get_resp = client.get(f"/api/v1/rules/{rule_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["version_count"] == 2

    # 5. Test rule with fixtures
    test_req = {
        "content": valid_oil,
        "fixtures": [{"event_type": "process_exec", "comm": "bash"}]
    }
    test_resp = client.post("/api/v1/rules/test", json=test_req, headers=headers)
    assert test_resp.status_code == 200
    assert test_resp.json()["matched"] is True


# -- Deployment State Machine & Rollback Tests ----------------------------------

def test_deployment_create_and_rollback():
    headers = DEV_HEADERS

    valid_oil = 'rule "deployable_rule" {\n  from endpoint.process\n  correlate process.exec as p\n  where p.pid > 0\n  respond alert info\n}'

    # 1. Create a rule and version first
    rule_resp = client.post("/api/v1/rules", json={
        "name": "deployable_rule",
        "content": valid_oil,
    }, headers=headers)
    rule_data = rule_resp.json()
    version_id = rule_data["latest_version"]["id"]

    # 2. Deploy rule version
    deploy_resp = client.post("/api/v1/deployments", json={
        "rule_version_id": version_id,
        "environment": "production",
        "strategy": "direct",
    }, headers=headers)
    assert deploy_resp.status_code == 201
    dep_data = deploy_resp.json()
    dep_id = dep_data["id"]
    assert dep_data["status"] == "active"

    # 3. Rollback deployment
    rollback_resp = client.post(f"/api/v1/deployments/{dep_id}/rollback", headers=headers)
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["status"] == "rolled_back"

    # 4. Attempting to rollback an already rolled back deployment should fail (400)
    repeat_resp = client.post(f"/api/v1/deployments/{dep_id}/rollback", headers=headers)
    assert repeat_resp.status_code == 400


# -- Audit Logging Tests -------------------------------------------------------

def test_audit_event_logging():
    headers = DEV_HEADERS

    # Retrieve audit events generated by previous mutations
    audit_resp = client.get("/api/v1/audit/events", headers=headers)
    assert audit_resp.status_code == 200
    data = audit_resp.json()
    assert data["total"] > 0
    actions = [item["action"] for item in data["items"]]
    assert "rule.create" in actions
    assert "deployment.create" in actions
    assert "deployment.rollback" in actions
