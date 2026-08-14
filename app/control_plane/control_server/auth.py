"""Authentication dependency and RequestContext for control plane."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import uuid
from typing import List, Optional

from fastapi import Depends, Header, HTTPException, Request, status
import jwt

from .config import Settings
from .deps import settings


@dataclass(frozen=True)
class RequestContext:
    """Central context representing authenticated caller and tenant boundary."""

    user_id: str
    tenant_id: str
    roles: List[str] = field(default_factory=lambda: ["viewer"])
    token_type: str = "bearer"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def has_role(self, role: str) -> bool:
        return role.lower() in [r.lower() for r in self.roles] or "admin" in [r.lower() for r in self.roles]


def get_jwt_secret() -> str:
    return os.getenv("JWT_SECRET", "olopa-control-plane-dev-secret-key-32bytes!")


def parse_bearer_token(token: str, request_id: str) -> RequestContext:
    secret = get_jwt_secret()
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return RequestContext(
            user_id=str(payload.get("sub") or payload.get("user_id") or "user-unknown"),
            tenant_id=str(payload.get("tenant_id") or "default"),
            roles=list(payload.get("roles") or ["viewer"]),
            token_type="jwt",
            request_id=request_id,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_TOKEN",
                "message": f"Invalid or expired authentication token: {exc}",
                "request_id": request_id,
            },
        ) from exc


def get_request_context(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    x_dev_token: Optional[str] = Header(None, alias="x-dev-token"),
    x_tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
) -> RequestContext:
    """FastAPI dependency to extract and validate caller identity and tenant scope."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    auth_required = os.getenv("CONTROL_AUTH_REQUIRED", "1").lower() in ("1", "true", "yes")
    dev_secret = os.getenv("CONTROL_DEV_TOKEN", "dev-secret")

    # 1. Dev token check
    token_candidate = None
    if authorization and authorization.startswith("Bearer "):
        token_candidate = authorization[7:].strip()
    elif x_dev_token:
        token_candidate = x_dev_token.strip()

    if token_candidate == dev_secret or (x_api_key and x_api_key == dev_secret):
        tenant = x_tenant_id or "default"
        return RequestContext(
            user_id="dev-admin",
            tenant_id=tenant,
            roles=["admin", "operator", "analyst", "viewer"],
            token_type="dev_token",
            request_id=request_id,
        )

    # 2. JWT bearer token check
    if token_candidate:
        return parse_bearer_token(token_candidate, request_id)

    # 3. API key / service token check
    if x_api_key:
        tenant = x_tenant_id or "default"
        return RequestContext(
            user_id="service-account",
            tenant_id=tenant,
            roles=["operator", "analyst", "viewer"],
            token_type="api_key",
            request_id=request_id,
        )

    # 4. Optional authentication fallback for dev checkouts when CONTROL_AUTH_REQUIRED=0
    if not auth_required:
        return RequestContext(
            user_id="anonymous-dev",
            tenant_id=x_tenant_id or "default",
            roles=["admin", "operator", "analyst", "viewer"],
            token_type="anonymous",
            request_id=request_id,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "UNAUTHORIZED",
            "message": "Authentication credentials were not provided.",
            "request_id": request_id,
        },
    )
