"""Authentication status and token utility router."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
import jwt

from ..auth import RequestContext, get_request_context, get_jwt_secret
from ..rbac import require_viewer, Role, ROLE_HIERARCHY

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class WhoAmIResponse(BaseModel):
    user_id: str
    tenant_id: str
    roles: List[str]
    token_type: str
    request_id: str
    permissions: List[str]


class TokenRequest(BaseModel):
    user_id: str = Field(..., example="operator-1")
    tenant_id: str = Field(default="default", example="default")
    roles: List[str] = Field(default=["operator"], example=["operator", "analyst"])
    expires_in_minutes: int = Field(default=60, ge=1, le=10080)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: str


@router.get("/whoami", response_model=WhoAmIResponse)
async def whoami(ctx: RequestContext = Depends(require_viewer)) -> WhoAmIResponse:
    """Return identity, tenant scope, and role permissions of current caller."""
    permissions = []
    if ctx.has_role("viewer"):
        permissions.extend(["rules:read", "metrics:read", "incidents:read", "agents:read", "deployments:read"])
    if ctx.has_role("analyst"):
        permissions.extend(["rules:write", "rules:compile", "rules:test", "incidents:write"])
    if ctx.has_role("operator"):
        permissions.extend(["deployments:write", "deployments:rollback", "agents:manage", "settings:write"])
    if ctx.has_role("admin"):
        permissions.extend(["audit:read", "rbac:manage", "tenant:manage", "system:admin"])

    return WhoAmIResponse(
        user_id=ctx.user_id,
        tenant_id=ctx.tenant_id,
        roles=ctx.roles,
        token_type=ctx.token_type,
        request_id=ctx.request_id,
        permissions=list(set(permissions)),
    )


@router.post("/token", response_model=TokenResponse)
async def generate_dev_token(req: TokenRequest) -> TokenResponse:
    """Generate a signed JWT token for testing and local integration."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=req.expires_in_minutes)
    payload = {
        "sub": req.user_id,
        "user_id": req.user_id,
        "tenant_id": req.tenant_id,
        "roles": req.roles,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    secret = get_jwt_secret()
    token = jwt.encode(payload, secret, algorithm="HS256")
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_at=exp.isoformat(),
    )
