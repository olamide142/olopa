"""Authentication status and token utility router."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
import jwt

from ..auth import RequestContext, get_jwt_secret
from ..deps import settings
from ..rbac import require_admin, require_viewer, Role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class WhoAmIResponse(BaseModel):
    user_id: str
    tenant_id: str
    roles: List[str]
    token_type: str
    request_id: str
    permissions: List[str]


class TokenRequest(BaseModel):
    user_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        json_schema_extra={"example": "operator-1"},
    )
    tenant_id: str = Field(
        default="default",
        min_length=1,
        max_length=64,
        json_schema_extra={"example": "default"},
    )
    roles: List[Role] = Field(
        default_factory=lambda: [Role.OPERATOR],
        min_length=1,
        max_length=4,
        json_schema_extra={"example": ["operator", "analyst"]},
    )
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
async def generate_dev_token(
    req: TokenRequest,
    ctx: RequestContext = Depends(require_admin),
) -> TokenResponse:
    """Generate a signed JWT when explicitly enabled for development."""
    if not settings.dev_token_issuance_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "TOKEN_ISSUANCE_DISABLED",
                "message": "Development token issuance is disabled",
                "request_id": ctx.request_id,
            },
        )
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=req.expires_in_minutes)
    payload = {
        "sub": req.user_id,
        "user_id": req.user_id,
        "tenant_id": req.tenant_id,
        "roles": [role.value for role in req.roles],
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    if settings.jwt_issuer:
        payload["iss"] = settings.jwt_issuer
    if settings.jwt_audience:
        payload["aud"] = settings.jwt_audience
    secret = get_jwt_secret()
    token = jwt.encode(payload, secret, algorithm="HS256")
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_at=exp.isoformat(),
    )
