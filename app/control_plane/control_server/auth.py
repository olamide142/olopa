"""Authentication and tenant-bound request identity for the control plane."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
from typing import Any

from fastapi import Header, HTTPException, Request, status
import jwt

from .deps import settings


ALLOWED_ROLES = frozenset({"viewer", "analyst", "operator", "admin"})
MAX_USER_ID_LENGTH = 128
MAX_TENANT_ID_LENGTH = 64


@dataclass(frozen=True)
class RequestContext:
    """Authenticated identity and immutable tenant scope for one request."""

    user_id: str
    tenant_id: str
    roles: list[str]
    token_type: str
    request_id: str

    def has_role(self, role: str) -> bool:
        """Return whether the context holds the named role or a higher role."""
        weights = {"viewer": 10, "analyst": 20, "operator": 30, "admin": 40}
        required = weights.get(role.strip().lower(), 0)
        return required > 0 and max((weights.get(item, 0) for item in self.roles), default=0) >= required


def _error(
    request: Request,
    status_code: int,
    code: str,
    message: str,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", "unknown"),
        },
    )


def get_jwt_secret() -> str:
    """Return the configured signing secret, failing closed when absent."""
    if not settings.jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_NOT_CONFIGURED",
                "message": "JWT_SECRET is not configured",
            },
        )
    return settings.jwt_secret


def _normalize_roles(raw_roles: Any) -> list[str] | None:
    if not isinstance(raw_roles, list) or not raw_roles:
        return None
    roles: list[str] = []
    for raw_role in raw_roles:
        if not isinstance(raw_role, str):
            return None
        role = raw_role.strip().lower()
        if role not in ALLOWED_ROLES:
            return None
        if role not in roles:
            roles.append(role)
    return roles


def _valid_identity_string(value: Any, max_length: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.strip()) <= max_length
    )


def _service_identities(request: Request) -> dict[str, RequestContext]:
    """Parse explicitly configured service tokens into fixed identities."""
    if not settings.service_tokens_json:
        return {}
    try:
        configured = json.loads(settings.service_tokens_json)
    except json.JSONDecodeError as exc:
        raise _error(
            request,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "AUTH_NOT_CONFIGURED",
            f"CONTROL_SERVICE_TOKENS_JSON is invalid JSON: {exc.msg}",
        ) from exc

    if not isinstance(configured, dict):
        raise _error(
            request,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "AUTH_NOT_CONFIGURED",
            "CONTROL_SERVICE_TOKENS_JSON must be a JSON object",
        )

    identities: dict[str, RequestContext] = {}
    request_id = getattr(request.state, "request_id", "unknown")
    for token, identity in configured.items():
        if not isinstance(token, str) or not token or not isinstance(identity, dict):
            raise _error(
                request,
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "AUTH_NOT_CONFIGURED",
                "Every service token must map to an identity object",
            )
        user_id = identity.get("user_id")
        tenant_id = identity.get("tenant_id")
        roles = _normalize_roles(identity.get("roles"))
        if (
            not _valid_identity_string(user_id, MAX_USER_ID_LENGTH)
            or not _valid_identity_string(tenant_id, MAX_TENANT_ID_LENGTH)
            or roles is None
        ):
            raise _error(
                request,
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "AUTH_NOT_CONFIGURED",
                "Service identities require non-empty user_id, tenant_id, and valid roles",
            )
        identities[token] = RequestContext(
            user_id=user_id.strip(),
            tenant_id=tenant_id.strip(),
            roles=roles,
            token_type="service",
            request_id=request_id,
        )
    return identities


def _authenticate_service_token(request: Request, presented: str) -> RequestContext:
    for expected, identity in _service_identities(request).items():
        if hmac.compare_digest(presented, expected):
            return identity
    raise _error(
        request,
        status.HTTP_401_UNAUTHORIZED,
        "UNAUTHORIZED",
        "Invalid service API key",
    )


def _authenticate_jwt(request: Request, token: str) -> RequestContext:
    decode_args: dict[str, Any] = {
        "algorithms": ["HS256"],
        "options": {"require": ["exp", "iat", "sub", "tenant_id", "roles"]},
    }
    if settings.jwt_issuer:
        decode_args["issuer"] = settings.jwt_issuer
    if settings.jwt_audience:
        decode_args["audience"] = settings.jwt_audience

    try:
        payload = jwt.decode(token, get_jwt_secret(), **decode_args)
    except jwt.ExpiredSignatureError as exc:
        raise _error(
            request,
            status.HTTP_401_UNAUTHORIZED,
            "TOKEN_EXPIRED",
            "Bearer token has expired",
        ) from exc
    except jwt.PyJWTError as exc:
        raise _error(
            request,
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid bearer token",
        ) from exc

    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    roles = _normalize_roles(payload.get("roles"))
    if (
        not _valid_identity_string(user_id, MAX_USER_ID_LENGTH)
        or not _valid_identity_string(tenant_id, MAX_TENANT_ID_LENGTH)
        or roles is None
    ):
        raise _error(
            request,
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Bearer token contains invalid identity claims",
        )

    return RequestContext(
        user_id=user_id.strip(),
        tenant_id=tenant_id.strip(),
        roles=roles,
        token_type="jwt",
        request_id=getattr(request.state, "request_id", "unknown"),
    )


async def get_request_context(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    x_dev_token: str | None = Header(default=None),
    x_tenant_id: str | None = Header(default=None),
) -> RequestContext:
    """Authenticate a request and bind it to exactly one tenant."""
    request_id = getattr(request.state, "request_id", "unknown")
    requested_tenant = (x_tenant_id or "").strip()
    if len(requested_tenant) > MAX_TENANT_ID_LENGTH:
        raise _error(
            request,
            status.HTTP_400_BAD_REQUEST,
            "INVALID_TENANT",
            f"Tenant IDs may not exceed {MAX_TENANT_ID_LENGTH} characters",
        )
    if not settings.auth_required:
        return RequestContext(
            user_id="auth-disabled",
            tenant_id=requested_tenant or "default",
            roles=["admin"],
            token_type="disabled",
            request_id=request_id,
        )

    credentials_present = sum(
        value is not None for value in (authorization, x_api_key, x_dev_token)
    )
    if credentials_present > 1:
        raise _error(
            request,
            status.HTTP_400_BAD_REQUEST,
            "AMBIGUOUS_CREDENTIALS",
            "Provide exactly one authentication credential",
        )

    if x_dev_token is not None:
        if not settings.dev_token or not hmac.compare_digest(x_dev_token, settings.dev_token):
            raise _error(
                request,
                status.HTTP_401_UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid development token",
            )
        context = RequestContext(
            user_id="dev-admin",
            tenant_id=requested_tenant or "default",
            roles=["admin"],
            token_type="development",
            request_id=request_id,
        )
    elif x_api_key is not None:
        context = _authenticate_service_token(request, x_api_key)
    elif authorization is not None:
        scheme, separator, token = authorization.strip().partition(" ")
        if not separator or scheme.lower() != "bearer" or not token.strip():
            raise _error(
                request,
                status.HTTP_401_UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authorization must use the Bearer scheme",
            )
        context = _authenticate_jwt(request, token.strip())
    else:
        raise _error(
            request,
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication is required",
        )

    if requested_tenant and requested_tenant != context.tenant_id:
        raise _error(
            request,
            status.HTTP_403_FORBIDDEN,
            "TENANT_MISMATCH",
            "Authenticated identity cannot access the requested tenant",
        )
    return context
