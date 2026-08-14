"""Role-Based Access Control (RBAC) authorization dependencies."""

from __future__ import annotations

from enum import Enum
from typing import Callable, List

from fastapi import Depends, HTTPException, status

from .auth import RequestContext, get_request_context


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


# Role hierarchy weights
ROLE_HIERARCHY = {
    Role.VIEWER: 10,
    Role.ANALYST: 20,
    Role.OPERATOR: 30,
    Role.ADMIN: 40,
}


def get_role_weight(role_name: str) -> int:
    try:
        return ROLE_HIERARCHY[Role(role_name.lower())]
    except ValueError:
        return 0


def require_roles(*allowed_roles: Role) -> Callable[[RequestContext], RequestContext]:
    """Dependency generator enforcing that caller holds at least one allowed role (or higher)."""
    min_required_weight = min([ROLE_HIERARCHY[r] for r in allowed_roles]) if allowed_roles else 0

    def rbac_guard(ctx: RequestContext = Depends(get_request_context)) -> RequestContext:
        user_max_weight = max([get_role_weight(r) for r in ctx.roles], default=0)
        if user_max_weight < min_required_weight:
            allowed_names = [r.value for r in allowed_roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": f"Caller roles {ctx.roles} do not satisfy required role(s): {allowed_names}",
                    "request_id": ctx.request_id,
                },
            )
        return ctx

    return rbac_guard


# Pre-configured common guards
require_viewer = require_roles(Role.VIEWER)
require_analyst = require_roles(Role.ANALYST)
require_operator = require_roles(Role.OPERATOR)
require_admin = require_roles(Role.ADMIN)
