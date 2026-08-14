"""Audit event recording helpers."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from .auth import RequestContext
from .models.audit import AuditEvent

logger = logging.getLogger("control_plane.audit")


def log_audit_event(
    db: Session,
    ctx: RequestContext,
    action: str,
    target: str,
    result: str = "success",
    details: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """Record a mutating action in the audit log table and structured logger."""
    event = AuditEvent(
        request_id=ctx.request_id,
        actor=ctx.user_id,
        tenant_id=ctx.tenant_id,
        action=action,
        target=target,
        result=result,
        details=details or {},
    )
    db.add(event)
    try:
        db.commit()
        db.refresh(event)
    except Exception as exc:
        db.rollback()
        logger.error("Failed to commit audit event %s: %s", action, exc)
        raise

    logger.info(
        "AUDIT_EVENT actor=%s tenant=%s action=%s target=%s result=%s req_id=%s",
        ctx.user_id,
        ctx.tenant_id,
        action,
        target,
        result,
        ctx.request_id,
    )
    return event
