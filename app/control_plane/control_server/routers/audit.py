"""Audit events API router."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..auth import RequestContext
from ..db import get_db
from ..models.audit import AuditEvent
from ..rbac import require_operator

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


class AuditEventResponse(BaseModel):
    id: str
    request_id: str
    actor: str
    tenant_id: str
    action: str
    target: str
    result: str
    details: Dict[str, Any]
    timestamp: Optional[str]


class AuditLogPageResponse(BaseModel):
    items: List[AuditEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("/events", response_model=AuditLogPageResponse)
async def list_audit_events(
    action: Optional[str] = Query(None, description="Filter by action name"),
    actor: Optional[str] = Query(None, description="Filter by actor user ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> AuditLogPageResponse:
    """List and search mutation audit log events for caller's tenant."""
    query = select(AuditEvent).where(AuditEvent.tenant_id == ctx.tenant_id)

    if action:
        query = query.where(AuditEvent.action.ilike(f"%{action}%"))
    if actor:
        query = query.where(AuditEvent.actor == actor)

    # Count total
    count_stmt = select(func.count()).select_from(query.subquery())
    total = db.scalar(count_stmt) or 0

    # Paginate and order by newest first
    offset = (page - 1) * page_size
    query = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(page_size)
    events = db.scalars(query).all()

    items = [AuditEventResponse(**e.to_dict()) for e in events]
    total_pages = (total + page_size - 1) // page_size if page_size > 0 else 1

    return AuditLogPageResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
