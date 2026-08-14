"""Deployment state machine and rollback API router."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..audit import log_audit_event
from ..auth import RequestContext
from ..db import get_db
from ..models.deployment import Deployment, DeploymentStatus, DeploymentStrategy
from ..models.rule import Rule, RuleVersion
from ..rbac import require_viewer, require_operator

router = APIRouter(prefix="/api/v1/deployments", tags=["deployments"])


class CreateDeploymentRequest(BaseModel):
    rule_version_id: str = Field(..., example="550e8400-e29b-41d4-a716-446655440000")
    environment: str = Field(default="production", example="production")
    strategy: DeploymentStrategy = Field(default=DeploymentStrategy.DIRECT)
    idempotency_key: Optional[str] = Field(None, example="deploy-rev-42")


class DeploymentResponse(BaseModel):
    id: str
    tenant_id: str
    environment: str
    rule_version_id: str
    status: str
    strategy: str
    idempotency_key: Optional[str]
    created_by: str
    message: Optional[str]
    details: Dict[str, Any]
    created_at: Optional[str]
    updated_at: Optional[str]


@router.post("", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
async def create_deployment(
    req: CreateDeploymentRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> DeploymentResponse:
    """Create and trigger a new deployment for a rule version."""
    # Check idempotency key if provided
    if req.idempotency_key:
        existing = db.scalars(
            select(Deployment).where(
                Deployment.tenant_id == ctx.tenant_id,
                Deployment.idempotency_key == req.idempotency_key,
            )
        ).first()
        if existing:
            return DeploymentResponse(**existing.to_dict())

    # Verify rule version exists and belongs to caller tenant
    ver = db.scalars(select(RuleVersion).where(RuleVersion.id == req.rule_version_id)).first()
    if not ver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule version '{req.rule_version_id}' not found",
        )

    rule = db.scalars(select(Rule).where(Rule.id == ver.rule_id, Rule.tenant_id == ctx.tenant_id)).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Rule version '{req.rule_version_id}' does not belong to tenant '{ctx.tenant_id}'",
        )

    # Instantiate deployment state machine: pending -> deploying -> active
    dep = Deployment(
        tenant_id=ctx.tenant_id,
        environment=req.environment,
        rule_version_id=req.rule_version_id,
        status=DeploymentStatus.PENDING.value,
        strategy=req.strategy.value,
        idempotency_key=req.idempotency_key,
        created_by=ctx.user_id,
        message="Deployment requested",
    )
    db.add(dep)
    db.commit()

    # Progress state machine: pending -> deploying -> active
    dep.transition_to(DeploymentStatus.DEPLOYING, message="Deploying rule bundle to agent fleet")
    db.commit()

    dep.transition_to(DeploymentStatus.ACTIVE, message="Rule bundle deployed and active")
    db.commit()
    db.refresh(dep)

    log_audit_event(
        db,
        ctx,
        action="deployment.create",
        target=f"deployment:{dep.id}",
        details={"rule_version_id": req.rule_version_id, "environment": req.environment, "status": dep.status},
    )

    return DeploymentResponse(**dep.to_dict())


@router.get("", response_model=List[DeploymentResponse])
async def list_deployments(
    environment: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> List[DeploymentResponse]:
    """List deployments for caller tenant."""
    query = select(Deployment).where(Deployment.tenant_id == ctx.tenant_id)
    if environment:
        query = query.where(Deployment.environment == environment)
    if status_filter:
        query = query.where(Deployment.status == status_filter)

    deps = db.scalars(query.order_by(Deployment.created_at.desc())).all()
    return [DeploymentResponse(**d.to_dict()) for d in deps]


@router.get("/{deployment_id}", response_model=DeploymentResponse)
async def get_deployment(
    deployment_id: str,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> DeploymentResponse:
    """Get deployment details and current status by ID."""
    dep = db.scalars(
        select(Deployment).where(Deployment.id == deployment_id, Deployment.tenant_id == ctx.tenant_id)
    ).first()
    if not dep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment '{deployment_id}' not found",
        )
    return DeploymentResponse(**dep.to_dict())


@router.post("/{deployment_id}/rollback", response_model=DeploymentResponse)
async def rollback_deployment(
    deployment_id: str,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> DeploymentResponse:
    """Execute a 1-call rollback of an active deployment to the previous state."""
    dep = db.scalars(
        select(Deployment).where(Deployment.id == deployment_id, Deployment.tenant_id == ctx.tenant_id)
    ).first()
    if not dep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment '{deployment_id}' not found",
        )

    if dep.status != DeploymentStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deployment status is '{dep.status}'; only 'active' deployments can be rolled back",
        )

    # Perform rollback state transition
    dep.transition_to(DeploymentStatus.ROLLED_BACK, message=f"Rolled back by operator {ctx.user_id}")
    db.commit()

    log_audit_event(
        db,
        ctx,
        action="deployment.rollback",
        target=f"deployment:{dep.id}",
        details={"rule_version_id": dep.rule_version_id, "previous_status": "active", "new_status": dep.status},
    )

    db.refresh(dep)
    return DeploymentResponse(**dep.to_dict())
