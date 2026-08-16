"""Deployment state machine ORM model."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import String, DateTime, JSON, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeploymentStatus(str, Enum):
    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class DeploymentStrategy(str, Enum):
    DIRECT = "direct"
    CANARY = "canary"


class Deployment(Base):
    """Rule version deployment instance with state machine transitions."""

    __tablename__ = "deployments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="production", nullable=False)
    rule_version_id: Mapped[str] = mapped_column(String(36), ForeignKey("rule_versions.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=DeploymentStatus.PENDING.value, index=True, nullable=False)
    strategy: Mapped[str] = mapped_column(String(32), default=DeploymentStrategy.DIRECT.value, nullable=False)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    VALID_TRANSITIONS = {
        DeploymentStatus.PENDING: {DeploymentStatus.DEPLOYING, DeploymentStatus.FAILED},
        DeploymentStatus.DEPLOYING: {DeploymentStatus.ACTIVE, DeploymentStatus.FAILED},
        DeploymentStatus.ACTIVE: {DeploymentStatus.ROLLED_BACK, DeploymentStatus.FAILED},
        DeploymentStatus.ROLLED_BACK: set(),
        DeploymentStatus.FAILED: set(),
    }

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_deployment_tenant_idempotency_key",
        ),
    )

    def can_transition_to(self, new_status: DeploymentStatus) -> bool:
        current = DeploymentStatus(self.status)
        return new_status in self.VALID_TRANSITIONS.get(current, set())

    def transition_to(self, new_status: DeploymentStatus, message: Optional[str] = None) -> None:
        if not self.can_transition_to(new_status):
            raise ValueError(f"Invalid deployment status transition from {self.status} to {new_status.value}")
        self.status = new_status.value
        if message:
            self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "rule_version_id": self.rule_version_id,
            "status": self.status,
            "strategy": self.strategy,
            "idempotency_key": self.idempotency_key,
            "created_by": self.created_by,
            "message": self.message,
            "details": self.details or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
