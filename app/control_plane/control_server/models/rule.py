"""Rule and RuleVersion ORM models."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import String, Integer, DateTime, JSON, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Rule(Base):
    """First-class rule entity owned by a tenant."""

    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    versions: Mapped[List[RuleVersion]] = relationship(
        "RuleVersion", back_populates="rule", cascade="all, delete-orphan", order_by="RuleVersion.version"
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_rule_tenant_name"),
    )

    def to_dict(self, include_latest_version: bool = True) -> Dict[str, Any]:
        latest = self.versions[-1].to_dict() if self.versions and include_latest_version else None
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "owner": self.owner,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "version_count": len(self.versions),
            "latest_version": latest,
        }


class RuleVersion(Base):
    """Immutable rule version snapshot with content, hash, and diagnostics."""

    __tablename__ = "rule_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("rules.id"), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    changelog: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compiled_ir: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    diagnostics: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    rule: Mapped[Rule] = relationship("Rule", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_rule_version_number"),
    )

    @staticmethod
    def compute_hash(content: str) -> str:
        return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "version": self.version,
            "content": self.content,
            "content_hash": self.content_hash,
            "author": self.author,
            "changelog": self.changelog,
            "compiled_ir": self.compiled_ir,
            "diagnostics": self.diagnostics or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
