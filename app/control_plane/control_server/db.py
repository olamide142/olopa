"""Database connection and session management for the control plane."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from .config import Settings


class Base(DeclarativeBase):
    """Base class for all control plane ORM models."""

    pass


def get_db_url() -> str:
    """Get database URL from environment or default to local SQLite database."""
    env_url = os.getenv("DATABASE_URL", "").strip()
    if env_url:
        return env_url

    # Default to sqlite file in app directory
    db_path = Path(__file__).resolve().parents[1] / "control_plane.db"
    return f"sqlite:///{db_path}"


engine = create_engine(
    get_db_url(),
    connect_args={"check_same_thread": False} if get_db_url().startswith("sqlite") else {},
    echo=os.getenv("SQL_ECHO", "0").lower() in ("1", "true"),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all table schemas defined by loaded ORM models."""
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
