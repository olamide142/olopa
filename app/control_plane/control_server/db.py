"""Database connection and session management for the control plane."""

from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import create_engine, event
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


_db_url = get_db_url()
_is_sqlite = _db_url.startswith("sqlite")

#: Bound on how long a blocked SQLite writer waits. See the connect_args note.
_SQLITE_BUSY_TIMEOUT_S = int(os.getenv("SQLITE_BUSY_TIMEOUT_S", "10"))

engine = create_engine(
    _db_url,
    connect_args=(
        # How long a blocked writer waits for the lock before failing. SQLite
        # serialises writers, so under overload this bounds how long a request
        # can hang: past it the caller gets an error and retries with backoff,
        # which degrades better than a pile of hung connections.
        {"check_same_thread": False, "timeout": _SQLITE_BUSY_TIMEOUT_S}
        if _is_sqlite
        else {}
    ),
    echo=os.getenv("SQL_ECHO", "0").lower() in ("1", "true"),
)


if _is_sqlite:

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _record) -> None:
        """Make SQLite viable for concurrent request handling.

        Rolling journal mode serialises readers against the single writer and
        fsyncs on every commit, which dominates request latency under load. WAL
        lets reads proceed during a write, and NORMAL keeps the fsync per
        checkpoint rather than per commit — durable across process crashes,
        which is the failure mode that matters here.
        """
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_S * 1000}")
        finally:
            cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all table schemas defined by loaded ORM models."""
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)


async def get_db() -> AsyncGenerator[Session, None]:
    """FastAPI dependency yielding a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
