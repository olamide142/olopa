"""Background maintenance loop for Secure Connect.

Two jobs run on the same tick:

- **reaper**: sessions whose profile expired and were never renewed are closed
  and their keys revoked. Without it a device that goes dark keeps a live peer
  entry on its gateway forever.
- **risk subscriber**: alerts from the ingest stream are correlated to live
  sessions and enforced.

The loop is deliberately fault-tolerant: an outage in either job is logged and
retried on the next tick, and never propagates into request handling.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import log_audit_event
from ..auth import RequestContext
from ..db import SessionLocal
from ..deps import settings
from ..models.secure_connect import (
    LIVE_SESSION_STATES,
    SecureConnectSession,
    SessionState,
    as_utc,
    utc_now,
)
from . import key_manager, risk_adapter, service
from .risk_subscriber import AlertDeduper, poll_once

logger = logging.getLogger("control_plane.secure_connect.worker")


def reap_expired_sessions(db: Session, grace_secs: int) -> List[str]:
    """Close live sessions whose profile expired beyond the grace window."""
    cutoff = utc_now() - timedelta(seconds=max(grace_secs, 0))
    candidates = db.scalars(
        select(SecureConnectSession).where(
            SecureConnectSession.state.in_(LIVE_SESSION_STATES)
        )
    ).all()

    reaped: List[str] = []
    by_tenant: Dict[str, List[str]] = {}
    for session in candidates:
        expires_at = as_utc(session.expires_at)
        if expires_at is None or expires_at > cutoff:
            continue
        risk_adapter.apply_transition(
            db,
            session,
            SessionState.TERMINATED,
            "session expired without renewal",
        )
        key_manager.revoke_key_material(db, session.id)
        reaped.append(session.id)
        by_tenant.setdefault(session.tenant_id, []).append(session.id)

    if not reaped:
        return []

    db.commit()
    for tenant_id, session_ids in by_tenant.items():
        log_audit_event(
            db,
            _reaper_context(tenant_id),
            action="secure_connect.session.expire",
            target=f"sc_tenant:{tenant_id}",
            details={"sessions": session_ids, "reason": "expired without renewal"},
        )
    logger.info("secure-connect reaped %d expired session(s)", len(reaped))
    return reaped


def _reaper_context(tenant_id: str) -> RequestContext:
    """Synthetic identity so automated closures are auditable like any other."""
    return RequestContext(
        user_id="secure-connect-reaper",
        tenant_id=tenant_id,
        roles=["operator"],
        token_type="service",
        request_id="reaper",
    )


async def run_maintenance_loop(stop: Optional[asyncio.Event] = None) -> None:
    """Run reaping and risk subscription until cancelled."""
    deduper = AlertDeduper()
    interval = max(settings.sc_worker_interval_secs, 5)
    thresholds = (
        settings.sc_risk_critical_score,
        settings.sc_risk_high_score,
        settings.sc_risk_medium_score,
    )
    logger.info(
        "secure-connect worker started interval=%ss risk_subscriber=%s",
        interval,
        settings.sc_risk_subscriber_enabled,
    )

    while not (stop and stop.is_set()):
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break

        db = SessionLocal()
        try:
            reap_expired_sessions(db, settings.sc_heartbeat_grace_secs)
        except Exception as exc:  # pragma: no cover - defensive
            db.rollback()
            logger.error("secure-connect reaper failed: %s", exc)
        finally:
            db.close()

        if settings.sc_auto_failover_enabled:
            db = SessionLocal()
            try:
                migrated, stranded = service.failover_sessions(
                    db, reachability_grace_secs=settings.sc_gateway_grace_secs
                )
                if migrated or stranded:
                    logger.info(
                        "secure-connect failover migrated=%d stranded=%d",
                        migrated,
                        stranded,
                    )
            except Exception as exc:  # pragma: no cover - defensive
                db.rollback()
                logger.error("secure-connect failover failed: %s", exc)
            finally:
                db.close()

        if not settings.sc_risk_subscriber_enabled:
            continue

        db = SessionLocal()
        try:
            await poll_once(
                db,
                deduper,
                base_url=settings.rust_ingest_base_url,
                api_token=settings.rust_ingest_api_token,
                limit=settings.sc_alert_poll_limit,
                timeout_s=settings.rust_request_timeout_s,
                thresholds=thresholds,
            )
        except Exception as exc:  # pragma: no cover - defensive
            db.rollback()
            logger.error("secure-connect risk subscriber failed: %s", exc)
        finally:
            db.close()
