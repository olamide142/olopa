"""Detection-stream subscription for Secure Connect.

The agent's rule engine emits alerts into the normal telemetry stream, so the
orchestrator correlates access decisions by reading ingested alert rows rather
than by owning a second detection path. Each alert is mapped to a severity,
matched to the live sessions anchored to the alerting host, and handed to the
risk adapter.

Rows are consumed at-most-once per `(host, rule, event)` identity: ingest keeps
a rolling in-memory window that is re-read on every poll, so without dedup a
single alert would re-fire on every tick.
"""

from __future__ import annotations

from collections import OrderedDict
import logging
from typing import Any, Dict, Iterable, List, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import log_audit_event
from ..auth import RequestContext
from ..models.secure_connect import LIVE_SESSION_STATES, SecureConnectSession
from . import service

logger = logging.getLogger("control_plane.secure_connect.risk")

#: Alert rows carry this marker in `attrs.wire`; everything else is telemetry.
ALERT_WIRE = "alert_binary"

#: Bound on remembered alert identities. Comfortably larger than the ingest
#: window the poller reads, so nothing is reprocessed before it ages out.
SEEN_ALERT_CAPACITY = 20_000

ACTOR = "secure-connect-risk-adapter"


class AlertDeduper:
    """Bounded FIFO of alert identities already applied to access decisions."""

    def __init__(self, capacity: int = SEEN_ALERT_CAPACITY) -> None:
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._capacity = max(capacity, 1)

    def is_new(self, identity: str) -> bool:
        if identity in self._seen:
            return False
        self._seen[identity] = None
        while len(self._seen) > self._capacity:
            self._seen.popitem(last=False)
        return True

    def __len__(self) -> int:
        return len(self._seen)


def severity_for_risk_score(
    score: float, thresholds: Tuple[float, float, float]
) -> str:
    """Bucket an alert's risk score into the severity vocabulary."""
    critical, high, medium = thresholds
    if score >= critical:
        return "critical"
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    return "low"


def alert_identity(row: Dict[str, Any], attrs: Dict[str, Any]) -> str:
    """Stable identity for one alert occurrence."""
    return "|".join(
        str(part)
        for part in (
            row.get("tenant_id", ""),
            row.get("host_id", ""),
            attrs.get("rule_id", ""),
            attrs.get("ts_ns", ""),
            attrs.get("vertex_id", ""),
            attrs.get("dst_vertex_id", ""),
        )
    )


def extract_alerts(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep only rows the agent emitted as rule alerts."""
    alerts: List[Dict[str, Any]] = []
    for row in rows:
        event = row.get("event")
        if not isinstance(event, dict):
            continue
        attrs = event.get("attrs")
        if not isinstance(attrs, dict) or attrs.get("wire") != ALERT_WIRE:
            continue
        alerts.append({**row, "attrs": attrs})
    return alerts


async def fetch_recent_rows(
    base_url: str, api_token: str, limit: int, timeout_s: float
) -> List[Dict[str, Any]]:
    """Read the ingest server's recent-row window across all tenants."""
    headers = {"authorization": f"Bearer {api_token}"} if api_token else {}
    url = f"{base_url}/api/v1/ingest/recent"
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        response = await client.get(url, params={"limit": limit}, headers=headers)
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("rows", [])
    return rows if isinstance(rows, list) else []


def _context(tenant_id: str) -> RequestContext:
    """Synthetic identity so automated transitions are auditable like any other."""
    return RequestContext(
        user_id=ACTOR,
        tenant_id=tenant_id,
        roles=["operator"],
        token_type="service",
        request_id="risk-adapter",
    )


def apply_alert(
    db: Session,
    tenant_id: str,
    host_id: str,
    severity: str,
    attrs: Dict[str, Any],
) -> int:
    """Drive the sessions anchored to an alerting host; returns transitions."""
    sessions = list(
        db.scalars(
            select(SecureConnectSession).where(
                SecureConnectSession.tenant_id == tenant_id,
                SecureConnectSession.host_id == host_id,
                SecureConnectSession.state.in_(LIVE_SESSION_STATES),
            )
        ).all()
    )
    if not sessions:
        return 0

    rule_name = str(attrs.get("rule_name") or attrs.get("rule_id") or "detection")
    reason = f"{severity} alert: {rule_name}"
    target, transitioned = service.apply_risk_signal(db, sessions, severity, reason)
    if not transitioned:
        db.commit()
        return 0

    db.commit()
    log_audit_event(
        db,
        _context(tenant_id),
        action="secure_connect.risk.transition",
        target=f"sc_host:{host_id}",
        details={
            "severity": severity,
            "rule_id": attrs.get("rule_id"),
            "rule_name": attrs.get("rule_name"),
            "risk_score": attrs.get("risk_score"),
            "target_state": target.value if target else None,
            "sessions": [session.id for session in transitioned],
            "source": "ingest_alert_stream",
        },
    )
    logger.info(
        "secure-connect risk transition host=%s severity=%s rule=%s sessions=%d",
        host_id,
        severity,
        rule_name,
        len(transitioned),
    )
    return len(transitioned)


async def poll_once(
    db: Session,
    deduper: AlertDeduper,
    *,
    base_url: str,
    api_token: str,
    limit: int,
    timeout_s: float,
    thresholds: Tuple[float, float, float],
) -> Dict[str, int]:
    """One subscription tick: read alerts, correlate, enforce."""
    try:
        rows = await fetch_recent_rows(base_url, api_token, limit, timeout_s)
    except (httpx.HTTPError, ValueError) as exc:
        # A detection-stream outage must not disturb existing tunnels.
        logger.warning("secure-connect risk poll failed: %s", exc)
        return {"rows": 0, "alerts": 0, "applied": 0, "transitions": 0}

    alerts = extract_alerts(rows)
    applied = 0
    transitions = 0
    for alert in alerts:
        attrs = alert["attrs"]
        if not deduper.is_new(alert_identity(alert, attrs)):
            continue
        tenant_id = str(alert.get("tenant_id") or "")
        host_id = str(alert.get("host_id") or "")
        if not tenant_id or not host_id:
            continue
        try:
            score = float(attrs.get("risk_score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        severity = severity_for_risk_score(score, thresholds)
        applied += 1
        try:
            transitions += apply_alert(db, tenant_id, host_id, severity, attrs)
        except Exception as exc:  # pragma: no cover - defensive
            db.rollback()
            logger.error("secure-connect risk application failed: %s", exc)

    return {
        "rows": len(rows),
        "alerts": len(alerts),
        "applied": applied,
        "transitions": transitions,
    }
