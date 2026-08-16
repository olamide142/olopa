"""Gateway selection and tunnel address allocation."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models.secure_connect import (
    LIVE_SESSION_STATES,
    GatewayStatus,
    SecureConnectAddressLease,
    SecureConnectGateway,
    SecureConnectSession,
)


class AllocationError(RuntimeError):
    """No gateway or address could be assigned to a session."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def select_gateway(
    db: Session,
    tenant_id: str,
    region: str = "",
    *,
    reachability_grace_secs: int = 120,
    exclude_gateway_ids: Optional[Iterable[str]] = None,
) -> SecureConnectGateway:
    """Pick the least-loaded healthy gateway for a tenant, preferring `region`.

    A gateway is eligible when an operator has it `online`, its reconciler has
    checked in recently (or has never checked in at all), and it has spare
    capacity. Tenant-dedicated gateways win over shared ones at equal load so a
    tenant with its own capacity never spills into the shared pool.
    """
    excluded = set(exclude_gateway_ids or ())
    load_subq = (
        select(
            SecureConnectSession.gateway_id.label("gateway_id"),
            func.count(SecureConnectSession.id).label("active_sessions"),
        )
        .where(SecureConnectSession.state.in_(LIVE_SESSION_STATES))
        .group_by(SecureConnectSession.gateway_id)
        .subquery()
    )

    query = (
        select(SecureConnectGateway, func.coalesce(load_subq.c.active_sessions, 0))
        .outerjoin(load_subq, load_subq.c.gateway_id == SecureConnectGateway.id)
        .where(
            SecureConnectGateway.status == GatewayStatus.ONLINE.value,
            or_(
                SecureConnectGateway.tenant_id.is_(None),
                SecureConnectGateway.tenant_id == tenant_id,
            ),
        )
    )
    candidates = [
        (gateway, load)
        for gateway, load in db.execute(query).all()
        if load < gateway.capacity
        and gateway.id not in excluded
        and gateway.is_reachable(reachability_grace_secs)
    ]
    if not candidates:
        raise AllocationError(
            "NO_GATEWAY_CAPACITY",
            "No reachable Secure Connect gateway has capacity for this tenant",
        )

    if region:
        regional = [item for item in candidates if item[0].region == region]
        if regional:
            candidates = regional

    candidates.sort(
        key=lambda item: (
            item[0].tenant_id is None,  # dedicated gateways first
            item[1] / max(item[0].capacity, 1),
            item[0].name,
        )
    )
    return candidates[0][0]


def _client_network(client_cidr: str) -> Tuple[Any, int]:
    try:
        network = ipaddress.ip_network(client_cidr, strict=False)
    except ValueError as exc:
        raise AllocationError(
            "INVALID_GATEWAY_CIDR", f"Gateway client CIDR is invalid: {exc}"
        ) from exc
    # `hosts()` already drops the network/broadcast addresses; skip one more so
    # the gateway keeps the first host address for its own tunnel interface.
    return network, 1


def allocate_address(
    db: Session, gateway: SecureConnectGateway, tenant_id: str, device_id: str
) -> str:
    """Return a stable tunnel address for a device on a gateway.

    A device keeps the same address across sessions, which keeps gateway peer
    entries and any address-based allow lists stable across reconnects.

    The lease is committed on its own rather than inside the caller's
    transaction. Two reasons: it keeps the write lock held for a single insert
    instead of the whole session-start path, and it avoids SAVEPOINT, which
    pysqlite does not implement reliably. A lease that outlives a failed session
    start is harmless — the same device reuses it on the next attempt.

    Callers must therefore allocate *before* opening other pending writes.
    """
    existing = db.scalars(
        select(SecureConnectAddressLease).where(
            SecureConnectAddressLease.gateway_id == gateway.id,
            SecureConnectAddressLease.device_id == device_id,
        )
    ).first()
    if existing:
        return existing.address

    network, reserved_hosts = _client_network(gateway.client_cidr)
    taken = set(
        db.scalars(
            select(SecureConnectAddressLease.address).where(
                SecureConnectAddressLease.gateway_id == gateway.id
            )
        ).all()
    )

    for index, candidate in enumerate(network.hosts()):
        if index < reserved_hosts:
            continue
        address = str(candidate)
        if address in taken:
            continue
        db.add(
            SecureConnectAddressLease(
                gateway_id=gateway.id,
                address=address,
                tenant_id=tenant_id,
                device_id=device_id,
            )
        )
        try:
            db.commit()
        except IntegrityError:
            # Another session start claimed this address first.
            db.rollback()
            taken.add(address)
            continue
        return address

    raise AllocationError(
        "GATEWAY_ADDRESS_POOL_EXHAUSTED",
        f"Gateway '{gateway.name}' has no free tunnel address in {gateway.client_cidr}",
    )


def release_address(db: Session, gateway_id: str, device_id: Optional[str]) -> None:
    """Free a device's lease so a revoked device stops holding pool space."""
    if not device_id:
        return
    lease = db.scalars(
        select(SecureConnectAddressLease).where(
            SecureConnectAddressLease.gateway_id == gateway_id,
            SecureConnectAddressLease.device_id == device_id,
        )
    ).first()
    if lease is not None:
        db.delete(lease)
