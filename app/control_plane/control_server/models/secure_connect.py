"""Secure Connect (managed WireGuard / ZTNA) ORM models.

The endpoint agent (`agent/agent/src/secure_connect`) is the only consumer of
the session tables, so the column semantics here mirror its wire contract:

- session state names serialise to the agent's `SessionState` snake_case names,
- `command_nonce` is strictly monotonic per session because the agent rejects
  any control response that replays or fails to advance it,
- restriction ranks are shared with the agent so the server never emits a
  relaxation the endpoint would refuse.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


def as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Return a timezone-aware UTC datetime; SQLite hands back naive values."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    aware = as_utc(value)
    return aware.isoformat() if aware else None


class SessionState(str, Enum):
    """Access states the control plane can assign to a session."""

    HEALTHY = "healthy"
    ELEVATED = "elevated"
    RESTRICTED = "restricted"
    QUARANTINED = "quarantined"
    TERMINATED = "terminated"


#: Higher rank means more restrictive. Mirrors `SessionState::restriction_rank`
#: in the agent so both sides agree on what counts as a relaxation.
RESTRICTION_RANK: Dict[str, int] = {
    SessionState.HEALTHY.value: 0,
    SessionState.ELEVATED.value: 1,
    SessionState.RESTRICTED.value: 2,
    SessionState.QUARANTINED.value: 3,
    SessionState.TERMINATED.value: 4,
}

#: States in which the endpoint still holds a usable tunnel.
LIVE_SESSION_STATES = (
    SessionState.HEALTHY.value,
    SessionState.ELEVATED.value,
    SessionState.RESTRICTED.value,
)


class ControlAction(str, Enum):
    """Commands the agent understands in a heartbeat response."""

    NONE = "none"
    REFRESH_PROFILE = "refresh_profile"
    REKEY = "rekey"
    RESTRICT = "restrict"
    QUARANTINE = "quarantine"
    TERMINATE = "terminate"


class DeviceState(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class AccessMode(str, Enum):
    SPLIT_TUNNEL = "split_tunnel"
    FULL_TUNNEL = "full_tunnel"


class GatewayStatus(str, Enum):
    ONLINE = "online"
    DRAINING = "draining"
    OFFLINE = "offline"


class SecureConnectGateway(Base):
    """A WireGuard endpoint the control plane can assign sessions to."""

    __tablename__ = "sc_gateways"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    # Dedicated gateways bind to one tenant; NULL means the pool is shared.
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    public_endpoint: Mapped[str] = mapped_column(String(256), nullable=False)
    client_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    dns_servers: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    # Operator intent, not observed health: `online` accepts new sessions,
    # `draining` keeps existing ones but takes no more, `offline` takes none and
    # its sessions are migrated away.
    status: Mapped[str] = mapped_column(
        String(32), default=GatewayStatus.ONLINE.value, index=True, nullable=False
    )
    capacity: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    # Liveness reported by the gateway reconciler. NULL means no reconciler has
    # ever checked in, which is treated as "unknown", not "dead".
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    observed_peers: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reconciler_version: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    __table_args__ = (UniqueConstraint("name", name="uq_sc_gateway_name"),)

    def is_reachable(self, grace_secs: int) -> bool:
        """False only when a gateway that *used to* report has gone silent."""
        last_seen = as_utc(self.last_seen_at)
        if last_seen is None:
            return True
        return (utc_now() - last_seen).total_seconds() <= grace_secs

    def accepts_new_sessions(self, grace_secs: int) -> bool:
        return self.status == GatewayStatus.ONLINE.value and self.is_reachable(grace_secs)

    def to_dict(self, grace_secs: int = 120) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "region": self.region,
            "tenant_id": self.tenant_id,
            "public_key": self.public_key,
            "public_endpoint": self.public_endpoint,
            "client_cidr": self.client_cidr,
            "dns_servers": list(self.dns_servers or []),
            "status": self.status,
            "capacity": self.capacity,
            "last_seen_at": _iso(self.last_seen_at),
            "observed_peers": self.observed_peers,
            "reconciler_version": self.reconciler_version,
            "reachable": self.is_reachable(grace_secs),
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
        }


class SecureConnectProfile(Base):
    """Intent-driven access profile compiled into an endpoint tunnel config."""

    __tablename__ = "sc_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    access_mode: Mapped[str] = mapped_column(
        String(32), default=AccessMode.SPLIT_TUNNEL.value, nullable=False
    )
    region: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    allowed_cidrs: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    # Applied instead of `allowed_cidrs` once a session is RESTRICTED.
    safe_cidrs: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    # Destinations that stay reachable outside the tunnel under the kill switch.
    bypass_cidrs: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    dns_servers: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    session_ttl_secs: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    rekey_interval_secs: Mapped[int] = mapped_column(Integer, default=900, nullable=False)
    persistent_keepalive_secs: Mapped[int] = mapped_column(Integer, default=25, nullable=False)
    mtu: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # severity -> risk action, e.g. {"critical": "quarantine"}
    risk_actions: Mapped[Dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_sc_profile_tenant_name"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "access_mode": self.access_mode,
            "region": self.region,
            "allowed_cidrs": list(self.allowed_cidrs or []),
            "safe_cidrs": list(self.safe_cidrs or []),
            "bypass_cidrs": list(self.bypass_cidrs or []),
            "dns_servers": list(self.dns_servers or []),
            "session_ttl_secs": self.session_ttl_secs,
            "rekey_interval_secs": self.rekey_interval_secs,
            "persistent_keepalive_secs": self.persistent_keepalive_secs,
            "mtu": self.mtu,
            "risk_actions": dict(self.risk_actions or {}),
            "is_default": self.is_default,
            "version": self.version,
            "created_by": self.created_by,
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
        }


class SecureConnectEnrollment(Base):
    """One-time enrollment token record; `jti` enforces single use."""

    __tablename__ = "sc_enrollments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    jti: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    device_hint: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    issued_by: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (UniqueConstraint("jti", name="uq_sc_enrollment_jti"),)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "jti": self.jti,
            "user_id": self.user_id,
            "device_hint": self.device_hint,
            "profile_id": self.profile_id,
            "issued_by": self.issued_by,
            "expires_at": _iso(self.expires_at),
            "used_at": _iso(self.used_at),
            "device_id": self.device_id,
            "created_at": _iso(self.created_at),
        }


class SecureConnectDevice(Base):
    """An enrolled endpoint, permanently bound to its enrollment identity."""

    __tablename__ = "sc_devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    host_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    device_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    # mTLS client certificate fingerprint captured at enrollment; the binding
    # material every later request is checked against.
    cert_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    wireguard_public_key: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    profile_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    state: Mapped[str] = mapped_column(
        String(32), default=DeviceState.ACTIVE.value, index=True, nullable=False
    )
    posture: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    enrolled_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_fingerprint", name="uq_sc_device_tenant_fingerprint"
        ),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "host_id": self.host_id,
            "user_id": self.user_id,
            "device_fingerprint": self.device_fingerprint,
            "cert_fingerprint": self.cert_fingerprint,
            "wireguard_public_key": self.wireguard_public_key,
            "profile_id": self.profile_id,
            "state": self.state,
            "posture": dict(self.posture or {}),
            "enrolled_by": self.enrolled_by,
            "enrolled_at": _iso(self.enrolled_at),
            "last_seen_at": _iso(self.last_seen_at),
            "updated_at": _iso(self.updated_at),
        }


class SecureConnectSession(Base):
    """One tunnel lifetime, from gateway assignment to teardown."""

    __tablename__ = "sc_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sc_devices.id"), index=True, nullable=False
    )
    gateway_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sc_gateways.id"), index=True, nullable=False
    )
    profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sc_profiles.id"), nullable=False
    )
    host_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    assigned_address: Mapped[str] = mapped_column(String(64), nullable=False)
    wireguard_public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(
        String(32), default=SessionState.HEALTHY.value, index=True, nullable=False
    )
    profile_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    command_nonce: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    acked_command_nonce: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pending_action: Mapped[str] = mapped_column(
        String(32), default=ControlAction.NONE.value, nullable=False
    )
    pending_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    pending_reason: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # Set when a command is queued so heartbeat can measure revoke propagation.
    pending_since: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_command_latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_rekey_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    # Start of the clean window that lets ELEVATED cool back down to HEALTHY.
    elevated_since: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_handshake_unix: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_tx: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_rx: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    posture: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    close_reason: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    terminated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    @property
    def is_live(self) -> bool:
        return self.state in LIVE_SESSION_STATES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "gateway_id": self.gateway_id,
            "profile_id": self.profile_id,
            "host_id": self.host_id,
            "assigned_address": self.assigned_address,
            "wireguard_public_key": self.wireguard_public_key,
            "state": self.state,
            "profile_version": self.profile_version,
            "command_nonce": self.command_nonce,
            "acked_command_nonce": self.acked_command_nonce,
            "pending_action": self.pending_action,
            "pending_state": self.pending_state,
            "pending_reason": self.pending_reason,
            "last_command_latency_ms": self.last_command_latency_ms,
            "started_at": _iso(self.started_at),
            "expires_at": _iso(self.expires_at),
            "last_heartbeat_at": _iso(self.last_heartbeat_at),
            "last_rekey_at": _iso(self.last_rekey_at),
            "last_handshake_unix": self.last_handshake_unix,
            "bytes_tx": self.bytes_tx,
            "bytes_rx": self.bytes_rx,
            "posture": dict(self.posture or {}),
            "close_reason": self.close_reason,
            "terminated_at": _iso(self.terminated_at),
        }


class SecureConnectKeyMaterial(Base):
    """Public-key lifetime per session. Private keys never leave the endpoint."""

    __tablename__ = "sc_key_material"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sc_sessions.id"), index=True, nullable=False
    )
    gateway_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    assigned_address: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "gateway_id": self.gateway_id,
            "public_key": self.public_key,
            "assigned_address": self.assigned_address,
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "revoked_at": _iso(self.revoked_at),
        }


class SecureConnectAddressLease(Base):
    """Stable tunnel address per device on a gateway.

    The unique `(gateway_id, address)` constraint is the allocation lock: two
    concurrent session starts cannot claim the same address.
    """

    __tablename__ = "sc_address_leases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    gateway_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(36), index=True, nullable=True)
    leased_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        UniqueConstraint("gateway_id", "address", name="uq_sc_lease_gateway_address"),
    )
