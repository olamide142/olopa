"""Secure Connect orchestration: enrollment, sessions, heartbeats, rekey.

This module owns every decision the endpoint is told to apply. The agent trusts
the control plane for policy but verifies the invariants it can check locally
(monotonic command nonces, no unconfirmed relaxations, well-formed profiles), so
anything emitted here has to satisfy those rules or the tunnel drops.
"""

from __future__ import annotations

from datetime import timedelta
import ipaddress
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.secure_connect import (
    LIVE_SESSION_STATES,
    AccessMode,
    ControlAction,
    DeviceState,
    GatewayStatus,
    SecureConnectDevice,
    SecureConnectGateway,
    SecureConnectProfile,
    SecureConnectSession,
    SessionState,
    as_utc,
    utc_now,
)
from . import allocator, key_manager, risk_adapter
from .schemas import (
    EnrollmentRequest,
    HeartbeatRequest,
    HeartbeatResponse,
    RekeyRequest,
    RekeyResponse,
    SessionStartRequest,
    SessionStartResponse,
    TunnelProfile,
)

#: Renew the tunnel profile once this much of its lifetime remains, so a
#: heartbeat always lands before the endpoint self-quarantines on expiry.
RENEWAL_FRACTION = 0.25


class ServiceError(RuntimeError):
    """Domain failure carrying the HTTP status the router should return."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# -- Profile compilation -------------------------------------------------------


def effective_allowed_cidrs(
    profile: SecureConnectProfile, state: str
) -> List[str]:
    """Destinations the endpoint may route, given the session's access state."""
    if state == SessionState.RESTRICTED.value:
        return list(profile.safe_cidrs or [])
    if profile.access_mode == AccessMode.FULL_TUNNEL.value:
        return ["0.0.0.0/0"]
    return list(profile.allowed_cidrs or [])


def host_cidr(address: str) -> str:
    """Single-host CIDR for a tunnel address (`/32` v4, `/128` v6)."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"{address}/32"
    return f"{address}/{parsed.max_prefixlen}"


def compile_profile(
    session: SecureConnectSession,
    profile: SecureConnectProfile,
    gateway: SecureConnectGateway,
) -> TunnelProfile:
    """Turn stored policy into the endpoint tunnel config for one session."""
    allowed = effective_allowed_cidrs(profile, session.state)
    if not allowed:
        raise ServiceError(
            "PROFILE_HAS_NO_ROUTES",
            f"Profile '{profile.name}' resolves to no allowed CIDRs in state "
            f"'{session.state}'",
            status_code=409,
        )
    expires_at = as_utc(session.expires_at)
    return TunnelProfile(
        interface_address=host_cidr(session.assigned_address),
        gateway_public_key=gateway.public_key,
        gateway_endpoint=gateway.public_endpoint,
        allowed_cidrs=allowed,
        bypass_cidrs=list(profile.bypass_cidrs or []),
        dns_servers=list(profile.dns_servers or gateway.dns_servers or []),
        profile_version=session.profile_version,
        expires_at_unix=int(expires_at.timestamp()) if expires_at else 0,
        persistent_keepalive_secs=profile.persistent_keepalive_secs,
        mtu=profile.mtu,
    )


def load_session_context(
    db: Session, session: SecureConnectSession
) -> Tuple[SecureConnectProfile, SecureConnectGateway]:
    profile = db.get(SecureConnectProfile, session.profile_id)
    gateway = db.get(SecureConnectGateway, session.gateway_id)
    if profile is None or gateway is None:
        raise ServiceError(
            "SESSION_CONTEXT_MISSING",
            "The session's profile or gateway no longer exists",
            status_code=409,
        )
    return profile, gateway


def resolve_profile(
    db: Session, device: SecureConnectDevice
) -> SecureConnectProfile:
    """Profile assigned to the device, else the tenant default."""
    if device.profile_id:
        profile = db.get(SecureConnectProfile, device.profile_id)
        if profile is not None and profile.tenant_id == device.tenant_id:
            return profile
    default = db.scalars(
        select(SecureConnectProfile).where(
            SecureConnectProfile.tenant_id == device.tenant_id,
            SecureConnectProfile.is_default.is_(True),
        )
    ).first()
    if default is None:
        raise ServiceError(
            "NO_PROFILE_ASSIGNED",
            "No Secure Connect profile is assigned to this device and the "
            "tenant has no default profile",
            status_code=409,
        )
    return default


# -- Enrollment ----------------------------------------------------------------


def enroll_device(
    db: Session,
    req: EnrollmentRequest,
    *,
    jwt_secret: str,
    cert_fingerprint: Optional[str],
    allow_unbound: bool,
    jwt_issuer: str = "",
    jwt_audience: str = "",
) -> SecureConnectDevice:
    """Redeem a one-time token and bind the endpoint identity to a device."""
    if not cert_fingerprint and not allow_unbound:
        raise ServiceError(
            "DEVICE_CERT_REQUIRED",
            "Enrollment requires an mTLS client certificate",
            status_code=401,
        )

    claims = key_manager.decode_enrollment_token(
        req.enrollment_token,
        secret=jwt_secret,
        issuer=jwt_issuer,
        audience=jwt_audience,
    )
    if claims.get("tenant_id") != req.tenant_id:
        raise ServiceError(
            "ENROLLMENT_TENANT_MISMATCH",
            "Enrollment token was not issued for the requested tenant",
            status_code=403,
        )
    public_key = key_manager.validate_wireguard_key(
        "wireguard_public_key", req.wireguard_public_key
    )

    device = db.scalars(
        select(SecureConnectDevice).where(
            SecureConnectDevice.tenant_id == req.tenant_id,
            SecureConnectDevice.device_fingerprint == req.device_fingerprint,
        )
    ).first()

    if device is not None:
        if device.state == DeviceState.REVOKED.value:
            raise ServiceError(
                "DEVICE_REVOKED",
                "This device was revoked and must be re-created by an operator",
                status_code=403,
            )
        # The first certificate seen binds permanently; a different one means a
        # different endpoint presenting a known machine fingerprint.
        if (
            device.cert_fingerprint
            and cert_fingerprint
            and device.cert_fingerprint != cert_fingerprint
        ):
            raise ServiceError(
                "DEVICE_BINDING_MISMATCH",
                "Presented client certificate does not match the device binding",
                status_code=403,
            )
        device.host_id = req.host_id
        device.user_id = req.user_id or claims.get("sub") or device.user_id
        device.wireguard_public_key = public_key
        device.posture = dict(req.posture or {})
        device.state = DeviceState.ACTIVE.value
        if cert_fingerprint and not device.cert_fingerprint:
            device.cert_fingerprint = cert_fingerprint
    else:
        device = SecureConnectDevice(
            tenant_id=req.tenant_id,
            host_id=req.host_id,
            user_id=req.user_id or claims.get("sub") or "",
            device_fingerprint=req.device_fingerprint,
            cert_fingerprint=cert_fingerprint,
            wireguard_public_key=public_key,
            state=DeviceState.ACTIVE.value,
            posture=dict(req.posture or {}),
            enrolled_by=claims.get("sub") or "",
        )
        db.add(device)
    db.flush()

    profile_id = claims.get("profile_id")
    if profile_id:
        profile = db.get(SecureConnectProfile, profile_id)
        if profile is not None and profile.tenant_id == req.tenant_id:
            device.profile_id = profile.id

    # Token consumption and device creation commit together, so a failed
    # enrollment never burns a token and a used token never lacks a device.
    key_manager.redeem_enrollment(
        db, jti=claims["jti"], tenant_id=req.tenant_id, device_id=device.id
    )
    return device


# -- Session lifecycle ---------------------------------------------------------


def _close_live_sessions(
    db: Session, device_id: str, reason: str
) -> List[SecureConnectSession]:
    """Terminate a device's live sessions; a device holds one tunnel at a time."""
    live = list(
        db.scalars(
            select(SecureConnectSession).where(
                SecureConnectSession.device_id == device_id,
                SecureConnectSession.state.in_(LIVE_SESSION_STATES),
            )
        ).all()
    )
    for session in live:
        session.state = SessionState.TERMINATED.value
        session.terminated_at = utc_now()
        session.close_reason = reason[:256]
        session.pending_action = ControlAction.NONE.value
        session.pending_state = None
        key_manager.revoke_key_material(db, session.id)
    if live:
        db.flush()
    return live


def start_session(
    db: Session,
    req: SessionStartRequest,
    device: SecureConnectDevice,
    *,
    reachability_grace_secs: int = 120,
) -> SessionStartResponse:
    """Assign a gateway, allocate an address, and issue the tunnel profile."""
    if device.state != DeviceState.ACTIVE.value:
        raise ServiceError(
            "DEVICE_NOT_ACTIVE",
            f"Device state is '{device.state}'; no session can be started",
            status_code=403,
        )
    public_key = key_manager.validate_wireguard_key(
        "wireguard_public_key", req.wireguard_public_key
    )
    profile = resolve_profile(db, device)

    try:
        gateway = allocator.select_gateway(
            db,
            device.tenant_id,
            profile.region,
            reachability_grace_secs=reachability_grace_secs,
        )
    except allocator.AllocationError as exc:
        raise ServiceError(exc.code, exc.message, status_code=503) from exc

    # Address allocation commits on its own, so it must happen before any other
    # pending writes in this request.
    try:
        address = allocator.allocate_address(db, gateway, device.tenant_id, device.id)
    except allocator.AllocationError as exc:
        raise ServiceError(exc.code, exc.message, status_code=503) from exc

    _close_live_sessions(db, device.id, "superseded by a new session")

    now = utc_now()
    session = SecureConnectSession(
        tenant_id=device.tenant_id,
        device_id=device.id,
        gateway_id=gateway.id,
        profile_id=profile.id,
        host_id=req.host_id or device.host_id,
        assigned_address=address,
        wireguard_public_key=public_key,
        state=SessionState.HEALTHY.value,
        profile_version=1,
        command_nonce=0,
        started_at=now,
        expires_at=now + timedelta(seconds=profile.session_ttl_secs),
        last_rekey_at=now,
        posture=dict(req.posture or {}),
    )
    db.add(session)
    db.flush()

    key_manager.issue_key_material(db, session, public_key, session.expires_at)
    device.host_id = session.host_id
    device.wireguard_public_key = public_key
    device.posture = dict(req.posture or {})
    device.last_seen_at = now
    db.flush()

    return SessionStartResponse(
        session_id=session.id,
        state=SessionState(session.state),
        profile=compile_profile(session, profile, gateway),
        command_nonce=session.command_nonce,
    )


def _renew_if_due(
    session: SecureConnectSession, profile: SecureConnectProfile
) -> bool:
    """Extend a session that is close to expiry; returns True when renewed."""
    expires_at = as_utc(session.expires_at)
    if expires_at is None:
        return False
    ttl = max(profile.session_ttl_secs, 1)
    remaining = (expires_at - utc_now()).total_seconds()
    if remaining > ttl * RENEWAL_FRACTION:
        return False
    session.expires_at = utc_now() + timedelta(seconds=ttl)
    session.profile_version += 1
    return True


def handle_heartbeat(
    db: Session,
    req: HeartbeatRequest,
    session: SecureConnectSession,
    device: SecureConnectDevice,
    *,
    elevated_cooldown_secs: int,
) -> HeartbeatResponse:
    """Record endpoint liveness and return at most one command to apply."""
    now = utc_now()
    profile, gateway = load_session_context(db, session)

    session.acked_command_nonce = max(
        session.acked_command_nonce, req.last_command_nonce
    )
    session.last_heartbeat_at = now
    session.last_handshake_unix = req.last_handshake_unix
    session.bytes_tx = req.bytes_tx
    session.bytes_rx = req.bytes_rx
    if req.posture:
        session.posture = dict(req.posture)
        device.posture = dict(req.posture)
    device.last_seen_at = now

    # A device quarantined or revoked out-of-band must not keep a live session.
    if device.state != DeviceState.ACTIVE.value and session.is_live:
        target = (
            SessionState.TERMINATED
            if device.state == DeviceState.REVOKED.value
            else SessionState.QUARANTINED
        )
        risk_adapter.apply_transition(
            db, session, target, f"device state is '{device.state}'"
        )

    # A session that already lost access re-asserts the teardown on every
    # heartbeat until the endpoint stops calling.
    if not session.is_live:
        target = SessionState(session.state)
        response = _deliver_command(
            db, session, risk_adapter.command_for_state(target), target, profile=None
        )
        db.flush()
        return response

    if session.pending_action != ControlAction.NONE.value or session.pending_state:
        action = ControlAction(session.pending_action)
        desired = (
            SessionState(session.pending_state) if session.pending_state else None
        )
        tunnel = (
            compile_profile(session, profile, gateway)
            if action in (ControlAction.RESTRICT, ControlAction.REFRESH_PROFILE)
            else None
        )
        response = _deliver_command(db, session, action, desired, profile=tunnel)
        db.flush()
        return response

    cooldown = risk_adapter.evaluate_cooldown(session, elevated_cooldown_secs)
    if cooldown is not None:
        target, reason = cooldown
        risk_adapter.apply_transition(
            db, session, target, reason, cooldown_secs=elevated_cooldown_secs
        )
        response = _deliver_command(
            db, session, ControlAction.NONE, target, profile=None
        )
        db.flush()
        return response

    renewed = _renew_if_due(session, profile)
    if renewed or req.profile_version != session.profile_version:
        response = _deliver_command(
            db,
            session,
            ControlAction.REFRESH_PROFILE,
            None,
            profile=compile_profile(session, profile, gateway),
        )
        db.flush()
        return response

    last_rekey = as_utc(session.last_rekey_at) or as_utc(session.started_at) or now
    if (now - last_rekey).total_seconds() >= profile.rekey_interval_secs:
        # Stamp the clock on issue so a dropped rekey does not re-fire on every
        # heartbeat; the endpoint's rekey call stamps it again on success.
        session.last_rekey_at = now
        response = _deliver_command(
            db, session, ControlAction.REKEY, None, profile=None
        )
        db.flush()
        return response

    db.flush()
    return HeartbeatResponse(action=ControlAction.NONE, command_nonce=0)


def _deliver_command(
    db: Session,
    session: SecureConnectSession,
    action: ControlAction,
    desired_state: Optional[SessionState],
    profile: Optional[TunnelProfile],
) -> HeartbeatResponse:
    """Emit one command with a fresh nonce and clear the pending slot."""
    session.command_nonce += 1
    pending_since = as_utc(session.pending_since)
    if pending_since is not None:
        session.last_command_latency_ms = int(
            (utc_now() - pending_since).total_seconds() * 1000
        )
    session.pending_action = ControlAction.NONE.value
    session.pending_state = None
    session.pending_since = None
    return HeartbeatResponse(
        desired_state=desired_state,
        action=action,
        profile=profile,
        command_nonce=session.command_nonce,
    )


def handle_rekey(
    db: Session,
    req: RekeyRequest,
    session: SecureConnectSession,
) -> RekeyResponse:
    """Rotate the session peer key without dropping the tunnel."""
    if not session.is_live:
        raise ServiceError(
            "SESSION_NOT_LIVE",
            f"Session state is '{session.state}'; rekey is not allowed",
            status_code=409,
        )
    public_key = key_manager.validate_wireguard_key(
        "wireguard_public_key", req.wireguard_public_key
    )
    profile, gateway = load_session_context(db, session)

    session.wireguard_public_key = public_key
    session.profile_version += 1
    session.last_rekey_at = utc_now()
    # The endpoint only flips to the new private key after this response, so the
    # new peer must be registered before the acknowledgement goes out.
    key_manager.issue_key_material(db, session, public_key, session.expires_at)
    session.command_nonce = max(session.command_nonce, req.last_command_nonce) + 1
    db.flush()

    return RekeyResponse(
        profile=compile_profile(session, profile, gateway),
        command_nonce=session.command_nonce,
    )


# -- Gateway failover ----------------------------------------------------------


def migrate_session(
    db: Session,
    session: SecureConnectSession,
    gateway: SecureConnectGateway,
    reason: str,
) -> SecureConnectSession:
    """Move a live session onto a different gateway without dropping it.

    The endpoint learns about the move through an ordinary profile refresh: it
    gets a new gateway endpoint, key, and tunnel address, removes the old peer,
    and applies the new one. The session id and device binding are unchanged, so
    nothing downstream has to treat a migration as a reconnect.
    """
    if not session.is_live:
        raise ServiceError(
            "SESSION_NOT_LIVE",
            f"Session state is '{session.state}'; it cannot be migrated",
            status_code=409,
        )
    if session.gateway_id == gateway.id:
        return session

    previous_gateway_id = session.gateway_id
    try:
        address = allocator.allocate_address(
            db, gateway, session.tenant_id, session.device_id
        )
    except allocator.AllocationError as exc:
        raise ServiceError(exc.code, exc.message, status_code=503) from exc

    session.gateway_id = gateway.id
    session.assigned_address = address
    session.profile_version += 1
    # Revoke on the old gateway and issue on the new one in the same step, so a
    # migrated device never holds valid key material on two gateways at once.
    key_manager.issue_key_material(
        db, session, session.wireguard_public_key, session.expires_at
    )
    risk_adapter.queue_command(
        session, ControlAction.REFRESH_PROFILE, None, reason
    )
    # The lease on the old gateway is released so its pool does not leak.
    allocator.release_address(db, previous_gateway_id, session.device_id)
    db.flush()
    return session


def failover_sessions(
    db: Session,
    *,
    reachability_grace_secs: int,
) -> Tuple[int, int]:
    """Move live sessions off gateways that can no longer serve them.

    Returns `(migrated, stranded)`. Stranded sessions are left running: if no
    healthy gateway exists, tearing tunnels down would turn a partial gateway
    outage into a total one.
    """
    gateways = {
        gateway.id: gateway
        for gateway in db.scalars(select(SecureConnectGateway)).all()
    }
    evacuating = {
        gateway_id
        for gateway_id, gateway in gateways.items()
        if gateway.status != GatewayStatus.ONLINE.value
        or not gateway.is_reachable(reachability_grace_secs)
    }
    if not evacuating:
        return 0, 0

    sessions = db.scalars(
        select(SecureConnectSession).where(
            SecureConnectSession.state.in_(LIVE_SESSION_STATES),
            SecureConnectSession.gateway_id.in_(evacuating),
        )
    ).all()

    migrated = 0
    stranded = 0
    for session in sessions:
        source = gateways.get(session.gateway_id)
        reason = (
            f"gateway '{source.name}' is {source.status}"
            if source and source.status != GatewayStatus.ONLINE.value
            else "gateway stopped reporting"
        )
        profile = db.get(SecureConnectProfile, session.profile_id)
        try:
            target = allocator.select_gateway(
                db,
                session.tenant_id,
                profile.region if profile else "",
                reachability_grace_secs=reachability_grace_secs,
                exclude_gateway_ids=evacuating,
            )
            migrate_session(db, session, target, reason)
        except (allocator.AllocationError, ServiceError):
            stranded += 1
            continue
        migrated += 1

    if migrated:
        db.commit()
    return migrated, stranded


# -- Operator actions ----------------------------------------------------------


def terminate_session(
    db: Session, session: SecureConnectSession, reason: str
) -> SecureConnectSession:
    risk_adapter.apply_transition(
        db, session, SessionState.TERMINATED, reason or "terminated by operator"
    )
    key_manager.revoke_key_material(db, session.id)
    db.flush()
    return session


def quarantine_device(
    db: Session, device: SecureConnectDevice, reason: str
) -> List[SecureConnectSession]:
    """Quarantine a device and every live session it holds."""
    device.state = DeviceState.QUARANTINED.value
    sessions = list(
        db.scalars(
            select(SecureConnectSession).where(
                SecureConnectSession.device_id == device.id,
                SecureConnectSession.state.in_(LIVE_SESSION_STATES),
            )
        ).all()
    )
    for session in sessions:
        risk_adapter.apply_transition(
            db,
            session,
            SessionState.QUARANTINED,
            reason or "device quarantined by operator",
        )
        key_manager.revoke_key_material(db, session.id)
    db.flush()
    return sessions


def plan_risk_target(
    severity: str, profile: Optional[SecureConnectProfile]
) -> Optional[SessionState]:
    """Resolve an alert severity to a target state for a session's profile.

    A restrict action with no safe CIDRs would leave the endpoint with an empty
    route set, which the agent rejects, so it escalates to quarantine instead.
    """
    risk_actions = dict(profile.risk_actions or {}) if profile else {}
    target = risk_adapter.target_state_for_severity(severity, risk_actions)
    if target == SessionState.RESTRICTED and not (profile and profile.safe_cidrs):
        return SessionState.QUARANTINED
    return target


def apply_risk_signal(
    db: Session,
    sessions: List[SecureConnectSession],
    severity: str,
    reason: str,
) -> Tuple[Optional[SessionState], List[SecureConnectSession]]:
    """Drive matched sessions to the state the severity calls for."""
    transitioned: List[SecureConnectSession] = []
    resolved_target: Optional[SessionState] = None
    for session in sessions:
        profile = db.get(SecureConnectProfile, session.profile_id)
        target = plan_risk_target(severity, profile)
        if target is None:
            continue
        resolved_target = target
        if risk_adapter.is_relaxation(session.state, target):
            # Detections never relax access; that needs an operator.
            continue
        if risk_adapter.apply_transition(db, session, target, reason):
            if target in (SessionState.QUARANTINED, SessionState.TERMINATED):
                key_manager.revoke_key_material(db, session.id)
            transitioned.append(session)
    db.flush()
    return resolved_target, transitioned
