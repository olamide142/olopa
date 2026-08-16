"""Secure Connect orchestrator API.

Route groups:
- agent-facing:    /enroll, /sessions/start, /sessions/{id}/heartbeat, /rekey
- operator-facing: enrollment tokens, gateways, profiles, devices, sessions
- risk-facing:     /risk-signals, fed by the detection/alert stream

`/enroll` is the only unauthenticated route: the one-time enrollment JWT plus
the mTLS client certificate *are* the credential, because a device has no API
identity until it is enrolled.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import log_audit_event
from ..auth import RequestContext
from ..db import get_db
from ..deps import settings
from ..models.secure_connect import (
    LIVE_SESSION_STATES,
    ControlAction,
    GatewayStatus,
    SecureConnectDevice,
    SecureConnectEnrollment,
    SecureConnectGateway,
    SecureConnectKeyMaterial,
    SecureConnectProfile,
    SecureConnectSession,
    SessionState,
    as_utc,
    utc_now,
)
from ..rbac import require_admin, require_operator, require_viewer
from . import allocator, key_manager, risk_adapter, service
from .schemas import (
    AssignProfileRequest,
    AssignProfileResponse,
    CreateEnrollmentTokenRequest,
    CreateEnrollmentTokenResponse,
    CreateGatewayRequest,
    CreateProfileRequest,
    DeviceResponse,
    EnrollmentRequest,
    EnrollmentResponse,
    GatewayFailoverResponse,
    GatewayHeartbeatRequest,
    GatewayHeartbeatResponse,
    GatewayPeer,
    GatewayResponse,
    GatewayUtilization,
    HeartbeatRequest,
    HeartbeatResponse,
    ProfileResponse,
    RekeyRequest,
    RekeyResponse,
    RiskSignalRequest,
    RiskSignalResponse,
    SecureConnectMetrics,
    SessionActionRequest,
    SessionResponse,
    SessionStartRequest,
    SessionStartResponse,
    SetSessionStateRequest,
    UpdateGatewayStatusRequest,
)

logger = logging.getLogger("control_plane.secure_connect")

router = APIRouter(prefix="/api/v1/secure-connect", tags=["secure-connect"])


# -- Helpers -------------------------------------------------------------------


def _fail(code: str, message: str, status_code: int = 400) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _service_error(exc: service.ServiceError) -> HTTPException:
    return _fail(exc.code, exc.message, exc.status_code)


def _client_cert_fingerprint(request: Request) -> Optional[str]:
    """Read the mTLS fingerprint the TLS terminator forwarded, if any."""
    value = request.headers.get(settings.sc_client_cert_header, "").strip()
    return value or None


def _require_jwt_secret() -> str:
    if not settings.jwt_secret:
        raise _fail(
            "AUTH_NOT_CONFIGURED",
            "JWT_SECRET is not configured",
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return settings.jwt_secret


def _require_tenant(ctx: RequestContext, tenant_id: str) -> None:
    if tenant_id != ctx.tenant_id:
        raise _fail(
            "TENANT_MISMATCH",
            "Authenticated identity cannot act on the requested tenant",
            status.HTTP_403_FORBIDDEN,
        )


def _load_device(db: Session, tenant_id: str, device_id: str) -> SecureConnectDevice:
    device = db.scalars(
        select(SecureConnectDevice).where(
            SecureConnectDevice.id == device_id,
            SecureConnectDevice.tenant_id == tenant_id,
        )
    ).first()
    if device is None:
        raise _fail("DEVICE_NOT_FOUND", f"Device '{device_id}' not found", 404)
    return device


def _load_gateway(db: Session, tenant_id: str, gateway_id: str) -> SecureConnectGateway:
    gateway = db.get(SecureConnectGateway, gateway_id)
    if gateway is None or (gateway.tenant_id and gateway.tenant_id != tenant_id):
        raise _fail("GATEWAY_NOT_FOUND", f"Gateway '{gateway_id}' not found", 404)
    return gateway


def _load_session(db: Session, tenant_id: str, session_id: str) -> SecureConnectSession:
    session = db.scalars(
        select(SecureConnectSession).where(
            SecureConnectSession.id == session_id,
            SecureConnectSession.tenant_id == tenant_id,
        )
    ).first()
    if session is None:
        raise _fail("SESSION_NOT_FOUND", f"Session '{session_id}' not found", 404)
    return session


def _check_device_binding(device: SecureConnectDevice, request: Request) -> None:
    """Fail closed when the presented certificate is not the bound one."""
    presented = _client_cert_fingerprint(request)
    if device.cert_fingerprint:
        if presented != device.cert_fingerprint:
            raise _fail(
                "DEVICE_BINDING_MISMATCH",
                "Presented client certificate does not match the device binding",
                status.HTTP_403_FORBIDDEN,
            )
    elif not settings.sc_allow_unbound_enrollment:
        raise _fail(
            "DEVICE_CERT_REQUIRED",
            "Device has no certificate binding; re-enrollment with mTLS is required",
            status.HTTP_403_FORBIDDEN,
        )


def _session_response(session: SecureConnectSession) -> SessionResponse:
    payload: Dict[str, Any] = session.to_dict()
    last_beat = as_utc(session.last_heartbeat_at) or as_utc(session.started_at)
    stale = bool(
        session.state in LIVE_SESSION_STATES
        and last_beat is not None
        and (utc_now() - last_beat).total_seconds() > settings.sc_heartbeat_grace_secs
    )
    payload["stale"] = stale
    return SessionResponse(**payload)


def _validate_cidrs(label: str, values: List[str]) -> List[str]:
    normalized: List[str] = []
    for value in values:
        try:
            normalized.append(str(ipaddress.ip_network(value.strip(), strict=False)))
        except ValueError as exc:
            raise _fail("INVALID_CIDR", f"{label} contains an invalid CIDR: {exc}") from exc
    return normalized


def _validate_addresses(label: str, values: List[str]) -> List[str]:
    for value in values:
        try:
            ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise _fail("INVALID_IP", f"{label} contains an invalid address: {exc}") from exc
    return [value.strip() for value in values]


# -- Agent-facing lifecycle ----------------------------------------------------


@router.post("/enroll", response_model=EnrollmentResponse)
async def enroll(
    req: EnrollmentRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> EnrollmentResponse:
    """Redeem a one-time enrollment token and register the device."""
    try:
        device = service.enroll_device(
            db,
            req,
            jwt_secret=_require_jwt_secret(),
            cert_fingerprint=_client_cert_fingerprint(request),
            allow_unbound=settings.sc_allow_unbound_enrollment,
            jwt_issuer=settings.jwt_issuer,
            jwt_audience=settings.jwt_audience,
        )
    except key_manager.KeyManagerError as exc:
        db.rollback()
        raise _fail(exc.code, exc.message, status.HTTP_401_UNAUTHORIZED) from exc
    except service.ServiceError as exc:
        db.rollback()
        raise _service_error(exc) from exc

    device_id = device.id
    profile_id = device.profile_id
    db.commit()
    logger.info(
        "secure-connect enrolled device=%s tenant=%s host=%s",
        device_id,
        req.tenant_id,
        req.host_id,
    )
    return EnrollmentResponse(device_id=device_id, profile_id=profile_id)


@router.post("/sessions/start", response_model=SessionStartResponse)
async def start_session(
    req: SessionStartRequest,
    request: Request,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> SessionStartResponse:
    """Issue tunnel credentials and a gateway assignment for an enrolled device."""
    _require_tenant(ctx, req.tenant_id)
    device = _load_device(db, ctx.tenant_id, req.device_id)
    _check_device_binding(device, request)

    try:
        response = service.start_session(
            db,
            req,
            device,
            reachability_grace_secs=settings.sc_gateway_grace_secs,
        )
    except key_manager.KeyManagerError as exc:
        db.rollback()
        raise _fail(exc.code, exc.message) from exc
    except service.ServiceError as exc:
        db.rollback()
        raise _service_error(exc) from exc

    db.commit()
    log_audit_event(
        db,
        ctx,
        action="secure_connect.session.start",
        target=f"sc_session:{response.session_id}",
        details={"device_id": device.id, "host_id": req.host_id},
    )
    return response


@router.post("/sessions/{session_id}/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    session_id: str,
    req: HeartbeatRequest,
    request: Request,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    """Accept endpoint liveness/posture and return at most one command."""
    _require_tenant(ctx, req.tenant_id)
    if req.session_id != session_id:
        raise _fail("SESSION_ID_MISMATCH", "Body session_id does not match the URL")

    session = _load_session(db, ctx.tenant_id, session_id)
    if session.device_id != req.device_id:
        raise _fail(
            "SESSION_DEVICE_MISMATCH",
            "Session does not belong to the reporting device",
            status.HTTP_403_FORBIDDEN,
        )
    device = _load_device(db, ctx.tenant_id, session.device_id)
    _check_device_binding(device, request)

    try:
        response = service.handle_heartbeat(
            db,
            req,
            session,
            device,
            elevated_cooldown_secs=settings.sc_elevated_cooldown_secs,
        )
    except service.ServiceError as exc:
        db.rollback()
        raise _service_error(exc) from exc

    db.commit()
    if response.action != ControlAction.NONE or response.desired_state is not None:
        logger.info(
            "secure-connect command session=%s action=%s state=%s nonce=%s",
            session_id,
            response.action.value,
            response.desired_state.value if response.desired_state else None,
            response.command_nonce,
        )
    return response


@router.post("/sessions/{session_id}/rekey", response_model=RekeyResponse)
async def rekey(
    session_id: str,
    req: RekeyRequest,
    request: Request,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> RekeyResponse:
    """Register a new endpoint public key and return the refreshed profile."""
    _require_tenant(ctx, req.tenant_id)
    session = _load_session(db, ctx.tenant_id, session_id)
    if session.device_id != req.device_id:
        raise _fail(
            "SESSION_DEVICE_MISMATCH",
            "Session does not belong to the reporting device",
            status.HTTP_403_FORBIDDEN,
        )
    device = _load_device(db, ctx.tenant_id, session.device_id)
    _check_device_binding(device, request)

    try:
        response = service.handle_rekey(db, req, session)
    except key_manager.KeyManagerError as exc:
        db.rollback()
        raise _fail(exc.code, exc.message) from exc
    except service.ServiceError as exc:
        db.rollback()
        raise _service_error(exc) from exc

    db.commit()
    log_audit_event(
        db,
        ctx,
        action="secure_connect.session.rekey",
        target=f"sc_session:{session_id}",
        details={"device_id": req.device_id, "profile_version": response.profile.profile_version},
    )
    return response


# -- Enrollment tokens ---------------------------------------------------------


@router.post(
    "/enrollment-tokens",
    response_model=CreateEnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_enrollment_token(
    req: CreateEnrollmentTokenRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> CreateEnrollmentTokenResponse:
    """Mint a single-use, short-lived enrollment token for one device."""
    if req.profile_id:
        profile = db.get(SecureConnectProfile, req.profile_id)
        if profile is None or profile.tenant_id != ctx.tenant_id:
            raise _fail("PROFILE_NOT_FOUND", f"Profile '{req.profile_id}' not found", 404)

    token, record = key_manager.issue_enrollment_token(
        db,
        secret=_require_jwt_secret(),
        tenant_id=ctx.tenant_id,
        user_id=req.user_id,
        issued_by=ctx.user_id,
        device_hint=req.device_hint,
        profile_id=req.profile_id,
        ttl_minutes=req.ttl_minutes,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )
    payload = record.to_dict()
    db.commit()

    log_audit_event(
        db,
        ctx,
        action="secure_connect.enrollment_token.create",
        target=f"sc_enrollment:{payload['id']}",
        details={"user_id": req.user_id, "ttl_minutes": req.ttl_minutes},
    )
    return CreateEnrollmentTokenResponse(
        token=token,
        jti=payload["jti"],
        expires_at=payload["expires_at"],
        profile_id=payload["profile_id"],
    )


# -- Gateways ------------------------------------------------------------------


@router.post("/gateways", response_model=GatewayResponse, status_code=status.HTTP_201_CREATED)
async def create_gateway(
    req: CreateGatewayRequest,
    ctx: RequestContext = Depends(require_admin),
    db: Session = Depends(get_db),
) -> GatewayResponse:
    """Register a WireGuard gateway the orchestrator can assign sessions to."""
    try:
        public_key = key_manager.validate_wireguard_key("public_key", req.public_key)
    except key_manager.KeyManagerError as exc:
        raise _fail(exc.code, exc.message) from exc
    client_cidr = _validate_cidrs("client_cidr", [req.client_cidr])[0]
    dns_servers = _validate_addresses("dns_servers", req.dns_servers)
    if ":" not in req.public_endpoint:
        raise _fail("INVALID_ENDPOINT", "public_endpoint must include a port")

    existing = db.scalars(
        select(SecureConnectGateway).where(SecureConnectGateway.name == req.name)
    ).first()
    if existing is not None:
        raise _fail("GATEWAY_EXISTS", f"Gateway '{req.name}' already exists", 409)

    gateway = SecureConnectGateway(
        name=req.name,
        region=req.region,
        tenant_id=ctx.tenant_id if req.dedicated else None,
        public_key=public_key,
        public_endpoint=req.public_endpoint,
        client_cidr=client_cidr,
        dns_servers=dns_servers,
        capacity=req.capacity,
        status=GatewayStatus.ONLINE.value,
    )
    db.add(gateway)
    db.commit()
    payload = gateway.to_dict(settings.sc_gateway_grace_secs)

    log_audit_event(
        db,
        ctx,
        action="secure_connect.gateway.create",
        target=f"sc_gateway:{payload['id']}",
        details={"region": req.region, "capacity": req.capacity},
    )
    return GatewayResponse(**payload)


@router.get("/gateways", response_model=List[GatewayResponse])
async def list_gateways(
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> List[GatewayResponse]:
    """List gateways usable by the caller's tenant."""
    gateways = db.scalars(
        select(SecureConnectGateway)
        .where(
            (SecureConnectGateway.tenant_id.is_(None))
            | (SecureConnectGateway.tenant_id == ctx.tenant_id)
        )
        .order_by(SecureConnectGateway.name)
    ).all()
    return [
        GatewayResponse(**gateway.to_dict(settings.sc_gateway_grace_secs))
        for gateway in gateways
    ]


@router.post("/gateways/{gateway_id}/heartbeat", response_model=GatewayHeartbeatResponse)
async def gateway_heartbeat(
    gateway_id: str,
    req: GatewayHeartbeatRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> GatewayHeartbeatResponse:
    """Record that a gateway's reconciler is alive and converged.

    A gateway that stops reporting is excluded from new session assignment and
    its live sessions are migrated away.
    """
    gateway = _load_gateway(db, ctx.tenant_id, gateway_id)
    gateway.last_seen_at = utc_now()
    gateway.observed_peers = req.observed_peers
    if req.reconciler_version:
        gateway.reconciler_version = req.reconciler_version

    expected = db.scalar(
        select(func.count(SecureConnectSession.id)).where(
            SecureConnectSession.gateway_id == gateway_id,
            SecureConnectSession.state.in_(LIVE_SESSION_STATES),
        )
    )
    db.commit()

    return GatewayHeartbeatResponse(
        gateway_id=gateway_id,
        status=gateway.status,
        expected_peers=int(expected or 0),
        acknowledged_at=gateway.to_dict()["last_seen_at"],
    )


@router.post("/gateways/{gateway_id}/status", response_model=GatewayResponse)
async def set_gateway_status(
    gateway_id: str,
    req: UpdateGatewayStatusRequest,
    ctx: RequestContext = Depends(require_admin),
    db: Session = Depends(get_db),
) -> GatewayResponse:
    """Drain or restore a gateway.

    Draining is the safe maintenance path: it stops new assignment immediately
    and leaves running tunnels alone. Use `/failover` to move them.
    """
    gateway = _load_gateway(db, ctx.tenant_id, gateway_id)
    previous = gateway.status
    gateway.status = req.status.value
    db.commit()
    payload = gateway.to_dict(settings.sc_gateway_grace_secs)

    log_audit_event(
        db,
        ctx,
        action="secure_connect.gateway.status",
        target=f"sc_gateway:{gateway_id}",
        details={"from": previous, "to": req.status.value, "reason": req.reason},
    )
    return GatewayResponse(**payload)


@router.post("/gateways/{gateway_id}/failover", response_model=GatewayFailoverResponse)
async def failover_gateway(
    gateway_id: str,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> GatewayFailoverResponse:
    """Move this gateway's live sessions onto healthy gateways now.

    Sessions with nowhere to go stay where they are: turning a partial gateway
    outage into a fleet-wide outage is never the safer choice.
    """
    gateway = _load_gateway(db, ctx.tenant_id, gateway_id)
    sessions = db.scalars(
        select(SecureConnectSession).where(
            SecureConnectSession.gateway_id == gateway.id,
            SecureConnectSession.tenant_id == ctx.tenant_id,
            SecureConnectSession.state.in_(LIVE_SESSION_STATES),
        )
    ).all()

    migrated: List[str] = []
    stranded = 0
    for session in sessions:
        profile = db.get(SecureConnectProfile, session.profile_id)
        try:
            target = allocator.select_gateway(
                db,
                session.tenant_id,
                profile.region if profile else "",
                reachability_grace_secs=settings.sc_gateway_grace_secs,
                exclude_gateway_ids={gateway.id},
            )
            service.migrate_session(
                db, session, target, f"operator failover from '{gateway.name}'"
            )
        except allocator.AllocationError:
            stranded += 1
            continue
        except service.ServiceError:
            stranded += 1
            continue
        migrated.append(session.id)
    db.commit()

    log_audit_event(
        db,
        ctx,
        action="secure_connect.gateway.failover",
        target=f"sc_gateway:{gateway_id}",
        details={"migrated": len(migrated), "stranded": stranded, "sessions": migrated},
    )
    return GatewayFailoverResponse(
        migrated_sessions=len(migrated),
        stranded_sessions=stranded,
        sessions=migrated,
    )


@router.get("/gateways/{gateway_id}/peers", response_model=List[GatewayPeer])
async def list_gateway_peers(
    gateway_id: str,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> List[GatewayPeer]:
    """Desired peer state for a gateway to reconcile.

    The gateway plane is external (plan option A), so it pulls this instead of
    the control plane pushing WireGuard config to it.
    """
    _load_gateway(db, ctx.tenant_id, gateway_id)

    rows = db.execute(
        select(SecureConnectSession, SecureConnectKeyMaterial)
        .join(
            SecureConnectKeyMaterial,
            SecureConnectKeyMaterial.session_id == SecureConnectSession.id,
        )
        .where(
            SecureConnectSession.gateway_id == gateway_id,
            SecureConnectSession.tenant_id == ctx.tenant_id,
            SecureConnectSession.state.in_(LIVE_SESSION_STATES),
            SecureConnectKeyMaterial.revoked_at.is_(None),
        )
    ).all()

    peers: List[GatewayPeer] = []
    for session, material in rows:
        expires_at = as_utc(session.expires_at)
        peers.append(
            GatewayPeer(
                session_id=session.id,
                device_id=session.device_id,
                public_key=material.public_key,
                allowed_ips=[service.host_cidr(material.assigned_address)],
                expires_at_unix=int(expires_at.timestamp()) if expires_at else 0,
            )
        )
    return peers


# -- Profiles ------------------------------------------------------------------


def _apply_profile_fields(
    profile: SecureConnectProfile, req: CreateProfileRequest
) -> None:
    allowed = _validate_cidrs("allowed_cidrs", req.allowed_cidrs)
    safe = _validate_cidrs("safe_cidrs", req.safe_cidrs)
    bypass = _validate_cidrs("bypass_cidrs", req.bypass_cidrs)
    dns = _validate_addresses("dns_servers", req.dns_servers)
    if not allowed and req.access_mode.value != "full_tunnel":
        raise _fail(
            "PROFILE_HAS_NO_ROUTES",
            "A split-tunnel profile must define at least one allowed CIDR",
        )
    unknown_actions = {
        action
        for action in req.risk_actions.values()
        if action
        not in {
            risk_adapter.RISK_ACTION_OBSERVE,
            risk_adapter.RISK_ACTION_STEP_UP_AUTH,
            risk_adapter.RISK_ACTION_RESTRICT,
            risk_adapter.RISK_ACTION_QUARANTINE,
            risk_adapter.RISK_ACTION_TERMINATE,
        }
    }
    if unknown_actions:
        raise _fail(
            "UNKNOWN_RISK_ACTION",
            f"Unsupported risk actions: {sorted(unknown_actions)}",
        )

    profile.name = req.name
    profile.access_mode = req.access_mode.value
    profile.region = req.region
    profile.allowed_cidrs = allowed
    profile.safe_cidrs = safe
    profile.bypass_cidrs = bypass
    profile.dns_servers = dns
    profile.session_ttl_secs = req.session_ttl_secs
    profile.rekey_interval_secs = req.rekey_interval_secs
    profile.persistent_keepalive_secs = req.persistent_keepalive_secs
    profile.mtu = req.mtu
    profile.risk_actions = dict(req.risk_actions)
    profile.is_default = req.is_default


def _clear_other_defaults(db: Session, tenant_id: str, keep_id: str) -> None:
    others = db.scalars(
        select(SecureConnectProfile).where(
            SecureConnectProfile.tenant_id == tenant_id,
            SecureConnectProfile.is_default.is_(True),
            SecureConnectProfile.id != keep_id,
        )
    ).all()
    for other in others:
        other.is_default = False


def _push_profile_refresh(db: Session, profile_id: str, reason: str) -> int:
    """Queue a profile refresh on every live session using a profile."""
    sessions = db.scalars(
        select(SecureConnectSession).where(
            SecureConnectSession.profile_id == profile_id,
            SecureConnectSession.state.in_(LIVE_SESSION_STATES),
        )
    ).all()
    for session in sessions:
        session.profile_version += 1
        risk_adapter.queue_command(
            session, ControlAction.REFRESH_PROFILE, None, reason
        )
    return len(sessions)


@router.post("/profiles", response_model=ProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_profile(
    req: CreateProfileRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> ProfileResponse:
    """Create an access profile for the caller's tenant."""
    existing = db.scalars(
        select(SecureConnectProfile).where(
            SecureConnectProfile.tenant_id == ctx.tenant_id,
            SecureConnectProfile.name == req.name,
        )
    ).first()
    if existing is not None:
        raise _fail("PROFILE_EXISTS", f"Profile '{req.name}' already exists", 409)

    profile = SecureConnectProfile(tenant_id=ctx.tenant_id, created_by=ctx.user_id)
    _apply_profile_fields(profile, req)
    db.add(profile)
    db.flush()
    if profile.is_default:
        _clear_other_defaults(db, ctx.tenant_id, profile.id)
    db.commit()
    payload = profile.to_dict()

    log_audit_event(
        db,
        ctx,
        action="secure_connect.profile.create",
        target=f"sc_profile:{payload['id']}",
        details={"name": req.name, "access_mode": payload["access_mode"]},
    )
    return ProfileResponse(**payload)


@router.get("/profiles", response_model=List[ProfileResponse])
async def list_profiles(
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> List[ProfileResponse]:
    """List access profiles for the caller's tenant."""
    profiles = db.scalars(
        select(SecureConnectProfile)
        .where(SecureConnectProfile.tenant_id == ctx.tenant_id)
        .order_by(SecureConnectProfile.name)
    ).all()
    return [ProfileResponse(**profile.to_dict()) for profile in profiles]


@router.put("/profiles/{profile_id}", response_model=ProfileResponse)
async def update_profile(
    profile_id: str,
    req: CreateProfileRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> ProfileResponse:
    """Replace a profile and push the new policy to live sessions."""
    profile = db.get(SecureConnectProfile, profile_id)
    if profile is None or profile.tenant_id != ctx.tenant_id:
        raise _fail("PROFILE_NOT_FOUND", f"Profile '{profile_id}' not found", 404)

    _apply_profile_fields(profile, req)
    profile.version += 1
    if profile.is_default:
        _clear_other_defaults(db, ctx.tenant_id, profile.id)
    refreshed = _push_profile_refresh(db, profile.id, "profile updated")
    db.commit()
    payload = profile.to_dict()

    log_audit_event(
        db,
        ctx,
        action="secure_connect.profile.update",
        target=f"sc_profile:{profile_id}",
        details={"version": payload["version"], "refreshed_sessions": refreshed},
    )
    return ProfileResponse(**payload)


@router.post("/profiles/{profile_id}/assign", response_model=AssignProfileResponse)
async def assign_profile(
    profile_id: str,
    req: AssignProfileRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> AssignProfileResponse:
    """Assign a profile to devices and refresh their live sessions in place."""
    profile = db.get(SecureConnectProfile, profile_id)
    if profile is None or profile.tenant_id != ctx.tenant_id:
        raise _fail("PROFILE_NOT_FOUND", f"Profile '{profile_id}' not found", 404)
    if not req.all_devices and not req.device_ids:
        raise _fail("NO_TARGET_DEVICES", "Provide device_ids or set all_devices")

    query = select(SecureConnectDevice).where(
        SecureConnectDevice.tenant_id == ctx.tenant_id
    )
    if not req.all_devices:
        query = query.where(SecureConnectDevice.id.in_(req.device_ids))
    devices = list(db.scalars(query).all())
    if not req.all_devices and len(devices) != len(set(req.device_ids)):
        found = {device.id for device in devices}
        missing = sorted(set(req.device_ids) - found)
        raise _fail("DEVICE_NOT_FOUND", f"Unknown devices: {missing}", 404)

    refreshed = 0
    for device in devices:
        device.profile_id = profile.id
        sessions = db.scalars(
            select(SecureConnectSession).where(
                SecureConnectSession.device_id == device.id,
                SecureConnectSession.state.in_(LIVE_SESSION_STATES),
            )
        ).all()
        for session in sessions:
            session.profile_id = profile.id
            session.profile_version += 1
            risk_adapter.queue_command(
                session, ControlAction.REFRESH_PROFILE, None, "profile assigned"
            )
            refreshed += 1
    db.commit()

    log_audit_event(
        db,
        ctx,
        action="secure_connect.profile.assign",
        target=f"sc_profile:{profile_id}",
        details={"devices": len(devices), "refreshed_sessions": refreshed},
    )
    return AssignProfileResponse(
        profile_id=profile_id,
        assigned_devices=len(devices),
        refreshed_sessions=refreshed,
    )


# -- Fleet operations ----------------------------------------------------------


@router.get("/devices", response_model=List[DeviceResponse])
async def list_devices(
    state: Optional[str] = Query(default=None),
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> List[DeviceResponse]:
    """List enrolled devices for the caller's tenant."""
    query = select(SecureConnectDevice).where(
        SecureConnectDevice.tenant_id == ctx.tenant_id
    )
    if state:
        query = query.where(SecureConnectDevice.state == state)
    devices = db.scalars(query.order_by(SecureConnectDevice.enrolled_at.desc())).all()
    return [DeviceResponse(**device.to_dict()) for device in devices]


@router.post("/devices/{device_id}/quarantine", response_model=List[SessionResponse])
async def quarantine_device(
    device_id: str,
    req: SessionActionRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> List[SessionResponse]:
    """Quarantine a device and revoke every session key it holds."""
    device = _load_device(db, ctx.tenant_id, device_id)
    sessions = service.quarantine_device(db, device, req.reason)
    db.commit()
    payloads = [_session_response(session) for session in sessions]

    log_audit_event(
        db,
        ctx,
        action="secure_connect.device.quarantine",
        target=f"sc_device:{device_id}",
        details={"reason": req.reason, "sessions": len(payloads)},
    )
    return payloads


@router.get("/sessions", response_model=List[SessionResponse])
async def list_sessions(
    state: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> List[SessionResponse]:
    """List sessions for the caller's tenant, flagging stale heartbeats."""
    query = select(SecureConnectSession).where(
        SecureConnectSession.tenant_id == ctx.tenant_id
    )
    if state:
        query = query.where(SecureConnectSession.state == state)
    if device_id:
        query = query.where(SecureConnectSession.device_id == device_id)
    sessions = db.scalars(query.order_by(SecureConnectSession.started_at.desc())).all()
    return [_session_response(session) for session in sessions]


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Fetch one session's state and counters."""
    return _session_response(_load_session(db, ctx.tenant_id, session_id))


@router.post("/sessions/{session_id}/terminate", response_model=SessionResponse)
async def terminate_session(
    session_id: str,
    req: SessionActionRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Tear down a session immediately and revoke its keys."""
    session = _load_session(db, ctx.tenant_id, session_id)
    try:
        service.terminate_session(db, session, req.reason)
    except risk_adapter.TransitionRejected as exc:
        db.rollback()
        raise _fail(exc.code, exc.message, 409) from exc
    db.commit()
    payload = _session_response(session)

    log_audit_event(
        db,
        ctx,
        action="secure_connect.session.terminate",
        target=f"sc_session:{session_id}",
        details={"reason": req.reason, "device_id": payload.device_id},
    )
    return payload


@router.post("/sessions/{session_id}/state", response_model=SessionResponse)
async def set_session_state(
    session_id: str,
    req: SetSessionStateRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Operator-confirmed transition for a session.

    Relaxations are limited to `elevated -> healthy`: the endpoint refuses any
    other loosening on a live session by design, so recovering a restricted or
    quarantined device goes through termination and a fresh session instead.
    """
    session = _load_session(db, ctx.tenant_id, session_id)
    target = req.desired_state
    if (
        risk_adapter.is_relaxation(session.state, target)
        and not (
            session.state == SessionState.ELEVATED.value
            and target == SessionState.HEALTHY
        )
    ):
        raise _fail(
            "RELAXATION_REQUIRES_NEW_SESSION",
            f"The endpoint only accepts 'elevated -> healthy' on a live session; "
            f"terminate session '{session_id}' so the device reconnects under the "
            f"relaxed profile",
            409,
        )
    if target == SessionState.RESTRICTED:
        profile = db.get(SecureConnectProfile, session.profile_id)
        if not (profile and profile.safe_cidrs):
            raise _fail(
                "PROFILE_HAS_NO_SAFE_CIDRS",
                "Restricting a session requires safe_cidrs on its profile",
                409,
            )
    try:
        risk_adapter.apply_transition(
            db,
            session,
            target,
            req.reason or f"operator set state {target.value}",
            operator_confirmed=True,
        )
    except risk_adapter.TransitionRejected as exc:
        db.rollback()
        raise _fail(exc.code, exc.message, 409) from exc
    db.commit()
    payload = _session_response(session)

    log_audit_event(
        db,
        ctx,
        action="secure_connect.session.set_state",
        target=f"sc_session:{session_id}",
        details={"state": target.value, "reason": req.reason},
    )
    return payload


@router.get("/metrics", response_model=SecureConnectMetrics)
async def secure_connect_metrics(
    ctx: RequestContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> SecureConnectMetrics:
    """Fleet counters behind the Secure Connect SLOs.

    Command latency is measured from the moment a command is queued to the
    heartbeat that delivered it, which is the revoke-propagation number the
    plan's SLO targets.
    """
    sessions = list(
        db.scalars(
            select(SecureConnectSession).where(
                SecureConnectSession.tenant_id == ctx.tenant_id
            )
        ).all()
    )
    devices = list(
        db.scalars(
            select(SecureConnectDevice).where(
                SecureConnectDevice.tenant_id == ctx.tenant_id
            )
        ).all()
    )
    gateways = list(
        db.scalars(
            select(SecureConnectGateway).where(
                (SecureConnectGateway.tenant_id.is_(None))
                | (SecureConnectGateway.tenant_id == ctx.tenant_id)
            )
        ).all()
    )
    enrollments = list(
        db.scalars(
            select(SecureConnectEnrollment).where(
                SecureConnectEnrollment.tenant_id == ctx.tenant_id
            )
        ).all()
    )

    sessions_by_state: Dict[str, int] = {}
    devices_by_state: Dict[str, int] = {}
    live_by_gateway: Dict[str, int] = {}
    latencies: List[int] = []
    stale = 0
    pending = 0
    now = utc_now()

    for session in sessions:
        sessions_by_state[session.state] = sessions_by_state.get(session.state, 0) + 1
        if session.last_command_latency_ms is not None:
            latencies.append(session.last_command_latency_ms)
        if session.state not in LIVE_SESSION_STATES:
            continue
        live_by_gateway[session.gateway_id] = live_by_gateway.get(session.gateway_id, 0) + 1
        if session.pending_action != ControlAction.NONE.value or session.pending_state:
            pending += 1
        last_beat = as_utc(session.last_heartbeat_at) or as_utc(session.started_at)
        if last_beat and (now - last_beat).total_seconds() > settings.sc_heartbeat_grace_secs:
            stale += 1

    for device in devices:
        devices_by_state[device.state] = devices_by_state.get(device.state, 0) + 1

    consumed = sum(1 for record in enrollments if record.used_at is not None)
    expired_unused = sum(
        1
        for record in enrollments
        if record.used_at is None
        and (as_utc(record.expires_at) or now) <= now
    )

    active_keys = db.scalar(
        select(func.count(SecureConnectKeyMaterial.id))
        .join(
            SecureConnectSession,
            SecureConnectSession.id == SecureConnectKeyMaterial.session_id,
        )
        .where(
            SecureConnectSession.tenant_id == ctx.tenant_id,
            SecureConnectKeyMaterial.revoked_at.is_(None),
        )
    )

    return SecureConnectMetrics(
        tenant_id=ctx.tenant_id,
        sessions_by_state=sessions_by_state,
        live_sessions=sum(live_by_gateway.values()),
        stale_sessions=stale,
        devices_by_state=devices_by_state,
        gateways=[
            GatewayUtilization(
                gateway_id=gateway.id,
                name=gateway.name,
                region=gateway.region,
                active_sessions=live_by_gateway.get(gateway.id, 0),
                capacity=gateway.capacity,
                utilization=round(
                    live_by_gateway.get(gateway.id, 0) / max(gateway.capacity, 1), 4
                ),
            )
            for gateway in gateways
        ],
        enrollment_tokens_issued=len(enrollments),
        enrollment_tokens_consumed=consumed,
        enrollment_tokens_expired_unused=expired_unused,
        pending_commands=pending,
        command_latency_ms=_latency_percentiles(latencies),
        active_peer_keys=int(active_keys or 0),
    )


def _latency_percentiles(values: List[int]) -> Dict[str, int]:
    if not values:
        return {"count": 0, "p50": 0, "p95": 0, "max": 0}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "p50": ordered[min(len(ordered) - 1, int(len(ordered) * 0.50))],
        "p95": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
        "max": ordered[-1],
    }


@router.post("/risk-signals", response_model=RiskSignalResponse)
async def submit_risk_signal(
    req: RiskSignalRequest,
    ctx: RequestContext = Depends(require_operator),
    db: Session = Depends(get_db),
) -> RiskSignalResponse:
    """Correlate a detection to live sessions and enforce the risk action.

    This is the seam the alert stream feeds: the caller supplies the host or
    device an alert fired on, and the orchestrator restricts, quarantines, or
    terminates every session anchored to it.
    """
    if not (req.host_id or req.device_id or req.session_id):
        raise _fail(
            "NO_CORRELATION_TARGET",
            "Provide host_id, device_id, or session_id to correlate the signal",
        )

    query = select(SecureConnectSession).where(
        SecureConnectSession.tenant_id == ctx.tenant_id,
        SecureConnectSession.state.in_(LIVE_SESSION_STATES),
    )
    if req.session_id:
        query = query.where(SecureConnectSession.id == req.session_id)
    if req.device_id:
        query = query.where(SecureConnectSession.device_id == req.device_id)
    if req.host_id:
        query = query.where(SecureConnectSession.host_id == req.host_id)
    sessions = list(db.scalars(query).all())

    reason = req.reason or f"{req.severity} alert"
    target, transitioned = service.apply_risk_signal(db, sessions, req.severity, reason)
    db.commit()
    payloads = [_session_response(session) for session in transitioned]

    if transitioned:
        log_audit_event(
            db,
            ctx,
            action="secure_connect.risk.transition",
            target=f"sc_tenant:{ctx.tenant_id}",
            details={
                "severity": req.severity,
                "alert_id": req.alert_id,
                "target_state": target.value if target else None,
                "sessions": [session.id for session in transitioned],
            },
        )
    return RiskSignalResponse(
        matched_sessions=len(sessions),
        transitioned_sessions=len(transitioned),
        target_state=target.value if target else None,
        sessions=payloads,
    )
