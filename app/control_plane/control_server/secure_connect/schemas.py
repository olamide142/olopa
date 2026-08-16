"""Wire schemas for `/api/v1/secure-connect/*`.

Field names and defaults mirror the agent's serde structs in
`agent/agent/src/secure_connect/orchestrator_client.rs`. Changing a name here
without changing it there silently breaks every enrolled endpoint.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..models.secure_connect import (
    AccessMode,
    ControlAction,
    GatewayStatus,
    SessionState,
)

#: Posture is deliberately open-ended: phase 1-2 endpoints self-report a small
#: baseline, and phase 4 adds eBPF-verified facts without a schema change.
PostureFacts = Dict[str, Any]


class TunnelProfile(BaseModel):
    """Compiled endpoint tunnel configuration."""

    interface_address: str
    gateway_public_key: str
    gateway_endpoint: str
    allowed_cidrs: List[str] = Field(default_factory=list)
    bypass_cidrs: List[str] = Field(default_factory=list)
    dns_servers: List[str] = Field(default_factory=list)
    profile_version: int = 0
    expires_at_unix: int = 0
    persistent_keepalive_secs: int = 25
    mtu: Optional[int] = None


# -- Agent-facing contract -----------------------------------------------------


class EnrollmentRequest(BaseModel):
    enrollment_token: str = Field(min_length=1, max_length=4096)
    tenant_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=128)
    user_id: Optional[str] = Field(default=None, max_length=128)
    device_fingerprint: str = Field(min_length=1, max_length=128)
    wireguard_public_key: str = Field(min_length=1, max_length=64)
    posture: PostureFacts = Field(default_factory=dict)


class EnrollmentResponse(BaseModel):
    device_id: str
    profile_id: Optional[str] = None


class SessionStartRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=36)
    host_id: str = Field(min_length=1, max_length=128)
    wireguard_public_key: str = Field(min_length=1, max_length=64)
    posture: PostureFacts = Field(default_factory=dict)


class SessionStartResponse(BaseModel):
    session_id: str
    state: SessionState
    profile: TunnelProfile
    command_nonce: int = 0


class HeartbeatRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=36)
    session_id: str = Field(min_length=1, max_length=36)
    # The agent also reports transient local states (connecting, degraded, ...)
    # that the control plane never assigns, so this stays a plain string.
    state: str = Field(default="", max_length=32)
    posture: PostureFacts = Field(default_factory=dict)
    profile_version: int = 0
    last_command_nonce: int = 0
    last_handshake_unix: int = 0
    bytes_tx: int = 0
    bytes_rx: int = 0


class HeartbeatResponse(BaseModel):
    desired_state: Optional[SessionState] = None
    action: ControlAction = ControlAction.NONE
    profile: Optional[TunnelProfile] = None
    # Must advance whenever a command is present: the agent rejects a replayed
    # nonce, and rejects a state-changing response that omits one.
    command_nonce: int = 0


class RekeyRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=36)
    wireguard_public_key: str = Field(min_length=1, max_length=64)
    last_command_nonce: int = 0


class RekeyResponse(BaseModel):
    profile: TunnelProfile
    command_nonce: int = 0


# -- Operator-facing contract --------------------------------------------------


class CreateEnrollmentTokenRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    device_hint: str = Field(default="", max_length=256)
    profile_id: Optional[str] = Field(default=None, max_length=36)
    ttl_minutes: int = Field(default=15, ge=1, le=15)


class CreateEnrollmentTokenResponse(BaseModel):
    token: str
    jti: str
    expires_at: Optional[str]
    profile_id: Optional[str]


class CreateGatewayRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    region: str = Field(min_length=1, max_length=64)
    public_key: str = Field(min_length=1, max_length=64)
    public_endpoint: str = Field(min_length=3, max_length=256)
    client_cidr: str = Field(min_length=3, max_length=64)
    dns_servers: List[str] = Field(default_factory=list)
    capacity: int = Field(default=1000, ge=1, le=1_000_000)
    dedicated: bool = Field(
        default=False,
        description="Bind the gateway to the calling tenant instead of the shared pool",
    )


class GatewayResponse(BaseModel):
    id: str
    name: str
    region: str
    tenant_id: Optional[str]
    public_key: str
    public_endpoint: str
    client_cidr: str
    dns_servers: List[str]
    status: str
    capacity: int
    last_seen_at: Optional[str]
    observed_peers: int
    reconciler_version: str
    reachable: bool
    created_at: Optional[str]
    updated_at: Optional[str]


class GatewayHeartbeatRequest(BaseModel):
    """Liveness posted by the gateway reconciler after a successful poll."""

    observed_peers: int = Field(default=0, ge=0)
    reconciler_version: str = Field(default="", max_length=64)


class GatewayHeartbeatResponse(BaseModel):
    gateway_id: str
    status: str
    expected_peers: int
    acknowledged_at: Optional[str]


class UpdateGatewayStatusRequest(BaseModel):
    """Operator intent for a gateway.

    `draining` stops new sessions but leaves current ones running; `offline`
    also evacuates them onto another gateway.
    """

    status: GatewayStatus
    reason: str = Field(default="", max_length=256)


class GatewayFailoverResponse(BaseModel):
    migrated_sessions: int
    stranded_sessions: int
    sessions: List[str]


class GatewayPeer(BaseModel):
    """Desired peer state for a gateway to reconcile against."""

    session_id: str
    device_id: str
    public_key: str
    allowed_ips: List[str]
    expires_at_unix: int


class CreateProfileRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    access_mode: AccessMode = AccessMode.SPLIT_TUNNEL
    region: str = Field(default="", max_length=64)
    allowed_cidrs: List[str] = Field(default_factory=list)
    safe_cidrs: List[str] = Field(default_factory=list)
    bypass_cidrs: List[str] = Field(default_factory=list)
    dns_servers: List[str] = Field(default_factory=list)
    session_ttl_secs: int = Field(default=3600, ge=60, le=86_400)
    rekey_interval_secs: int = Field(default=900, ge=60, le=86_400)
    persistent_keepalive_secs: int = Field(default=25, ge=0, le=65_535)
    mtu: Optional[int] = Field(default=None, ge=576, le=9_000)
    risk_actions: Dict[str, str] = Field(default_factory=dict)
    is_default: bool = False


class ProfileResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    access_mode: str
    region: str
    allowed_cidrs: List[str]
    safe_cidrs: List[str]
    bypass_cidrs: List[str]
    dns_servers: List[str]
    session_ttl_secs: int
    rekey_interval_secs: int
    persistent_keepalive_secs: int
    mtu: Optional[int]
    risk_actions: Dict[str, str]
    is_default: bool
    version: int
    created_by: str
    created_at: Optional[str]
    updated_at: Optional[str]


class AssignProfileRequest(BaseModel):
    device_ids: List[str] = Field(default_factory=list, max_length=1000)
    all_devices: bool = False


class AssignProfileResponse(BaseModel):
    profile_id: str
    assigned_devices: int
    refreshed_sessions: int


class DeviceResponse(BaseModel):
    id: str
    tenant_id: str
    host_id: str
    user_id: str
    device_fingerprint: str
    cert_fingerprint: Optional[str]
    wireguard_public_key: str
    profile_id: Optional[str]
    state: str
    posture: Dict[str, Any]
    enrolled_by: str
    enrolled_at: Optional[str]
    last_seen_at: Optional[str]
    updated_at: Optional[str]


class SessionResponse(BaseModel):
    id: str
    tenant_id: str
    device_id: str
    gateway_id: str
    profile_id: str
    host_id: str
    assigned_address: str
    wireguard_public_key: str
    state: str
    profile_version: int
    command_nonce: int
    acked_command_nonce: int
    pending_action: str
    pending_state: Optional[str]
    pending_reason: Optional[str]
    last_command_latency_ms: Optional[int]
    started_at: Optional[str]
    expires_at: Optional[str]
    last_heartbeat_at: Optional[str]
    last_rekey_at: Optional[str]
    last_handshake_unix: int
    bytes_tx: int
    bytes_rx: int
    posture: Dict[str, Any]
    close_reason: Optional[str]
    terminated_at: Optional[str]
    #: True when the endpoint has missed its heartbeat grace window.
    stale: bool = False


class SessionActionRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


class SetSessionStateRequest(BaseModel):
    desired_state: SessionState
    reason: str = Field(default="", max_length=256)


class RiskSignalRequest(BaseModel):
    """Detection input from the alert stream, correlated by host."""

    host_id: Optional[str] = Field(default=None, max_length=128)
    device_id: Optional[str] = Field(default=None, max_length=36)
    session_id: Optional[str] = Field(default=None, max_length=36)
    severity: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=256)
    alert_id: Optional[str] = Field(default=None, max_length=128)


class RiskSignalResponse(BaseModel):
    matched_sessions: int
    transitioned_sessions: int
    target_state: Optional[str]
    sessions: List[SessionResponse]


class GatewayUtilization(BaseModel):
    gateway_id: str
    name: str
    region: str
    active_sessions: int
    capacity: int
    utilization: float


class SecureConnectMetrics(BaseModel):
    """Fleet-level counters behind the Secure Connect SLOs."""

    tenant_id: str
    sessions_by_state: Dict[str, int]
    live_sessions: int
    stale_sessions: int
    devices_by_state: Dict[str, int]
    gateways: List[GatewayUtilization]
    enrollment_tokens_issued: int
    enrollment_tokens_consumed: int
    enrollment_tokens_expired_unused: int
    pending_commands: int
    command_latency_ms: Dict[str, int]
    active_peer_keys: int
