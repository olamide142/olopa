"""Configuration for the Python control-plane service."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    host: str
    port: int
    rust_ingest_base_url: str
    rust_request_timeout_s: float
    compiler_timeout_s: int
    oilc_manifest_path: str
    oilc_binary_path: str
    agent_download_url: str
    agent_binary_path: str
    auth_required: bool
    dev_token: str
    jwt_secret: str
    jwt_issuer: str
    jwt_audience: str
    service_tokens_json: str
    dev_token_issuance_enabled: bool
    rust_ingest_api_token: str
    compiler_source_root: str
    # -- Secure Connect (managed WireGuard / ZTNA) --
    sc_client_cert_header: str
    sc_allow_unbound_enrollment: bool
    sc_heartbeat_grace_secs: int
    sc_elevated_cooldown_secs: int
    sc_worker_enabled: bool
    sc_worker_interval_secs: int
    sc_risk_subscriber_enabled: bool
    sc_alert_poll_limit: int
    sc_risk_critical_score: float
    sc_risk_high_score: float
    sc_risk_medium_score: float
    sc_gateway_grace_secs: int
    sc_auto_failover_enabled: bool

    @classmethod
    def from_env(cls) -> "Settings":
        """Create settings from environment with safe defaults."""
        repo_root = Path(__file__).resolve().parents[3]
        default_manifest = repo_root / "oilc" / "Cargo.toml"
        # Prefer explicit control-plane config, but accept ingest URL aliases
        # typically used in deployment systems (for example Railway).
        rust_base = _env_str(
            "RUST_INGEST_BASE_URL",
            _env_str("INGEST_SERVER_URL", "http://127.0.0.1:8000"),
        ).strip()
        if "://" not in rust_base:
            rust_base = f"http://{rust_base}"
        rust_base = rust_base.rstrip("/")
        return cls(
            host=_env_str("CONTROL_HOST", "0.0.0.0"),
            port=_env_int("CONTROL_PORT", 8100),
            rust_ingest_base_url=rust_base,
            rust_request_timeout_s=_env_float("RUST_REQUEST_TIMEOUT_S", 3.0),
            compiler_timeout_s=_env_int("COMPILER_TIMEOUT_S", 20),
            oilc_manifest_path=_env_str("OILC_MANIFEST_PATH", str(default_manifest)),
            oilc_binary_path=os.getenv("OILC_BINARY_PATH", "").strip(),
            agent_download_url=_env_str("AGENT_DOWNLOAD_URL", ""),
            agent_binary_path=_env_str("AGENT_BINARY_PATH", ""),
            auth_required=_env_bool("CONTROL_AUTH_REQUIRED", True),
            # There is intentionally no built-in credential. Development and
            # test environments must opt in with an explicit token.
            dev_token=os.getenv("CONTROL_DEV_TOKEN", "").strip(),
            jwt_secret=os.getenv("JWT_SECRET", "").strip(),
            jwt_issuer=os.getenv("JWT_ISSUER", "").strip(),
            jwt_audience=os.getenv("JWT_AUDIENCE", "").strip(),
            service_tokens_json=os.getenv("CONTROL_SERVICE_TOKENS_JSON", "").strip(),
            dev_token_issuance_enabled=_env_bool(
                "CONTROL_DEV_TOKEN_ISSUANCE_ENABLED", False
            ),
            rust_ingest_api_token=os.getenv("RUST_INGEST_API_TOKEN", "").strip(),
            compiler_source_root=os.getenv("CONTROL_COMPILER_SOURCE_ROOT", "").strip(),
            # The TLS terminator in front of the control plane forwards the
            # verified client-certificate fingerprint in this header.
            sc_client_cert_header=_env_str(
                "CONTROL_SC_CLIENT_CERT_HEADER", "x-olopa-client-cert-fingerprint"
            ),
            # Mirrors the agent's OLOPA_SC_ALLOW_UNBOUND_ENROLLMENT: local
            # development only, since it drops the mTLS device binding.
            sc_allow_unbound_enrollment=_env_bool(
                "CONTROL_SC_ALLOW_UNBOUND_ENROLLMENT", False
            ),
            sc_heartbeat_grace_secs=_env_int("CONTROL_SC_HEARTBEAT_GRACE_SECS", 90),
            sc_elevated_cooldown_secs=_env_int(
                "CONTROL_SC_ELEVATED_COOLDOWN_SECS", 900
            ),
            # The reaper is safe to run anywhere; the risk subscriber needs a
            # reachable ingest server, so it stays opt-in.
            sc_worker_enabled=_env_bool("CONTROL_SC_WORKER_ENABLED", True),
            sc_worker_interval_secs=_env_int("CONTROL_SC_WORKER_INTERVAL_SECS", 15),
            sc_risk_subscriber_enabled=_env_bool(
                "CONTROL_SC_RISK_SUBSCRIBER_ENABLED", False
            ),
            sc_alert_poll_limit=_env_int("CONTROL_SC_ALERT_POLL_LIMIT", 500),
            sc_risk_critical_score=_env_float("CONTROL_SC_RISK_CRITICAL_SCORE", 0.9),
            sc_risk_high_score=_env_float("CONTROL_SC_RISK_HIGH_SCORE", 0.7),
            sc_risk_medium_score=_env_float("CONTROL_SC_RISK_MEDIUM_SCORE", 0.4),
            # How long a gateway may go without a reconciler heartbeat before it
            # stops receiving sessions. Gateways that have never reported are
            # treated as unknown, not dead.
            sc_gateway_grace_secs=_env_int("CONTROL_SC_GATEWAY_GRACE_SECS", 120),
            sc_auto_failover_enabled=_env_bool(
                "CONTROL_SC_AUTO_FAILOVER_ENABLED", True
            ),
        )
