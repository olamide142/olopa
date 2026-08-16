//! Managed WireGuard client runtime.
//!
//! Secure Connect is deliberately isolated from the sensor and ingest loops:
//! configuration or control-plane failures are reported through its own
//! health snapshot and never stop endpoint telemetry.

mod config;
mod health;
mod orchestrator_client;
mod policy_applier;
mod posture;
mod session_manager;
mod telemetry;
mod wireguard_manager;

pub use config::SecureConnectConfig;
pub use health::read_health_from_env;

use crate::transport::http_sender::SenderHandle;
use log::{info, warn};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    Disabled,
    Idle,
    Enrolling,
    Connecting,
    Healthy,
    Elevated,
    Restricted,
    Quarantined,
    Terminated,
    Degraded,
}

impl SessionState {
    /// Higher values represent more restrictive access decisions.
    pub(crate) fn restriction_rank(self) -> u8 {
        match self {
            Self::Disabled | Self::Idle | Self::Enrolling | Self::Connecting | Self::Healthy => 0,
            Self::Elevated | Self::Degraded => 1,
            Self::Restricted => 2,
            Self::Quarantined => 3,
            Self::Terminated => 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct TunnelProfile {
    pub interface_address: String,
    pub gateway_public_key: String,
    pub gateway_endpoint: String,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub bypass_cidrs: Vec<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub profile_version: u64,
    #[serde(default)]
    pub expires_at_unix: u64,
    #[serde(default)]
    pub persistent_keepalive_secs: u16,
    #[serde(default)]
    pub mtu: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlAction {
    #[default]
    None,
    RefreshProfile,
    Rekey,
    Restrict,
    Quarantine,
    Terminate,
}

/// Start the subsystem when explicitly enabled. Failures are intentionally
/// contained so the endpoint sensor and durable ingest pipeline remain live.
///
/// `sender` lets tunnel and posture events ride the existing telemetry spool;
/// passing `None` disables Secure Connect telemetry without affecting the
/// tunnel itself.
pub fn spawn_from_env(sender: Option<SenderHandle>) {
    let config = match SecureConnectConfig::from_env() {
        Ok(Some(config)) => config,
        Ok(None) => {
            health::record_disabled();
            return;
        }
        Err(err) => {
            warn!("secure-connect configuration rejected: {err:#}");
            health::record_startup_error(err.to_string());
            return;
        }
    };

    info!(
        "secure-connect enabled control={} interface={}",
        config.control_url, config.interface
    );
    let telemetry = telemetry::Telemetry::new(sender);
    tokio::spawn(async move {
        if let Err(err) = session_manager::run(config, telemetry).await {
            warn!("secure-connect worker stopped: {err:#}");
            health::record_runtime_error(err.to_string());
        }
    });
}

pub(crate) fn current_health() -> SecureConnectHealth {
    health::current()
}

pub(crate) use health::SecureConnectHealth;
