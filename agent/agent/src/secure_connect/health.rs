use super::SessionState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SecureConnectHealth {
    pub enabled: bool,
    pub state: SessionState,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub interface: Option<String>,
    pub profile_version: u64,
    pub last_heartbeat_unix: u64,
    pub last_handshake_unix: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub reconnect_count: u64,
    pub policy_apply_ms: u64,
    pub revoke_apply_ms: u64,
    pub kill_switch_apply_ms: u64,
    pub posture_updated_unix: u64,
    pub last_error: Option<String>,
}

static HEALTH: OnceLock<RwLock<SecureConnectHealth>> = OnceLock::new();
static STATUS_PATH: OnceLock<PathBuf> = OnceLock::new();

pub(crate) fn current() -> SecureConnectHealth {
    HEALTH
        .get()
        .and_then(|health| health.read().ok())
        .map(|health| health.clone())
        .unwrap_or_default()
}

pub(crate) fn record_disabled() {
    let path = std::env::var("OLOPA_SC_STATUS_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/olopa/agent/secure-connect.json"));
    let _ = STATUS_PATH.set(path);
    update(|health| {
        *health = SecureConnectHealth::default();
        health.state = SessionState::Disabled;
    });
}

pub(crate) fn initialize(path: PathBuf, interface: String) {
    let _ = STATUS_PATH.set(path);
    update(|health| {
        health.enabled = true;
        health.state = SessionState::Idle;
        health.interface = Some(interface);
        health.last_error = None;
    });
}

/// Apply an update and return the resulting reconnect count, so callers can
/// report it without taking a second lock.
pub(crate) fn update_and_read(mutator: impl FnOnce(&mut SecureConnectHealth)) -> u64 {
    let shared = HEALTH.get_or_init(|| RwLock::new(SecureConnectHealth::default()));
    let snapshot = if let Ok(mut health) = shared.write() {
        mutator(&mut health);
        health.clone()
    } else {
        return 0;
    };
    if let Some(path) = STATUS_PATH.get() {
        let _ = write_atomic(path, &snapshot);
    }
    snapshot.reconnect_count
}

pub(crate) fn update(mutator: impl FnOnce(&mut SecureConnectHealth)) {
    let _ = update_and_read(mutator);
}

pub(crate) fn record_startup_error(error: String) {
    if STATUS_PATH.get().is_none() {
        let path = std::env::var("OLOPA_SC_STATUS_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/olopa/agent/secure-connect.json"));
        let _ = STATUS_PATH.set(path);
    }
    update(|health| {
        health.enabled = true;
        health.state = SessionState::Degraded;
        health.last_error = Some(error);
    });
}

pub(crate) fn record_runtime_error(error: String) {
    update(|health| {
        health.state = SessionState::Degraded;
        health.last_error = Some(error);
    });
}

pub fn read_health_from_env() -> Option<SecureConnectHealth> {
    let path = std::env::var("OLOPA_SC_STATUS_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/olopa/agent/secure-connect.json"));
    fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

fn write_atomic(path: &Path, health: &SecureConnectHealth) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    let encoded = serde_json::to_vec_pretty(health)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    fs::write(&temp, encoded)?;
    fs::rename(temp, path)
}
