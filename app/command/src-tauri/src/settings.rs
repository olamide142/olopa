//! Local operator settings for Olopa Command.
//!
//! Command is a client, never an authority: it stores where to find the agent's
//! status snapshots and which ingest / control-plane endpoints to read. Nothing
//! here is a credential store for the agent itself — the agent's own
//! configuration remains the source of truth for how it runs.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Mirrors the agent default in `agent/agent/src/agent.rs`.
pub const DEFAULT_STATUS_PATH: &str = "/tmp/olopa/agent/status.json";
/// Mirrors the Secure Connect default in `secure_connect/config.rs`.
pub const DEFAULT_SC_STATUS_PATH: &str = "/tmp/olopa/agent/secure-connect.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Agent runtime snapshot written every 5s by the housekeeping loop.
    pub agent_status_path: String,
    /// Secure Connect health snapshot written by the session manager.
    pub secure_connect_status_path: String,
    /// Rust ingest server, read directly for live telemetry.
    pub ingest_base_url: String,
    /// Python control plane, read for the rule registry and Secure Connect.
    pub control_base_url: String,
    /// systemd unit that supervises the agent daemon.
    pub agent_service_name: String,
    /// One credential, matching the control plane's single-credential rule.
    pub credential_kind: String,
    pub credential_value: String,
    pub tenant_id: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            agent_status_path: DEFAULT_STATUS_PATH.to_string(),
            secure_connect_status_path: DEFAULT_SC_STATUS_PATH.to_string(),
            ingest_base_url: "http://127.0.0.1:8000".to_string(),
            control_base_url: "http://127.0.0.1:8100".to_string(),
            agent_service_name: "olopa".to_string(),
            credential_kind: "none".to_string(),
            credential_value: String::new(),
            tenant_id: String::new(),
        }
    }
}

impl Settings {
    /// Credential headers, honouring the control plane's "exactly one" rule.
    pub fn auth_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        let value = self.credential_value.trim();
        if !value.is_empty() {
            match self.credential_kind.as_str() {
                "bearer" => headers.push(("authorization".into(), format!("Bearer {value}"))),
                "api-key" => headers.push(("x-api-key".into(), value.to_string())),
                "dev-token" => headers.push(("x-dev-token".into(), value.to_string())),
                _ => {}
            }
        }
        let tenant = self.tenant_id.trim();
        if !tenant.is_empty() {
            headers.push(("x-tenant-id".into(), tenant.to_string()));
        }
        headers
    }
}

fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("olopa-command").join("settings.json")
}

pub fn load() -> Settings {
    let path = config_path();
    let Ok(raw) = fs::read_to_string(&path) else {
        return Settings::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save(settings: &Settings) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Where settings live, surfaced in the Diagnostics panel.
pub fn location() -> String {
    config_path().display().to_string()
}
