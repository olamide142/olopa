//! Local agent observation and lifecycle control.
//!
//! Command never embeds the agent. The agent is an independent privileged
//! daemon that writes a status snapshot every 5s; Command reads that snapshot
//! and, when asked, drives the service manager. Closing Command must never stop
//! protection, so nothing here holds the agent's lifetime.

use crate::settings::Settings;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command as Proc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Housekeeping writes every 5s; treat anything older than this as stale.
const STALE_AFTER_MS: u64 = 15_000;

// -- Wire contract (mirrors RuntimeStatusSnapshot in agent/agent/src/agent.rs) --

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendStatus {
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceStatus {
    pub cpu_pct: f32,
    pub cpu_budget_pct: f32,
    pub mem_mb: f32,
    pub mem_ceiling_mb: f32,
    pub bw_mb_s: f32,
    pub bw_limit_pct: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowStatus {
    pub captured: u64,
    pub transmitted: u64,
    pub dropped_budget: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallStatus {
    pub allow: u64,
    pub deny: u64,
    pub approve: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentSnapshot {
    pub version: u8,
    pub generated_at_unix_ms: u64,
    pub pid: u32,
    pub running: bool,
    pub iface: String,
    pub probes: Vec<String>,
    pub backend: BackendStatus,
    pub resources: ResourceStatus,
    pub window_5s: WindowStatus,
    pub firewall: FirewallStatus,
}

/// Mirrors `SecureConnectHealth` in `agent/agent/src/secure_connect/health.rs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecureConnectHealth {
    pub enabled: bool,
    /// Left as a string so a new session state never breaks the panel.
    pub state: String,
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

/// A snapshot read plus everything the UI needs to explain a missing one.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotReport<T> {
    pub path: String,
    pub present: bool,
    pub stale: bool,
    pub age_ms: Option<u64>,
    pub snapshot: Option<T>,
    pub error: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_snapshot<T: for<'de> Deserialize<'de>>(path: &str) -> SnapshotReport<T> {
    let mut report = SnapshotReport {
        path: path.to_string(),
        present: false,
        stale: false,
        age_ms: None,
        snapshot: None,
        error: None,
    };
    if !Path::new(path).exists() {
        report.error = Some(format!("no snapshot at {path} — is the agent running?"));
        return report;
    }
    report.present = true;
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<T>(&raw) {
            Ok(snapshot) => report.snapshot = Some(snapshot),
            Err(err) => report.error = Some(format!("snapshot is not valid JSON: {err}")),
        },
        Err(err) => report.error = Some(format!("cannot read {path}: {err}")),
    }
    report
}

pub fn agent_status(settings: &Settings) -> SnapshotReport<AgentSnapshot> {
    let mut report = read_snapshot::<AgentSnapshot>(&settings.agent_status_path);
    if let Some(snapshot) = &report.snapshot {
        let age = now_ms().saturating_sub(snapshot.generated_at_unix_ms);
        report.age_ms = Some(age);
        report.stale = age > STALE_AFTER_MS;
        if report.stale {
            report.error = Some(format!(
                "snapshot is {}s old — the agent may have stopped writing it",
                age / 1000
            ));
        }
    }
    report
}

pub fn secure_connect_status(settings: &Settings) -> SnapshotReport<SecureConnectHealth> {
    read_snapshot::<SecureConnectHealth>(&settings.secure_connect_status_path)
}

// -- Lifecycle -----------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentAction {
    Start,
    Stop,
    Restart,
    Status,
}

impl AgentAction {
    fn verb(self) -> &'static str {
        match self {
            AgentAction::Start => "start",
            AgentAction::Stop => "stop",
            AgentAction::Restart => "restart",
            AgentAction::Status => "status",
        }
    }

}

#[derive(Debug, Clone, Serialize)]
pub struct CommandOutcome {
    pub command: String,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

fn run(program: &str, args: &[&str]) -> CommandOutcome {
    let printable = format!("{program} {}", args.join(" "));
    match Proc::new(program).args(args).output() {
        Ok(output) => CommandOutcome {
            command: printable,
            ok: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(err) => CommandOutcome {
            command: printable,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to execute: {err}"),
        },
    }
}

/// Drive the agent's systemd unit.
///
/// Command deliberately does not escalate privileges itself: a mutating action
/// that needs root fails with systemd's own message, which the UI shows verbatim
/// rather than silently retrying under sudo.
pub fn control(settings: &Settings, action: AgentAction) -> CommandOutcome {
    let unit = settings.agent_service_name.trim();
    if unit.is_empty() || !unit.chars().all(|c| c.is_alphanumeric() || "-_.@".contains(c)) {
        return CommandOutcome {
            command: "systemctl".into(),
            ok: false,
            exit_code: None,
            stderr: format!("refusing to run systemctl for invalid unit name '{unit}'"),
            stdout: String::new(),
        };
    }
    run("systemctl", &["--no-pager", action.verb(), unit])
}

/// Read the agent's own rendering of its status, which includes fields the
/// snapshot does not carry.
pub fn cli_status(settings: &Settings) -> CommandOutcome {
    run(
        "olopa",
        &[
            "status",
            "--verbose",
            "--no-color",
            "--no-mascot",
            "--status-path",
            &settings.agent_status_path,
        ],
    )
}

/// Host facts the Overview panel pairs with the agent snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct HostFacts {
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub uptime_secs: u64,
}

pub fn host_facts() -> HostFacts {
    let read = |path: &str| fs::read_to_string(path).unwrap_or_default().trim().to_string();
    let os = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|raw| {
            raw.lines()
                .find(|line| line.starts_with("PRETTY_NAME="))
                .map(|line| line.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let uptime_secs = read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v as u64)
        .unwrap_or(0);
    HostFacts {
        hostname: read("/proc/sys/kernel/hostname"),
        kernel: read("/proc/sys/kernel/osrelease"),
        os,
        uptime_secs,
    }
}
