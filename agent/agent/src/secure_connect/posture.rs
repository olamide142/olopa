//! Endpoint posture facts reported with every heartbeat.
//!
//! Two tiers are reported together:
//!
//! - baseline self-reported facts (OS, kernel, disk encryption, privileges),
//! - kernel-verified facts sourced from the live sensor's own status snapshot
//!   and rule-engine deployment state.
//!
//! The second tier is what separates this from self-report-only posture: the
//! values come from the running eBPF sensor, and `kernel_verified_posture` is
//! false whenever that snapshot is missing or stale, so the control plane can
//! tell a healthy endpoint from one whose sensor stopped reporting.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_STATUS_PATH: &str = "/tmp/olopa/agent/status.json";
const DEFAULT_RULE_STATUS_PATH: &str = "/tmp/olopa/agent/rules.json";

/// A sensor snapshot older than this is not treated as kernel-verified.
const SENSOR_SNAPSHOT_MAX_AGE_SECS: u64 = 60;

#[derive(Clone, Debug, Serialize)]
pub struct PostureFacts {
    // -- Baseline self-reported --
    pub agent_version: String,
    pub os_version: String,
    pub kernel_version: String,
    pub disk_encryption_detected: bool,
    pub running_as_root: bool,
    pub probe_health: String,
    pub collected_at_unix: u64,

    // -- Kernel-verified (sourced from the live sensor) --
    /// True only when the sensor snapshot exists and is fresh.
    pub kernel_verified_posture: bool,
    /// Probes the sensor reports as actually attached.
    pub probes_attached: Vec<String>,
    /// Age of the sensor snapshot; large values mean the sensor stalled.
    pub sensor_status_age_secs: u64,
    pub sensor_events_captured: u64,
    pub sensor_events_transmitted: u64,
    pub sensor_events_dropped: u64,
    pub firewall_deny: u64,
    pub firewall_approve: u64,
    pub ingest_backend_reachable: bool,
    /// Rule-engine deployment facts; a zero rule count means detection is off.
    pub rule_count: u64,
    pub rule_generation: u64,
    pub rule_fallback_active: bool,
}

/// Subset of the sensor's runtime status file that posture depends on.
#[derive(Debug, Default, Deserialize)]
struct SensorStatus {
    #[serde(default)]
    generated_at_unix_ms: u64,
    #[serde(default)]
    running: bool,
    #[serde(default)]
    probes: Vec<String>,
    #[serde(default)]
    backend: SensorBackend,
    #[serde(default)]
    window_5s: SensorWindow,
    #[serde(default)]
    firewall: SensorFirewall,
}

#[derive(Debug, Default, Deserialize)]
struct SensorBackend {
    #[serde(default)]
    reachable: bool,
}

#[derive(Debug, Default, Deserialize)]
struct SensorWindow {
    #[serde(default)]
    captured: u64,
    #[serde(default)]
    transmitted: u64,
    #[serde(default)]
    dropped_budget: u64,
}

#[derive(Debug, Default, Deserialize)]
struct SensorFirewall {
    #[serde(default)]
    deny: u64,
    #[serde(default)]
    approve: u64,
}

/// Subset of the rule-engine deployment status file.
#[derive(Debug, Default, Deserialize)]
struct RuleStatus {
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    rule_count: u64,
    #[serde(default)]
    fallback_active: bool,
}

pub fn collect() -> PostureFacts {
    let now = now_unix();
    let sensor = read_json::<SensorStatus>(status_path());
    let rules = read_json::<RuleStatus>(rule_status_path());

    let snapshot_age = sensor
        .as_ref()
        .map(|status| now.saturating_sub(status.generated_at_unix_ms / 1_000))
        .unwrap_or(u64::MAX);
    let verified = sensor
        .as_ref()
        .is_some_and(|status| status.running && snapshot_age <= SENSOR_SNAPSHOT_MAX_AGE_SECS);

    PostureFacts {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        os_version: os_version(),
        kernel_version: fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string(),
        disk_encryption_detected: disk_encryption_detected(),
        running_as_root: unsafe { libc::geteuid() } == 0,
        probe_health: probe_health(verified, sensor.as_ref()),
        collected_at_unix: now,

        kernel_verified_posture: verified,
        probes_attached: sensor
            .as_ref()
            .map(|status| status.probes.clone())
            .unwrap_or_default(),
        sensor_status_age_secs: snapshot_age.min(u64::MAX),
        sensor_events_captured: sensor.as_ref().map_or(0, |s| s.window_5s.captured),
        sensor_events_transmitted: sensor.as_ref().map_or(0, |s| s.window_5s.transmitted),
        sensor_events_dropped: sensor.as_ref().map_or(0, |s| s.window_5s.dropped_budget),
        firewall_deny: sensor.as_ref().map_or(0, |s| s.firewall.deny),
        firewall_approve: sensor.as_ref().map_or(0, |s| s.firewall.approve),
        ingest_backend_reachable: sensor.as_ref().is_some_and(|s| s.backend.reachable),
        rule_count: rules.as_ref().map_or(0, |r| r.rule_count),
        rule_generation: rules.as_ref().map_or(0, |r| r.generation),
        rule_fallback_active: rules.as_ref().is_some_and(|r| r.fallback_active),
    }
}

/// Single-word health summary the control plane can key policy off.
fn probe_health(verified: bool, sensor: Option<&SensorStatus>) -> String {
    match sensor {
        None => "unreported".to_string(),
        Some(_) if !verified => "stale".to_string(),
        Some(status) if status.probes.is_empty() => "no_probes".to_string(),
        Some(status) if status.window_5s.dropped_budget > status.window_5s.captured => {
            "degraded".to_string()
        }
        Some(_) => "healthy".to_string(),
    }
}

fn status_path() -> PathBuf {
    env_path("OLOPA_STATUS_PATH", DEFAULT_STATUS_PATH)
}

fn rule_status_path() -> PathBuf {
    env_path("OLOPA_RULE_STATUS_PATH", DEFAULT_RULE_STATUS_PATH)
}

fn env_path(key: &str, default: &str) -> PathBuf {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn read_json<T: serde::de::DeserializeOwned>(path: PathBuf) -> Option<T> {
    fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

fn os_version() -> String {
    let raw = fs::read_to_string("/etc/os-release").unwrap_or_default();
    raw.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn disk_encryption_detected() -> bool {
    fs::read_dir("/sys/class/block")
        .ok()
        .is_some_and(|entries| {
            entries.flatten().any(|entry| {
                fs::read_to_string(entry.path().join("dm/uuid"))
                    .ok()
                    .is_some_and(|uuid| uuid.trim().to_ascii_uppercase().starts_with("CRYPT-"))
            })
        })
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sensor(probes: Vec<&str>, captured: u64, dropped: u64) -> SensorStatus {
        SensorStatus {
            generated_at_unix_ms: 0,
            running: true,
            probes: probes.into_iter().map(str::to_string).collect(),
            backend: SensorBackend { reachable: true },
            window_5s: SensorWindow {
                captured,
                transmitted: captured,
                dropped_budget: dropped,
            },
            firewall: SensorFirewall::default(),
        }
    }

    #[test]
    fn missing_or_stale_sensor_snapshots_are_not_kernel_verified() {
        assert_eq!(probe_health(false, None), "unreported");
        assert_eq!(probe_health(false, Some(&sensor(vec!["exec"], 10, 0))), "stale");
    }

    #[test]
    fn probe_health_reflects_attachment_and_drop_pressure() {
        assert_eq!(probe_health(true, Some(&sensor(vec![], 0, 0))), "no_probes");
        assert_eq!(
            probe_health(true, Some(&sensor(vec!["exec"], 10, 99))),
            "degraded"
        );
        assert_eq!(
            probe_health(true, Some(&sensor(vec!["exec"], 100, 1))),
            "healthy"
        );
    }

    #[test]
    fn collect_reports_baseline_facts_without_a_sensor_snapshot() {
        // Secure Connect must still enroll on a host where the sensor has not
        // written a snapshot yet.
        std::env::set_var("OLOPA_STATUS_PATH", "/nonexistent/olopa-status.json");
        std::env::set_var("OLOPA_RULE_STATUS_PATH", "/nonexistent/olopa-rules.json");
        let facts = collect();
        assert!(!facts.kernel_verified_posture);
        assert_eq!(facts.probe_health, "unreported");
        assert_eq!(facts.rule_count, 0);
        assert!(!facts.agent_version.is_empty());
        std::env::remove_var("OLOPA_STATUS_PATH");
        std::env::remove_var("OLOPA_RULE_STATUS_PATH");
    }
}
