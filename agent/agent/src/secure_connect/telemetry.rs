//! Secure Connect telemetry emitted through the existing ingest stream.
//!
//! Tunnel and posture events ride the sensor's durable spool rather than a
//! dedicated ingress, so they survive restarts and reach the same store the
//! detection pipeline reads. Emission is always best-effort: telemetry loss
//! must never affect tunnel availability.

use super::posture::PostureFacts;
use super::{SessionState, TunnelProfile};
use crate::transport::http_sender::SenderHandle;
use log::debug;

/// Wire prefix recognised by the ingest sender's line mapper.
const LINE_PREFIX: &str = "sc_event";

#[derive(Clone, Default)]
pub(crate) struct Telemetry {
    handle: Option<SenderHandle>,
}

impl Telemetry {
    pub fn new(handle: Option<SenderHandle>) -> Self {
        Self { handle }
    }

    /// Emit one key/value event line. Values are sanitised because the ingest
    /// line parser splits fields on whitespace.
    fn emit(&self, event: &str, fields: &[(&str, String)]) {
        let Some(handle) = &self.handle else {
            return;
        };
        let mut line = format!("{LINE_PREFIX} event={event}");
        for (key, value) in fields {
            line.push(' ');
            line.push_str(key);
            line.push('=');
            line.push_str(&sanitize(value));
        }
        if let Err(err) = handle.emit(line.into_bytes()) {
            debug!("secure-connect telemetry dropped: {err:#}");
        }
    }

    pub fn session_started(
        &self,
        session_id: &str,
        device_id: &str,
        profile: &TunnelProfile,
        policy_apply_ms: u64,
    ) {
        self.emit(
            "session_started",
            &[
                ("session_id", session_id.to_string()),
                ("device_id", device_id.to_string()),
                ("profile_version", profile.profile_version.to_string()),
                ("gateway_endpoint", profile.gateway_endpoint.clone()),
                ("allowed_cidrs", profile.allowed_cidrs.join(",")),
                ("policy_apply_ms", policy_apply_ms.to_string()),
            ],
        );
    }

    pub fn state_changed(
        &self,
        session_id: &str,
        from: SessionState,
        to: SessionState,
        reason: &str,
    ) {
        self.emit(
            "state_changed",
            &[
                ("session_id", session_id.to_string()),
                ("from_state", format!("{from:?}").to_lowercase()),
                ("to_state", format!("{to:?}").to_lowercase()),
                ("reason", reason.to_string()),
            ],
        );
    }

    pub fn command_applied(&self, session_id: &str, action: &str, nonce: u64, apply_ms: u64) {
        self.emit(
            "command_applied",
            &[
                ("session_id", session_id.to_string()),
                ("action", action.to_string()),
                ("command_nonce", nonce.to_string()),
                ("apply_ms", apply_ms.to_string()),
            ],
        );
    }

    /// Access revocation is the SLO-critical path, so its latency is reported
    /// separately from ordinary policy application.
    pub fn access_revoked(
        &self,
        session_id: &str,
        state: SessionState,
        revoke_ms: u64,
        kill_switch_ms: u64,
        reason: &str,
    ) {
        self.emit(
            "access_revoked",
            &[
                ("session_id", session_id.to_string()),
                ("to_state", format!("{state:?}").to_lowercase()),
                ("revoke_ms", revoke_ms.to_string()),
                ("kill_switch_ms", kill_switch_ms.to_string()),
                ("reason", reason.to_string()),
            ],
        );
    }

    pub fn posture_reported(&self, session_id: &str, posture: &PostureFacts) {
        self.emit(
            "posture_reported",
            &[
                ("session_id", session_id.to_string()),
                ("agent_version", posture.agent_version.clone()),
                ("kernel_version", posture.kernel_version.clone()),
                ("os_version", posture.os_version.clone()),
                (
                    "disk_encryption_detected",
                    posture.disk_encryption_detected.to_string(),
                ),
                ("probe_health", posture.probe_health.clone()),
                ("probes_attached", posture.probes_attached.join(",")),
                (
                    "sensor_events_captured",
                    posture.sensor_events_captured.to_string(),
                ),
                (
                    "sensor_events_dropped",
                    posture.sensor_events_dropped.to_string(),
                ),
                ("rule_count", posture.rule_count.to_string()),
                (
                    "kernel_verified",
                    posture.kernel_verified_posture.to_string(),
                ),
            ],
        );
    }

    pub fn tunnel_metrics(
        &self,
        session_id: &str,
        bytes_tx: u64,
        bytes_rx: u64,
        last_handshake_unix: u64,
        reconnect_count: u64,
    ) {
        self.emit(
            "tunnel_metrics",
            &[
                ("session_id", session_id.to_string()),
                ("bytes_tx", bytes_tx.to_string()),
                ("bytes_rx", bytes_rx.to_string()),
                ("last_handshake_unix", last_handshake_unix.to_string()),
                ("reconnect_count", reconnect_count.to_string()),
            ],
        );
    }

    pub fn session_failed(&self, error: &str) {
        self.emit("session_failed", &[("error", error.to_string())]);
    }
}

/// Collapse anything the whitespace-delimited line parser would mis-split.
fn sanitize(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_whitespace() || c == '=' { '_' } else { c })
        .collect();
    if cleaned.is_empty() {
        return "none".to_string();
    }
    cleaned.chars().take(256).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_values_that_would_break_field_splitting() {
        assert_eq!(sanitize("control plane unavailable"), "control_plane_unavailable");
        assert_eq!(sanitize("a=b"), "a_b");
        assert_eq!(sanitize(""), "none");
        assert_eq!(sanitize(&"x".repeat(400)).len(), 256);
    }

    #[test]
    fn emitting_without_a_sender_is_a_no_op() {
        // Secure Connect must run even when ingest transport is disabled.
        Telemetry::new(None).session_failed("boom");
    }
}
