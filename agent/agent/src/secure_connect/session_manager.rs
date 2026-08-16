use super::config::SecureConnectConfig;
use super::health;
use super::orchestrator_client::{
    EnrollmentRequest, HeartbeatRequest, OrchestratorClient, RekeyRequest, SessionStartRequest,
};
use super::policy_applier::PolicyApplier;
use super::posture::{self, PostureFacts};
use super::telemetry::Telemetry;
use super::wireguard_manager::{KeyPair, SystemCommandRunner, WireGuardManager};
use super::{ControlAction, SessionState, TunnelProfile};
use anyhow::{bail, Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Default, Deserialize, Serialize)]
struct PersistedState {
    version: u16,
    tenant_id: String,
    host_id: String,
    device_id: String,
}

struct ActiveSession {
    device_id: String,
    session_id: String,
    state: SessionState,
    key_pair: KeyPair,
    profile: TunnelProfile,
    last_command_nonce: u64,
}

/// Why a session ended.
///
/// Only `Terminated` is terminal: per the access state machine, a terminated
/// session requires re-enrollment, while a quarantined endpoint keeps the kill
/// switch applied and waits for the control plane to grant a new session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionOutcome {
    Terminated,
    Quarantined,
    ProfileExpired,
}

/// Emit posture roughly every five minutes at the default heartbeat cadence;
/// tunnel counters are cheap enough to send on every beat.
const POSTURE_REPORT_EVERY_N_HEARTBEATS: u32 = 20;

pub async fn run(config: SecureConnectConfig, telemetry: Telemetry) -> Result<()> {
    health::initialize(config.status_path.clone(), config.interface.clone());
    let client = OrchestratorClient::new(&config)?;
    let runner = Arc::new(SystemCommandRunner);
    let mut wireguard = WireGuardManager::new(config.interface.clone(), config.mtu, runner.clone());
    let policy = PolicyApplier::new(config.interface.clone(), config.kill_switch, runner);
    let mut retry = config.retry_min;

    loop {
        match bootstrap_and_run(&config, &client, &mut wireguard, &policy, &telemetry).await {
            Ok(SessionOutcome::Terminated) => {
                info!("secure-connect access terminated; re-enrollment is required");
                return Ok(());
            }
            Ok(outcome) => {
                // Recoverable ends: the kill switch stays applied while the
                // endpoint waits for the control plane to grant a new session.
                warn!("secure-connect session ended ({outcome:?}); awaiting a new session");
                let cooldown = match outcome {
                    SessionOutcome::Quarantined => config.retry_max,
                    _ => config.retry_min,
                };
                retry = config.retry_min;
                tokio::time::sleep(cooldown).await;
            }
            Err(err) => {
                warn!("secure-connect session failed: {err:#}");
                telemetry.session_failed(&err.to_string());
                wireguard.teardown();
                let kill_ms = policy.quarantine(None).unwrap_or(0);
                health::update(|status| {
                    status.state = SessionState::Degraded;
                    status.reconnect_count = status.reconnect_count.saturating_add(1);
                    status.kill_switch_apply_ms = kill_ms;
                    status.last_error = Some(err.to_string());
                });
                tokio::time::sleep(retry).await;
                retry = retry.saturating_mul(2).min(config.retry_max);
            }
        }
    }
}

async fn bootstrap_and_run(
    config: &SecureConnectConfig,
    client: &OrchestratorClient,
    wireguard: &mut WireGuardManager,
    policy: &PolicyApplier,
    telemetry: &Telemetry,
) -> Result<SessionOutcome> {
    let posture = posture::collect();
    health::update(|status| {
        status.state = SessionState::Enrolling;
        status.posture_updated_unix = posture.collected_at_unix;
        status.last_error = None;
    });

    let key_pair = wireguard
        .generate_keypair()
        .context("generate WireGuard keypair")?;
    let device_id = ensure_enrolled(config, client, &key_pair, &posture).await?;
    health::update(|status| status.device_id = Some(device_id.clone()));

    health::update(|status| status.state = SessionState::Connecting);
    let started = client
        .start_session(&SessionStartRequest {
            tenant_id: &config.tenant_id,
            device_id: &device_id,
            host_id: &config.host_id,
            wireguard_public_key: &key_pair.public,
            posture: &posture,
        })
        .await
        .context("start Secure Connect session")?;
    let state = started.state.unwrap_or(SessionState::Healthy);
    if matches!(state, SessionState::Quarantined | SessionState::Terminated) {
        bail!("control plane refused tunnel with state {state:?}");
    }

    let apply_started = Instant::now();
    wireguard
        .apply(&started.profile, &key_pair.private)
        .context("apply WireGuard session")?;
    let policy_ms = match policy.apply(&started.profile) {
        Ok(ms) => ms,
        Err(err) => {
            wireguard.teardown();
            return Err(err).context("apply Secure Connect route/DNS/kill-switch policy");
        }
    };
    let total_apply_ms = u64::try_from(apply_started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let mut active = ActiveSession {
        device_id,
        session_id: started.session_id,
        state,
        key_pair,
        profile: started.profile,
        last_command_nonce: started.command_nonce,
    };
    health::update(|status| {
        status.state = active.state;
        status.session_id = Some(active.session_id.clone());
        status.profile_version = active.profile.profile_version;
        status.policy_apply_ms = policy_ms.max(total_apply_ms);
        status.last_error = None;
    });
    info!(
        "secure-connect tunnel active session={} profile_version={}",
        active.session_id, active.profile.profile_version
    );
    telemetry.session_started(
        &active.session_id,
        &active.device_id,
        &active.profile,
        policy_ms.max(total_apply_ms),
    );
    telemetry.posture_reported(&active.session_id, &posture);

    heartbeat_loop(config, client, wireguard, policy, telemetry, &mut active).await
}

async fn ensure_enrolled(
    config: &SecureConnectConfig,
    client: &OrchestratorClient,
    key_pair: &KeyPair,
    posture: &PostureFacts,
) -> Result<String> {
    if let Some(state) = load_state(&config.state_path) {
        if state.version == 1
            && state.tenant_id == config.tenant_id
            && state.host_id == config.host_id
            && !state.device_id.is_empty()
        {
            return Ok(state.device_id);
        }
    }

    let token = config
        .enrollment_token
        .as_deref()
        .context("OLOPA_SC_ENROLLMENT_TOKEN is required for first enrollment")?;
    let fingerprint = device_fingerprint(&config.host_id);
    let enrolled = client
        .enroll(&EnrollmentRequest {
            enrollment_token: token,
            tenant_id: &config.tenant_id,
            host_id: &config.host_id,
            user_id: config.user_id.as_deref(),
            device_fingerprint: &fingerprint,
            wireguard_public_key: &key_pair.public,
            posture,
        })
        .await
        .context("enroll Secure Connect device")?;
    if enrolled.device_id.trim().is_empty() {
        bail!("control plane returned an empty Secure Connect device id");
    }
    save_state(
        &config.state_path,
        &PersistedState {
            version: 1,
            tenant_id: config.tenant_id.clone(),
            host_id: config.host_id.clone(),
            device_id: enrolled.device_id.clone(),
        },
    )?;
    Ok(enrolled.device_id)
}

async fn heartbeat_loop(
    config: &SecureConnectConfig,
    client: &OrchestratorClient,
    wireguard: &mut WireGuardManager,
    policy: &PolicyApplier,
    telemetry: &Telemetry,
    active: &mut ActiveSession,
) -> Result<SessionOutcome> {
    let mut last_control_success = Instant::now();
    let mut heartbeat_retry = config.retry_min;
    let mut heartbeats: u32 = 0;

    loop {
        tokio::time::sleep(config.heartbeat_interval).await;
        if active.profile.expires_at_unix != 0
            && posture::now_unix() >= active.profile.expires_at_unix
        {
            let started = Instant::now();
            let kill_ms = policy.quarantine(Some(&active.profile))?;
            wireguard.teardown();
            let previous = active.state;
            active.state = SessionState::Quarantined;
            health::update(|status| {
                status.state = SessionState::Quarantined;
                status.kill_switch_apply_ms = kill_ms;
                status.last_error = Some("Secure Connect profile expired".to_string());
            });
            telemetry.state_changed(
                &active.session_id,
                previous,
                SessionState::Quarantined,
                "profile_expired",
            );
            telemetry.access_revoked(
                &active.session_id,
                SessionState::Quarantined,
                elapsed_ms(started),
                kill_ms,
                "profile_expired",
            );
            return Ok(SessionOutcome::ProfileExpired);
        }
        heartbeats = heartbeats.saturating_add(1);
        let posture = posture::collect();
        let metrics = wireguard.metrics();
        let response = client
            .heartbeat(
                &active.session_id,
                &HeartbeatRequest {
                    tenant_id: &config.tenant_id,
                    device_id: &active.device_id,
                    session_id: &active.session_id,
                    state: active.state,
                    posture: &posture,
                    profile_version: active.profile.profile_version,
                    last_command_nonce: active.last_command_nonce,
                    last_handshake_unix: metrics.last_handshake_unix,
                    bytes_tx: metrics.bytes_tx,
                    bytes_rx: metrics.bytes_rx,
                },
            )
            .await;

        let response = match response {
            Ok(response) => {
                last_control_success = Instant::now();
                heartbeat_retry = config.retry_min;
                response
            }
            Err(err) => {
                health::update(|status| {
                    status.state = SessionState::Degraded;
                    status.last_error = Some(err.to_string());
                });
                if last_control_success.elapsed() >= config.policy_ttl {
                    let kill_ms = policy.quarantine(Some(&active.profile))?;
                    wireguard.teardown();
                    health::update(|status| {
                        status.state = SessionState::Quarantined;
                        status.kill_switch_apply_ms = kill_ms;
                    });
                    bail!("control plane unavailable beyond policy TTL");
                }
                tokio::time::sleep(heartbeat_retry).await;
                heartbeat_retry = heartbeat_retry.saturating_mul(2).min(config.retry_max);
                continue;
            }
        };

        if response.command_nonce != 0 {
            if response.command_nonce <= active.last_command_nonce {
                bail!(
                    "replayed Secure Connect command nonce {} (last {})",
                    response.command_nonce,
                    active.last_command_nonce
                );
            }
            active.last_command_nonce = response.command_nonce;
        } else if response.action != ControlAction::None || response.desired_state.is_some() {
            bail!("state-changing Secure Connect response omitted command nonce");
        }

        let desired_state = response.desired_state;
        if let Some(desired) = desired_state {
            let previous = active.state;
            apply_state_transition(active, desired)?;
            if previous != desired {
                telemetry.state_changed(&active.session_id, previous, desired, "control_plane");
            }
        }
        if response.action == ControlAction::RefreshProfile && response.profile.is_none() {
            bail!("refresh_profile command omitted replacement profile");
        }
        if let Some(profile) = response.profile {
            let started = Instant::now();
            wireguard.apply(&profile, &active.key_pair.private)?;
            let policy_ms = policy.apply(&profile)?;
            active.profile = profile;
            health::update(|status| status.policy_apply_ms = policy_ms);
            telemetry.command_applied(
                &active.session_id,
                "refresh_profile",
                response.command_nonce,
                elapsed_ms(started),
            );
        }

        let effective_action = match (response.action, desired_state) {
            (ControlAction::None, Some(SessionState::Restricted)) => ControlAction::Restrict,
            (ControlAction::None, Some(SessionState::Quarantined)) => ControlAction::Quarantine,
            (ControlAction::None, Some(SessionState::Terminated)) => ControlAction::Terminate,
            (action, _) => action,
        };
        match effective_action {
            ControlAction::None | ControlAction::RefreshProfile => {}
            ControlAction::Rekey => {
                let started = Instant::now();
                let next = wireguard.generate_keypair()?;
                let response = client
                    .rekey(
                        &active.session_id,
                        &RekeyRequest {
                            tenant_id: &config.tenant_id,
                            device_id: &active.device_id,
                            wireguard_public_key: &next.public,
                            last_command_nonce: active.last_command_nonce,
                        },
                    )
                    .await?;
                if response.command_nonce <= active.last_command_nonce {
                    bail!("rekey acknowledgement did not advance command nonce");
                }
                wireguard.apply(&response.profile, &next.private)?;
                policy.apply(&response.profile)?;
                active.key_pair = next;
                active.profile = response.profile;
                active.last_command_nonce = response.command_nonce;
                telemetry.command_applied(
                    &active.session_id,
                    "rekey",
                    active.last_command_nonce,
                    elapsed_ms(started),
                );
            }
            ControlAction::Restrict => apply_state_transition(active, SessionState::Restricted)?,
            ControlAction::Quarantine => {
                let started = Instant::now();
                let kill_ms = policy.quarantine(Some(&active.profile))?;
                wireguard.teardown();
                active.state = SessionState::Quarantined;
                let revoke_ms = elapsed_ms(started);
                health::update(|status| {
                    status.state = SessionState::Quarantined;
                    status.kill_switch_apply_ms = kill_ms;
                    status.revoke_apply_ms = revoke_ms;
                });
                telemetry.access_revoked(
                    &active.session_id,
                    SessionState::Quarantined,
                    revoke_ms,
                    kill_ms,
                    "control_plane_quarantine",
                );
                return Ok(SessionOutcome::Quarantined);
            }
            ControlAction::Terminate => {
                let started = Instant::now();
                let kill_ms = policy.quarantine(Some(&active.profile))?;
                wireguard.teardown();
                active.state = SessionState::Terminated;
                let revoke_ms = elapsed_ms(started);
                health::update(|status| {
                    status.state = SessionState::Terminated;
                    status.kill_switch_apply_ms = kill_ms;
                    status.revoke_apply_ms = revoke_ms;
                });
                telemetry.access_revoked(
                    &active.session_id,
                    SessionState::Terminated,
                    revoke_ms,
                    kill_ms,
                    "control_plane_terminate",
                );
                return Ok(SessionOutcome::Terminated);
            }
        }

        let reconnects = health::update_and_read(|status| {
            status.state = active.state;
            status.profile_version = active.profile.profile_version;
            status.last_heartbeat_unix = posture.collected_at_unix;
            status.posture_updated_unix = posture.collected_at_unix;
            status.last_handshake_unix = metrics.last_handshake_unix;
            status.bytes_tx = metrics.bytes_tx;
            status.bytes_rx = metrics.bytes_rx;
            status.last_error = None;
        });

        telemetry.tunnel_metrics(
            &active.session_id,
            metrics.bytes_tx,
            metrics.bytes_rx,
            metrics.last_handshake_unix,
            reconnects,
        );
        if heartbeats % POSTURE_REPORT_EVERY_N_HEARTBEATS == 0 {
            telemetry.posture_reported(&active.session_id, &posture);
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn apply_state_transition(active: &mut ActiveSession, desired: SessionState) -> Result<()> {
    if active.state == SessionState::Terminated && desired != SessionState::Terminated {
        bail!("terminated Secure Connect sessions cannot transition");
    }
    if desired.restriction_rank() < active.state.restriction_rank()
        && !(active.state == SessionState::Elevated && desired == SessionState::Healthy)
    {
        bail!(
            "control response attempted an unconfirmed relaxation {:?} -> {:?}",
            active.state,
            desired
        );
    }
    active.state = desired;
    Ok(())
}

fn load_state(path: &Path) -> Option<PersistedState> {
    fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

fn save_state(path: &Path, state: &PersistedState) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec_pretty(state)?)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
    }
    Ok(())
}

fn device_fingerprint(fallback: &str) -> String {
    fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::wireguard_manager::PrivateKey;
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    fn active(state: SessionState) -> ActiveSession {
        ActiveSession {
            device_id: "device".to_string(),
            session_id: "session".to_string(),
            state,
            key_pair: KeyPair {
                private: PrivateKey(STANDARD.encode([1u8; 32])),
                public: STANDARD.encode([2u8; 32]),
            },
            profile: TunnelProfile {
                interface_address: "10.0.0.2/32".to_string(),
                gateway_public_key: STANDARD.encode([3u8; 32]),
                gateway_endpoint: "192.0.2.1:51820".to_string(),
                allowed_cidrs: vec!["10.0.0.0/8".to_string()],
                bypass_cidrs: Vec::new(),
                dns_servers: Vec::new(),
                profile_version: 1,
                expires_at_unix: 0,
                persistent_keepalive_secs: 25,
                mtu: None,
            },
            last_command_nonce: 1,
        }
    }

    #[test]
    fn restrictive_transitions_are_automatic_but_relaxation_is_rejected() {
        let mut session = active(SessionState::Healthy);
        apply_state_transition(&mut session, SessionState::Restricted).unwrap();
        assert_eq!(session.state, SessionState::Restricted);
        assert!(apply_state_transition(&mut session, SessionState::Healthy).is_err());
    }

    #[test]
    fn terminated_state_is_terminal() {
        let mut session = active(SessionState::Terminated);
        assert!(apply_state_transition(&mut session, SessionState::Healthy).is_err());
    }
}
