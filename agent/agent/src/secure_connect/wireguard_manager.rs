use super::TunnelProfile;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

pub(crate) trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<String>;
}

#[derive(Default)]
pub(crate) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("start {program}"))?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .context("command stdin unavailable")?
                .write_all(input)
                .with_context(|| format!("write {program} stdin"))?;
        }
        let output = child
            .wait_with_output()
            .with_context(|| format!("wait for {program}"))?;
        if !output.status.success() {
            bail!(
                "{} {} failed: {}",
                program,
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

pub(crate) struct PrivateKey(pub(crate) String);

impl PrivateKey {
    fn as_pipe_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateKey([redacted])")
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Best-effort zeroing of the owned allocation before release.
        unsafe { self.0.as_bytes_mut().fill(0) };
    }
}

#[derive(Debug)]
pub(crate) struct KeyPair {
    pub private: PrivateKey,
    pub public: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WireGuardMetrics {
    pub last_handshake_unix: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
}

pub(crate) struct WireGuardManager {
    interface: String,
    default_mtu: u16,
    runner: Arc<dyn CommandRunner>,
    applied_routes: Vec<String>,
    /// Gateway peer currently configured on the interface. `wg set` adds peers
    /// but never replaces them, so a gateway migration or gateway-side key
    /// rotation would silently leave the old peer installed.
    applied_peer: Option<String>,
}

impl WireGuardManager {
    pub(crate) fn new(interface: String, default_mtu: u16, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            interface,
            default_mtu,
            runner,
            applied_routes: Vec::new(),
            applied_peer: None,
        }
    }

    pub fn generate_keypair(&self) -> Result<KeyPair> {
        let mut raw = [0u8; 32];
        rand::rng().fill_bytes(&mut raw);
        raw[0] &= 248;
        raw[31] &= 127;
        raw[31] |= 64;
        let private = PrivateKey(STANDARD.encode(raw));
        raw.fill(0);
        let public = self
            .runner
            .run("wg", &["pubkey"], Some(&private.as_pipe_bytes()))?;
        validate_key("derived public key", &public)?;
        Ok(KeyPair { private, public })
    }

    pub fn apply(&mut self, profile: &TunnelProfile, private_key: &PrivateKey) -> Result<()> {
        validate_profile(profile)?;
        if self
            .runner
            .run("ip", &["link", "show", "dev", &self.interface], None)
            .is_err()
        {
            self.runner.run(
                "ip",
                &["link", "add", "dev", &self.interface, "type", "wireguard"],
                None,
            )?;
        }

        // Drop the previous gateway before installing the new one so a migrated
        // session cannot keep routing to the gateway it was moved off.
        if let Some(previous) = self.applied_peer.take() {
            if previous != profile.gateway_public_key {
                let _ = self.runner.run(
                    "wg",
                    &["set", &self.interface, "peer", &previous, "remove"],
                    None,
                );
            }
        }

        let allowed = profile.allowed_cidrs.join(",");
        let keepalive = profile.persistent_keepalive_secs.max(1).to_string();
        self.runner.run(
            "wg",
            &[
                "set",
                &self.interface,
                "private-key",
                "/dev/stdin",
                "peer",
                &profile.gateway_public_key,
                "endpoint",
                &profile.gateway_endpoint,
                "allowed-ips",
                &allowed,
                "persistent-keepalive",
                &keepalive,
            ],
            Some(&private_key.as_pipe_bytes()),
        )?;
        self.applied_peer = Some(profile.gateway_public_key.clone());
        self.runner.run(
            "ip",
            &[
                "address",
                "replace",
                &profile.interface_address,
                "dev",
                &self.interface,
            ],
            None,
        )?;
        let mtu = profile.mtu.unwrap_or(self.default_mtu).to_string();
        self.runner.run(
            "ip",
            &["link", "set", "dev", &self.interface, "mtu", &mtu, "up"],
            None,
        )?;

        let old_routes = std::mem::take(&mut self.applied_routes);
        for route in &profile.allowed_cidrs {
            self.runner.run(
                "ip",
                &["route", "replace", route, "dev", &self.interface],
                None,
            )?;
            self.applied_routes.push(route.clone());
        }
        for route in old_routes {
            if !self.applied_routes.contains(&route) {
                let _ = self.runner.run(
                    "ip",
                    &["route", "del", &route, "dev", &self.interface],
                    None,
                );
            }
        }
        Ok(())
    }

    pub fn metrics(&self) -> WireGuardMetrics {
        let Ok(dump) = self
            .runner
            .run("wg", &["show", &self.interface, "dump"], None)
        else {
            return WireGuardMetrics::default();
        };
        let Some(peer) = dump.lines().nth(1) else {
            return WireGuardMetrics::default();
        };
        let fields = peer.split_whitespace().collect::<Vec<_>>();
        WireGuardMetrics {
            last_handshake_unix: fields
                .get(4)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            bytes_rx: fields
                .get(5)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            bytes_tx: fields
                .get(6)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        }
    }

    pub fn teardown(&mut self) {
        self.applied_peer = None;
        for route in std::mem::take(&mut self.applied_routes) {
            let _ = self.runner.run(
                "ip",
                &["route", "del", &route, "dev", &self.interface],
                None,
            );
        }
        let _ = self
            .runner
            .run("ip", &["link", "del", "dev", &self.interface], None);
    }
}

fn validate_profile(profile: &TunnelProfile) -> Result<()> {
    validate_key("gateway public key", &profile.gateway_public_key)?;
    validate_cidr(&profile.interface_address)?;
    if profile.allowed_cidrs.is_empty() {
        bail!("Secure Connect profile has no allowed CIDRs");
    }
    for cidr in profile
        .allowed_cidrs
        .iter()
        .chain(profile.bypass_cidrs.iter())
    {
        validate_cidr(cidr)?;
    }
    validate_endpoint(&profile.gateway_endpoint)?;
    for server in &profile.dns_servers {
        server
            .parse::<std::net::IpAddr>()
            .with_context(|| format!("invalid Secure Connect DNS server '{server}'"))?;
    }
    Ok(())
}

fn validate_key(label: &str, key: &str) -> Result<()> {
    let decoded = STANDARD
        .decode(key.trim())
        .with_context(|| format!("invalid base64 {label}"))?;
    if decoded.len() != 32 {
        bail!("{label} must decode to 32 bytes");
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<()> {
    let (address, prefix) = cidr
        .split_once('/')
        .with_context(|| format!("CIDR '{cidr}' is missing a prefix"))?;
    let address = address
        .parse::<std::net::IpAddr>()
        .with_context(|| format!("invalid CIDR address '{cidr}'"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid CIDR prefix '{cidr}'"))?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("CIDR prefix out of range '{cidr}'");
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .with_context(|| format!("gateway endpoint '{endpoint}' must include a port"))?;
    if host.trim_matches(['[', ']']).is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        bail!("invalid gateway endpoint host '{endpoint}'");
    }
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid gateway endpoint port '{endpoint}'"))?;
    if port == 0 {
        bail!("gateway endpoint port cannot be zero");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<String>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
            self.calls.lock().unwrap().push(format!(
                "{} {} stdin={}",
                program,
                args.join(" "),
                stdin.is_some()
            ));
            if program == "wg" && args == ["pubkey"] {
                return Ok(STANDARD.encode([7u8; 32]));
            }
            if program == "ip" && args.starts_with(&["link", "show"]) {
                bail!("missing");
            }
            Ok(String::new())
        }
    }

    fn profile() -> TunnelProfile {
        TunnelProfile {
            interface_address: "10.40.0.2/32".to_string(),
            gateway_public_key: STANDARD.encode([9u8; 32]),
            gateway_endpoint: "192.0.2.4:51820".to_string(),
            allowed_cidrs: vec!["10.0.0.0/8".to_string()],
            bypass_cidrs: vec!["192.0.2.4/32".to_string()],
            dns_servers: vec!["10.0.0.53".to_string()],
            profile_version: 1,
            expires_at_unix: 0,
            persistent_keepalive_secs: 25,
            mtu: None,
        }
    }

    #[test]
    fn applies_profile_without_putting_private_key_in_arguments() {
        let runner = Arc::new(RecordingRunner::default());
        let mut manager = WireGuardManager::new("olopa0".to_string(), 1420, runner.clone());
        let private = PrivateKey(STANDARD.encode([3u8; 32]));
        manager.apply(&profile(), &private).expect("apply profile");
        let calls = runner.calls.lock().unwrap().join("\n");
        assert!(calls.contains("private-key /dev/stdin"));
        assert!(!calls.contains(&private.0));
        assert!(calls.contains("ip route replace 10.0.0.0/8 dev olopa0"));
    }

    #[test]
    fn migrating_to_a_new_gateway_removes_the_previous_peer() {
        let runner = Arc::new(RecordingRunner::default());
        let mut manager = WireGuardManager::new("olopa0".to_string(), 1420, runner.clone());
        let private = PrivateKey(STANDARD.encode([3u8; 32]));

        let first = profile();
        manager.apply(&first, &private).expect("apply first gateway");

        let mut migrated = profile();
        migrated.gateway_public_key = STANDARD.encode([11u8; 32]);
        migrated.gateway_endpoint = "192.0.2.9:51820".to_string();
        migrated.interface_address = "10.41.0.5/32".to_string();
        manager.apply(&migrated, &private).expect("apply new gateway");

        let calls = runner.calls.lock().unwrap().join("\n");
        assert!(calls.contains(&format!(
            "wg set olopa0 peer {} remove",
            first.gateway_public_key
        )));
        assert!(calls.contains(&format!("peer {}", migrated.gateway_public_key)));
    }

    #[test]
    fn reapplying_the_same_gateway_does_not_remove_its_peer() {
        let runner = Arc::new(RecordingRunner::default());
        let mut manager = WireGuardManager::new("olopa0".to_string(), 1420, runner.clone());
        let private = PrivateKey(STANDARD.encode([3u8; 32]));

        manager.apply(&profile(), &private).expect("apply");
        manager.apply(&profile(), &private).expect("reapply");

        let calls = runner.calls.lock().unwrap().join("\n");
        assert!(!calls.contains("remove"));
    }

    #[test]
    fn rejects_invalid_control_plane_profile_before_commands() {
        let runner = Arc::new(RecordingRunner::default());
        let mut manager = WireGuardManager::new("olopa0".to_string(), 1420, runner.clone());
        let private = PrivateKey(STANDARD.encode([3u8; 32]));
        let mut invalid = profile();
        invalid.allowed_cidrs = vec!["not-a-cidr".to_string()];
        assert!(manager.apply(&invalid, &private).is_err());
        assert!(runner.calls.lock().unwrap().is_empty());
    }
}
