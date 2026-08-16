use super::wireguard_manager::CommandRunner;
use super::TunnelProfile;
use anyhow::{bail, Result};
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct PolicyApplier {
    interface: String,
    kill_switch: bool,
    runner: Arc<dyn CommandRunner>,
}

impl PolicyApplier {
    pub fn new(interface: String, kill_switch: bool, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            interface,
            kill_switch,
            runner,
        }
    }

    pub fn apply(&self, profile: &TunnelProfile) -> Result<u64> {
        let started = Instant::now();
        if profile.dns_servers.is_empty() {
            let _ = self
                .runner
                .run("resolvectl", &["revert", &self.interface], None);
        } else {
            let mut args = vec!["dns", self.interface.as_str()];
            args.extend(profile.dns_servers.iter().map(String::as_str));
            self.runner.run("resolvectl", &args, None)?;
            self.runner
                .run("resolvectl", &["domain", &self.interface, "~."], None)?;
        }
        if self.kill_switch {
            let script = nft_script(&self.interface, profile, false)?;
            self.runner
                .run("nft", &["-f", "-"], Some(script.as_bytes()))?;
        }
        Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
    }

    pub fn quarantine(&self, profile: Option<&TunnelProfile>) -> Result<u64> {
        if !self.kill_switch {
            return Ok(0);
        }
        let started = Instant::now();
        let script = nft_script(&self.interface, profile.unwrap_or(&empty_profile()), true)?;
        self.runner
            .run("nft", &["-f", "-"], Some(script.as_bytes()))?;
        Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
    }
}

fn empty_profile() -> TunnelProfile {
    TunnelProfile {
        interface_address: "0.0.0.0/32".to_string(),
        gateway_public_key: String::new(),
        gateway_endpoint: "0.0.0.0:1".to_string(),
        allowed_cidrs: Vec::new(),
        bypass_cidrs: Vec::new(),
        dns_servers: Vec::new(),
        profile_version: 0,
        expires_at_unix: 0,
        persistent_keepalive_secs: 0,
        mtu: None,
    }
}

fn nft_script(interface: &str, profile: &TunnelProfile, quarantine: bool) -> Result<String> {
    if interface.contains('"') || interface.contains('\n') {
        bail!("invalid interface in kill-switch policy");
    }
    let mut bypass = profile.bypass_cidrs.clone();
    if let Some((host, _)) = profile.gateway_endpoint.rsplit_once(':') {
        let host = host.trim_matches(['[', ']']);
        if let Ok(address) = host.parse::<std::net::IpAddr>() {
            bypass.push(format!(
                "{address}/{}",
                if address.is_ipv4() { 32 } else { 128 }
            ));
        }
    }
    for cidr in &bypass {
        if !safe_cidr(cidr) {
            bail!("invalid bypass CIDR in kill-switch policy: {cidr}");
        }
    }

    let mut rules = String::from(
        "destroy table inet olopa_sc\n\
         table inet olopa_sc {\n\
           chain output {\n\
             type filter hook output priority -150; policy accept;\n\
             oifname \"lo\" accept\n\
             ct state established,related accept\n",
    );
    if !quarantine {
        rules.push_str(&format!("    oifname \"{interface}\" accept\n"));
    }
    for cidr in bypass {
        let family = if cidr.contains(':') { "ip6" } else { "ip" };
        rules.push_str(&format!("    {family} daddr {cidr} accept\n"));
    }
    rules.push_str("    counter drop\n  }\n}\n");
    Ok(rules)
}

fn safe_cidr(cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    #[test]
    fn quarantine_policy_does_not_allow_tunnel_interface() {
        let profile = TunnelProfile {
            interface_address: "10.0.0.2/32".to_string(),
            gateway_public_key: STANDARD.encode([1u8; 32]),
            gateway_endpoint: "192.0.2.8:51820".to_string(),
            allowed_cidrs: vec!["10.0.0.0/8".to_string()],
            bypass_cidrs: vec!["198.51.100.0/24".to_string()],
            dns_servers: Vec::new(),
            profile_version: 1,
            expires_at_unix: 0,
            persistent_keepalive_secs: 25,
            mtu: None,
        };
        let healthy = nft_script("olopa0", &profile, false).unwrap();
        let quarantined = nft_script("olopa0", &profile, true).unwrap();
        assert!(healthy.contains("oifname \"olopa0\" accept"));
        assert!(!quarantined.contains("oifname \"olopa0\" accept"));
        assert!(quarantined.contains("192.0.2.8/32 accept"));
    }
}
