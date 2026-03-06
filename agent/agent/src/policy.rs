use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::Ebpf;
use serde::Deserialize;

/// Policy fields map directly to eBPF policy maps.
#[derive(Debug, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub blocked_ipv4: Vec<String>,
    #[serde(default)]
    pub blocked_ports: Vec<u16>,
    #[serde(default)]
    pub blocked_tgids: Vec<u32>,
    #[serde(default)]
    pub allow_tgids: Vec<u32>,
}

pub fn load_policy(bpf: &mut Ebpf, policy_path: &Path) -> Result<()> {
    if !policy_path.exists() {
        eprintln!(
            "policy file not found at {} - continuing with empty policy",
            policy_path.to_string_lossy()
        );
        return Ok(());
    }

    let raw = std::fs::read_to_string(policy_path)
        .with_context(|| format!("failed to read policy file {}", policy_path.to_string_lossy()))?;
    let policy: Policy = serde_json::from_str(&raw).context("failed parsing policy JSON")?;

    {
        let mut blocked_ipv4: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("BLOCKED_IPV4")
                .context("missing BLOCKED_IPV4 map")?,
        )?;
        for ip in &policy.blocked_ipv4 {
            if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
                let key = u32::from_be_bytes(parsed.octets());
                blocked_ipv4
                    .insert(key, 1, 0)
                    .with_context(|| format!("failed to insert blocked ipv4 {ip}"))?;
            } else {
                eprintln!("invalid blocked_ipv4 entry skipped: {ip}");
            }
        }
    }

    {
        let mut blocked_ports: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("BLOCKED_PORTS")
                .context("missing BLOCKED_PORTS map")?,
        )?;
        for port in &policy.blocked_ports {
            let key = u32::from(port.to_be());
            blocked_ports
                .insert(key, 1, 0)
                .with_context(|| format!("failed to insert blocked port {port}"))?;
        }
    }

    {
        let mut blocked_tgids: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("BLOCKED_TGIDS")
                .context("missing BLOCKED_TGIDS map")?,
        )?;
        for tgid in &policy.blocked_tgids {
            blocked_tgids
                .insert(*tgid, 1, 0)
                .with_context(|| format!("failed to insert blocked tgid {tgid}"))?;
        }
    }

    {
        let mut allow_tgids: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("ALLOW_TGIDS")
                .context("missing ALLOW_TGIDS map")?,
        )?;
        for tgid in &policy.allow_tgids {
            allow_tgids
                .insert(*tgid, 1, 0)
                .with_context(|| format!("failed to insert allowed tgid {tgid}"))?;
        }
    }

    println!(
        "loaded policy: {} blocked IPs, {} blocked ports, {} blocked tgids, {} allowed tgids",
        policy.blocked_ipv4.len(),
        policy.blocked_ports.len(),
        policy.blocked_tgids.len(),
        policy.allow_tgids.len()
    );
    Ok(())
}

