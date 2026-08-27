//! eBPF program and map inventory.
//!
//! The agent owns its probes and does not expose an introspection socket, so
//! Command reads the kernel's own view through `bpftool -j` and correlates it
//! with the probe list the agent publishes in its status snapshot. When
//! `bpftool` is missing or unprivileged, that is reported plainly rather than
//! rendering an empty table that looks like "no probes attached".

use serde::Serialize;
use serde_json::Value;
use std::process::Command as Proc;

#[derive(Debug, Clone, Serialize)]
pub struct BpfProgram {
    pub id: u64,
    pub name: String,
    pub kind: String,
    pub tag: String,
    pub run_time_ns: u64,
    pub run_count: u64,
    pub map_ids: Vec<u64>,
    /// True when the agent's status snapshot also lists this probe group.
    pub attributed_to_agent: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BpfMap {
    pub id: u64,
    pub name: String,
    pub kind: String,
    pub max_entries: u64,
    pub bytes_key: u64,
    pub bytes_value: u64,
    /// Kernel-reported memory footprint, when available.
    pub bytes_memlock: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BpfInventory {
    pub available: bool,
    /// Why the inventory is empty, when it is.
    pub note: Option<String>,
    pub programs: Vec<BpfProgram>,
    pub maps: Vec<BpfMap>,
    /// Probe groups the agent says it attached, from the status snapshot.
    pub agent_probes: Vec<String>,
}

fn bpftool(args: &[&str]) -> Result<Value, String> {
    let output = Proc::new("bpftool")
        .args(args)
        .output()
        .map_err(|err| format!("bpftool unavailable: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("bpftool {} failed", args.join(" "))
        } else {
            stderr
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|err| format!("bpftool JSON parse failed: {err}"))
}

fn u64_at(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn str_at(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Collect the kernel's program and map inventory.
///
/// `agent_probes` comes from the agent status snapshot and is used only to mark
/// which kernel programs plausibly belong to Olopa — the kernel does not record
/// ownership, so this is a name-prefix heuristic, not an authoritative link.
pub fn inventory(agent_probes: Vec<String>) -> BpfInventory {
    let mut inventory = BpfInventory {
        available: false,
        note: None,
        programs: Vec::new(),
        maps: Vec::new(),
        agent_probes,
    };

    let programs = match bpftool(&["-j", "prog", "show"]) {
        Ok(value) => value,
        Err(err) => {
            inventory.note = Some(format!(
                "{err}. Install bpftool and run Command with CAP_BPF (or as root) to inspect kernel programs."
            ));
            return inventory;
        }
    };
    inventory.available = true;

    if let Some(items) = programs.as_array() {
        for item in items {
            let name = str_at(item, "name");
            let attributed = inventory
                .agent_probes
                .iter()
                .any(|probe| name.contains(probe.as_str()) || probe.contains(name.as_str()))
                || name.starts_with("olopa");
            inventory.programs.push(BpfProgram {
                id: u64_at(item, "id"),
                name,
                kind: str_at(item, "type"),
                tag: str_at(item, "tag"),
                run_time_ns: u64_at(item, "run_time_ns"),
                run_count: u64_at(item, "run_cnt"),
                map_ids: item
                    .get("map_ids")
                    .and_then(Value::as_array)
                    .map(|ids| ids.iter().filter_map(Value::as_u64).collect())
                    .unwrap_or_default(),
                attributed_to_agent: attributed,
            });
        }
    }

    match bpftool(&["-j", "map", "show"]) {
        Ok(maps) => {
            if let Some(items) = maps.as_array() {
                for item in items {
                    inventory.maps.push(BpfMap {
                        id: u64_at(item, "id"),
                        name: str_at(item, "name"),
                        kind: str_at(item, "type"),
                        max_entries: u64_at(item, "max_entries"),
                        bytes_key: u64_at(item, "bytes_key"),
                        bytes_value: u64_at(item, "bytes_value"),
                        bytes_memlock: u64_at(item, "bytes_memlock"),
                    });
                }
            }
        }
        Err(err) => inventory.note = Some(format!("map inventory unavailable: {err}")),
    }

    if inventory.programs.is_empty() && inventory.note.is_none() {
        inventory.note =
            Some("bpftool returned no programs — the kernel has none loaded, or they are not visible to this user.".into());
    }
    inventory
}
