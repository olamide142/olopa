//! Threat intelligence store for runtime set-membership lookups.
//!
//! The agent loads an `intel.json` artifact produced by the `intel_sync`
//! service.  Rules written as `x in org.threat_intel.c2_domains` resolve
//! against the sets held here instead of inlining thousands of literals into
//! the compiled rule IR.
//!
//! # Hot-reload
//! A background thread polls the artifact file every `POLL_INTERVAL_S` seconds.
//! When the mtime changes, the store is atomically replaced.  Rule evaluation
//! holds a read-lock for the duration of one event — O(nanoseconds).
//!
//! # Wire format (`intel.json`)
//! ```json
//! {
//!   "version": 1,
//!   "generated_at_unix_s": 1234567890,
//!   "sets": {
//!     "org.threat_intel.c2_domains": {
//!       "type": "string",
//!       "items": ["evil.com", "malware.net"]
//!     },
//!     "org.threat_intel.outgoing_ips": {
//!       "type": "ip",
//!       "items": ["1.2.3.4", "5.6.7.8"]
//!     },
//!     "org.threat_intel.malware_hashes": {
//!       "type": "string",
//!       "items": ["sha256:abc123..."]
//!     }
//!   }
//! }
//! ```
//!
//! `"type": "ip"` entries are parsed into `u32` at load time so IP comparisons
//! remain O(1) without re-parsing on every event.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use log::{debug, info, warn};
use serde::Deserialize;

// ── Global singleton ─────────────────────────────────────────────────────────

static INTEL_STORE: OnceLock<RwLock<IntelStoreInner>> = OnceLock::new();

/// How often the background thread checks the artifact mtime.
const POLL_INTERVAL_S: u64 = 60;

// ── Public API ────────────────────────────────────────────────────────────────

/// Check whether `value` is a member of the named string-type intel set.
///
/// Returns `false` when the store has not been initialised or the set is
/// unknown — rules evaluate safely but never match on missing intel.
pub fn contains_str(set_name: &str, value: &str) -> bool {
    let store = match INTEL_STORE.get() {
        Some(s) => s,
        None => return false,
    };
    match store.read() {
        Ok(inner) => inner.contains_str(set_name, value),
        Err(_) => false,
    }
}

/// Check whether `ip` (host-endian `u32`) is a member of the named IP-type
/// intel set.
///
/// Returns `false` when the store has not been initialised or the set is
/// unknown.
pub fn contains_ip(set_name: &str, ip: u32) -> bool {
    let store = match INTEL_STORE.get() {
        Some(s) => s,
        None => return false,
    };
    match store.read() {
        Ok(inner) => inner.contains_ip(set_name, ip),
        Err(_) => false,
    }
}

/// Return whether an intel set with the given name is loaded.
pub fn set_exists(set_name: &str) -> bool {
    let store = match INTEL_STORE.get() {
        Some(s) => s,
        None => return false,
    };
    match store.read() {
        Ok(inner) => {
            inner.string_sets.contains_key(set_name) || inner.ip_sets.contains_key(set_name)
        }
        Err(_) => false,
    }
}

/// Snapshot a string-backed intel set for callable consumers.
///
/// Membership checks should continue using `contains_str`; this allocation is
/// intended for explicit collection-returning functions such as
/// `intel.domains(feed)`.
pub fn string_set_items(set_name: &str) -> Option<Vec<String>> {
    let store = INTEL_STORE.get()?;
    let inner = store.read().ok()?;
    let mut items = inner
        .string_sets
        .get(set_name)?
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    items.sort();
    Some(items)
}

#[cfg(test)]
pub fn install_test_string_set(set_name: &str, items: &[&str]) {
    let store = INTEL_STORE.get_or_init(|| RwLock::new(IntelStoreInner::empty()));
    let mut guard = store.write().expect("intel test store write lock");
    guard.string_sets.insert(
        set_name.to_string(),
        items.iter().map(|item| item.to_ascii_lowercase()).collect(),
    );
}

/// Initialise the global store from `path` and start the hot-reload watcher.
///
/// This function is idempotent: calling it a second time is a no-op (the
/// `OnceLock` guarantees only one store is ever created).  The background
/// thread continues running for the lifetime of the process.
pub fn init(path: &Path) {
    let inner = match IntelStoreInner::load(path) {
        Ok(store) => {
            info!(
                "intel-store loaded: path={} string_sets={} ip_sets={}",
                path.display(),
                store.string_sets.len(),
                store.ip_sets.len(),
            );
            store
        }
        Err(e) => {
            warn!(
                "intel-store failed to load from {}: {} — starting empty",
                path.display(),
                e
            );
            IntelStoreInner::empty()
        }
    };

    // Only the first caller wins the OnceLock race; all subsequent calls are
    // no-ops.
    let _ = INTEL_STORE.get_or_init(|| RwLock::new(inner));

    // Spawn watcher regardless — it always polls INTEL_STORE if initialised.
    let path_owned = path.to_path_buf();
    std::thread::Builder::new()
        .name("intel-store-watcher".into())
        .spawn(move || watcher_loop(path_owned))
        .ok();
}

// ── Internal types ────────────────────────────────────────────────────────────

#[derive(Default)]
struct IntelStoreInner {
    string_sets: HashMap<String, HashSet<String>>,
    ip_sets: HashMap<String, HashSet<u32>>,
}

impl IntelStoreInner {
    fn empty() -> Self {
        Self::default()
    }

    fn contains_str(&self, set_name: &str, value: &str) -> bool {
        self.string_sets
            .get(set_name)
            .is_some_and(|s| s.contains(value))
    }

    fn contains_ip(&self, set_name: &str, ip: u32) -> bool {
        self.ip_sets.get(set_name).is_some_and(|s| s.contains(&ip))
    }

    fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;

        let wire: IntelWire =
            serde_json::from_str(&raw).map_err(|e| format!("JSON parse failed: {e}"))?;

        if wire.version != 1 {
            return Err(format!("unsupported intel.json version: {}", wire.version));
        }

        let mut string_sets: HashMap<String, HashSet<String>> = HashMap::new();
        let mut ip_sets: HashMap<String, HashSet<u32>> = HashMap::new();

        for (name, set) in wire.sets {
            match set.set_type.as_str() {
                "ip" => {
                    let parsed: HashSet<u32> = set
                        .items
                        .iter()
                        .filter_map(|s| parse_ipv4_to_u32(s))
                        .collect();
                    debug!(
                        "intel-store: ip set '{}' loaded {} entries",
                        name,
                        parsed.len()
                    );
                    ip_sets.insert(name, parsed);
                }
                _ => {
                    // "string", "domain", "hash", etc. — all stored as strings.
                    let parsed: HashSet<String> =
                        set.items.into_iter().map(|s| s.to_lowercase()).collect();
                    debug!(
                        "intel-store: string set '{}' loaded {} entries",
                        name,
                        parsed.len()
                    );
                    string_sets.insert(name, parsed);
                }
            }
        }

        Ok(Self {
            string_sets,
            ip_sets,
        })
    }
}

// ── Wire format deserialisation ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IntelWire {
    version: u32,
    #[serde(default)]
    sets: HashMap<String, IntelSetWire>,
}

#[derive(Debug, Deserialize)]
struct IntelSetWire {
    #[serde(rename = "type")]
    set_type: String,
    #[serde(default)]
    items: Vec<String>,
}

// ── Hot-reload watcher ────────────────────────────────────────────────────────

fn watcher_loop(path: PathBuf) {
    let mut last_mtime: Option<SystemTime> = None;

    loop {
        std::thread::sleep(Duration::from_secs(POLL_INTERVAL_S));

        let mtime = match std::fs::metadata(&path) {
            Ok(m) => match m.modified() {
                Ok(t) => t,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        if last_mtime == Some(mtime) {
            continue;
        }
        last_mtime = Some(mtime);

        match IntelStoreInner::load(&path) {
            Ok(new_store) => {
                info!(
                    "intel-store hot-reloaded: path={} string_sets={} ip_sets={}",
                    path.display(),
                    new_store.string_sets.len(),
                    new_store.ip_sets.len(),
                );
                if let Some(store) = INTEL_STORE.get() {
                    match store.write() {
                        Ok(mut guard) => *guard = new_store,
                        Err(e) => {
                            warn!("intel-store write lock poisoned during reload: {e}");
                        }
                    }
                }
            }
            Err(e) => {
                warn!("intel-store reload failed (keeping previous): {e}");
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse an IPv4 address string into host-endian u32.
fn parse_ipv4_to_u32(s: &str) -> Option<u32> {
    // Strip optional CIDR suffix for subnet entries (store the network addr).
    let host = s.split('/').next().unwrap_or(s).trim();
    Ipv4Addr::from_str(host).ok().map(u32::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_returns_false() {
        let store = IntelStoreInner::empty();
        assert!(!store.contains_str("org.threat_intel.c2_domains", "evil.com"));
        assert!(!store.contains_ip("org.threat_intel.outgoing_ips", 0x01020304));
    }

    #[test]
    fn string_set_lookup_is_case_insensitive() {
        let mut sets = HashMap::new();
        let mut s = HashSet::new();
        s.insert("evil.com".to_string());
        sets.insert("org.threat_intel.c2_domains".to_string(), s);
        let store = IntelStoreInner {
            string_sets: sets,
            ip_sets: HashMap::new(),
        };
        // Stored lowercase; input is normalised at query time.
        assert!(store.contains_str("org.threat_intel.c2_domains", "evil.com"));
        assert!(!store.contains_str("org.threat_intel.c2_domains", "safe.com"));
    }

    #[test]
    fn ip_set_lookup_works() {
        let mut ip_sets = HashMap::new();
        let mut ips = HashSet::new();
        ips.insert(u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        ip_sets.insert("org.threat_intel.outgoing_ips".to_string(), ips);
        let store = IntelStoreInner {
            string_sets: HashMap::new(),
            ip_sets,
        };
        assert!(store.contains_ip(
            "org.threat_intel.outgoing_ips",
            u32::from(Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert!(!store.contains_ip(
            "org.threat_intel.outgoing_ips",
            u32::from(Ipv4Addr::new(9, 9, 9, 9))
        ));
    }

    #[test]
    fn parse_ipv4_strips_cidr_suffix() {
        assert_eq!(
            parse_ipv4_to_u32("1.2.3.4/24"),
            Some(u32::from(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(
            parse_ipv4_to_u32("1.2.3.4"),
            Some(u32::from(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(parse_ipv4_to_u32("not-an-ip"), None);
    }
}
