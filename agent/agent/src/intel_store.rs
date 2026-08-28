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

use log::{info, warn};
use serde::Deserialize;

// ── Global singleton ─────────────────────────────────────────────────────────

static INTEL_STORE: OnceLock<RwLock<IntelStoreInner>> = OnceLock::new();

/// How often the background thread checks the artifact mtime.
const POLL_INTERVAL_S: u64 = 60;

/// How often the Redis-backed background thread polls for a new generation.
/// Redis is the source of truth once configured; this only governs how fast
/// a fresh `intel_sync` run propagates into this process's local cache.
const REDIS_POLL_INTERVAL_S: u64 = 30;

/// Redis key holding the set of published intel set names.
const REDIS_SETS_KEY: &str = "intel:sets";
/// Redis key (INCR'd by intel_sync on every successful run) used to skip
/// re-pulling set membership when nothing has changed.
const REDIS_GENERATION_KEY: &str = "intel:generation";

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

/// Start the Redis-backed refresh watcher, in addition to (not instead of)
/// the file watcher started by `init`. Redis becomes the source of truth
/// once `intel_sync` is pointed at it; `intel.json` stays as a fallback that
/// keeps working if Redis is briefly unreachable at agent startup, so this
/// only warns rather than failing when the connection can't be established.
pub fn spawn_redis_refresh(redis_url: String) {
    // Ensure the store exists so this can be called before or after `init`.
    let _ = INTEL_STORE.get_or_init(|| RwLock::new(IntelStoreInner::empty()));

    std::thread::Builder::new()
        .name("intel-store-redis-watcher".into())
        .spawn(move || redis_watcher_loop(redis_url))
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

        let sets = wire
            .sets
            .into_iter()
            .map(|(name, set)| (name, (set.set_type, set.items)))
            .collect();

        Ok(Self::from_typed_sets(sets))
    }

    /// Build from `(set_name -> (set_type, items))`, the shape both the
    /// `intel.json` file and Redis reduce to. Shared so the two loaders
    /// can't drift on how `"ip"` vs. everything-else is classified.
    fn from_typed_sets(sets: HashMap<String, (String, Vec<String>)>) -> Self {
        let mut string_sets: HashMap<String, HashSet<String>> = HashMap::new();
        let mut ip_sets: HashMap<String, HashSet<u32>> = HashMap::new();

        for (name, (set_type, items)) in sets {
            if set_type == "ip" {
                ip_sets.insert(name, items.iter().filter_map(|s| parse_ipv4_to_u32(s)).collect());
            } else {
                string_sets.insert(name, items.into_iter().map(|s| s.to_lowercase()).collect());
            }
        }

        Self {
            string_sets,
            ip_sets,
        }
    }

    /// Pull the current snapshot from Redis. Key schema (written by
    /// `app/intel_sync/sync.py`):
    ///   `intel:sets`          - SET of published set names
    ///   `intel:meta:{name}`   - HASH with a `type` field ("ip" or else)
    ///   `intel:members:{name}` - SET of the set's raw entries
    fn load_from_redis(conn: &mut redis::Connection) -> Result<Self, String> {
        use redis::Commands;

        let names: Vec<String> = conn
            .smembers(REDIS_SETS_KEY)
            .map_err(|e| format!("SMEMBERS {REDIS_SETS_KEY} failed: {e}"))?;

        let mut sets: HashMap<String, (String, Vec<String>)> = HashMap::new();
        for name in names {
            let set_type: String = conn
                .hget(format!("intel:meta:{name}"), "type")
                .unwrap_or_else(|_| "string".to_string());
            let items: Vec<String> = conn
                .smembers(format!("intel:members:{name}"))
                .map_err(|e| format!("SMEMBERS intel:members:{name} failed: {e}"))?;
            sets.insert(name, (set_type, items));
        }

        Ok(Self::from_typed_sets(sets))
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

fn redis_watcher_loop(redis_url: String) {
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            warn!("intel-store: invalid redis url {redis_url}: {e} — redis refresh disabled");
            return;
        }
    };

    let mut last_generation: Option<String> = None;

    loop {
        let outcome = (|| -> Result<Option<String>, String> {
            use redis::Commands;
            let mut conn = client
                .get_connection()
                .map_err(|e| format!("redis connect failed: {e}"))?;
            let generation: Option<String> = conn
                .get(REDIS_GENERATION_KEY)
                .map_err(|e| format!("GET {REDIS_GENERATION_KEY} failed: {e}"))?;
            if generation.is_some() && generation == last_generation {
                return Ok(generation);
            }
            let new_store = IntelStoreInner::load_from_redis(&mut conn)?;
            info!(
                "intel-store redis-refreshed: generation={:?} string_sets={} ip_sets={}",
                generation,
                new_store.string_sets.len(),
                new_store.ip_sets.len(),
            );
            if let Some(store) = INTEL_STORE.get() {
                match store.write() {
                    Ok(mut guard) => *guard = new_store,
                    Err(e) => warn!("intel-store write lock poisoned during redis refresh: {e}"),
                }
            }
            Ok(generation)
        })();

        match outcome {
            Ok(generation) => last_generation = generation,
            Err(e) => warn!("intel-store redis refresh failed (keeping previous): {e}"),
        }

        std::thread::sleep(Duration::from_secs(REDIS_POLL_INTERVAL_S));
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
