//! Threat-intel IOC store for the central correlation engine.
//!
//! Mirrors `agent/agent/src/intel_store.rs`: Redis is the shared source of
//! truth written by `app/intel_sync`, and each evaluator (the agent, and
//! this one) keeps its own in-memory snapshot refreshed on a poll interval
//! so a rule evaluation on the hot path never does a network round trip.
//!
//! Before this module existed, `x in org.threat_intel.*` compiled to a call
//! to the `intel.domains(feed)` stdlib callable (see
//! `oilc/src/oil_stdlib/src/callables.oil`), but `CorrelationEngine::eval_call`
//! had no arm for it and silently fell through to `Value::Null` - every rule
//! using threat-intel membership (e.g. `dns_c2_domain_lookup`) could compile
//! and load without error but could never match.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tracing::{info, warn};

const REDIS_SETS_KEY: &str = "intel:sets";
const REDIS_GENERATION_KEY: &str = "intel:generation";
const POLL_INTERVAL_S: u64 = 30;

#[derive(Default)]
struct Inner {
    string_sets: HashMap<String, HashSet<String>>,
    ip_sets: HashMap<String, HashSet<u32>>,
}

/// Thread-safe threat-intel snapshot, refreshed from Redis in the background.
#[derive(Clone, Default)]
pub struct ThreatIntelStore {
    inner: Arc<RwLock<Inner>>,
}

impl ThreatIntelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot a named set's members. Returns an empty vec for a set that
    /// doesn't exist (not yet synced, or Redis unreachable) - membership
    /// checks against it evaluate as "no match" rather than erroring, same
    /// contract as the agent-side store.
    pub fn string_set_items(&self, set_name: &str) -> Vec<String> {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .string_sets
            .get(set_name)
            .cloned()
            .map(|set| set.into_iter().collect())
            .unwrap_or_default()
    }

    /// Membership check for a string-type set (domains, hashes). `value`
    /// should already be lowercased by the caller, matching how sets are
    /// stored.
    pub fn contains_str(&self, set_name: &str, value: &str) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .string_sets
            .get(set_name)
            .is_some_and(|s| s.contains(value))
    }

    /// Membership check for an IP-type set (host-endian u32, matching how
    /// `Value::Ip` is represented elsewhere in this crate).
    pub fn contains_ip(&self, set_name: &str, ip: u32) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .ip_sets
            .get(set_name)
            .is_some_and(|s| s.contains(&ip))
    }

    /// Spawn the Redis polling loop on a dedicated OS thread. Uses the
    /// synchronous `redis` client rather than tying this into the axum/tokio
    /// runtime - the poll cadence is slow (30s) and this must never block
    /// request handling if Redis is briefly unreachable.
    pub fn spawn_redis_refresh(&self, redis_url: String) {
        let store = self.clone();
        std::thread::Builder::new()
            .name("threat-intel-redis-watcher".into())
            .spawn(move || store.redis_watcher_loop(redis_url))
            .ok();
    }

    fn redis_watcher_loop(&self, redis_url: String) {
        let client = match redis::Client::open(redis_url.as_str()) {
            Ok(c) => c,
            Err(e) => {
                warn!(%redis_url, error = %e, "threat-intel: invalid redis url, refresh disabled");
                return;
            }
        };

        let mut last_generation: Option<String> = None;

        loop {
            match self.poll_once(&client, &last_generation) {
                Ok(Some(generation)) => last_generation = Some(generation),
                Ok(None) => {}
                Err(e) => warn!(error = %e, "threat-intel: redis refresh failed, keeping previous snapshot"),
            }
            std::thread::sleep(Duration::from_secs(POLL_INTERVAL_S));
        }
    }

    fn poll_once(
        &self,
        client: &redis::Client,
        last_generation: &Option<String>,
    ) -> Result<Option<String>, String> {
        use redis::Commands;

        let mut conn = client
            .get_connection()
            .map_err(|e| format!("redis connect failed: {e}"))?;

        let generation: Option<String> = conn
            .get(REDIS_GENERATION_KEY)
            .map_err(|e| format!("GET {REDIS_GENERATION_KEY} failed: {e}"))?;
        if generation.is_some() && &generation == last_generation {
            return Ok(generation);
        }

        let names: Vec<String> = conn
            .smembers(REDIS_SETS_KEY)
            .map_err(|e| format!("SMEMBERS {REDIS_SETS_KEY} failed: {e}"))?;

        let mut string_sets: HashMap<String, HashSet<String>> = HashMap::new();
        let mut ip_sets: HashMap<String, HashSet<u32>> = HashMap::new();
        for name in &names {
            let set_type: String = conn
                .hget(format!("intel:meta:{name}"), "type")
                .unwrap_or_else(|_: redis::RedisError| "string".to_string());
            let items: HashSet<String> = conn
                .smembers(format!("intel:members:{name}"))
                .map_err(|e| format!("SMEMBERS intel:members:{name} failed: {e}"))?;

            if set_type == "ip" {
                ip_sets.insert(
                    name.clone(),
                    items
                        .iter()
                        .filter_map(|s| s.split('/').next().and_then(|h| h.trim().parse::<std::net::Ipv4Addr>().ok()))
                        .map(u32::from)
                        .collect(),
                );
            } else {
                string_sets.insert(name.clone(), items.into_iter().map(|s| s.to_lowercase()).collect());
            }
        }

        let (string_count, ip_count) = (string_sets.len(), ip_sets.len());
        {
            let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
            guard.string_sets = string_sets;
            guard.ip_sets = ip_sets;
        }
        info!(generation = ?generation, string_sets = string_count, ip_sets = ip_count, "threat-intel redis-refreshed");

        Ok(generation)
    }
}

#[cfg(test)]
pub fn install_test_string_set(store: &ThreatIntelStore, set_name: &str, items: &[&str]) {
    let mut guard = store.inner.write().unwrap();
    guard.string_sets.insert(
        set_name.to_string(),
        items.iter().map(|s| s.to_ascii_lowercase()).collect(),
    );
}
