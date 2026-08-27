//! Centralized novelty, rate, and baseline evaluation state.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Default)]
pub struct HostBaseline {
    pub domains: HashSet<String>,
    pub ips: HashSet<String>,
    pub processes: HashSet<String>,
    pub users: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UserBaseline {
    pub countries: HashSet<String>,
    pub hosts: HashSet<String>,
    pub geos: HashSet<String>,
    pub login_hours: HashSet<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct BaselineProfiles {
    pub hosts: HashMap<String, HostBaseline>,
    pub users: HashMap<String, UserBaseline>,
    pub images: HashMap<String, HashSet<String>>,
}

type RareKey = (String, String, String); // (tenant, rule, value)
type UnusualKey = (String, String, String, String); // (tenant, rule, entity, value)
type RateKey = (String, String, String, u64); // (tenant, rule, value, window_ns)

const DEFAULT_STATE_CAPACITY: usize = 200_000;
const NUM_SHARDS: usize = 16;

#[derive(Default)]
struct StateShard {
    rare_counts: HashMap<RareKey, u64>,
    unusual_counts: HashMap<UnusualKey, u64>,
    rate_observations: HashMap<RateKey, VecDeque<u64>>,
    order: VecDeque<StateKey>,
}

enum StateKey {
    Rare(RareKey),
    Unusual(UnusualKey),
    Rate(RateKey),
}

/// Sharded, high-performance central callable evaluation state.
#[derive(Clone)]
pub struct CentralCallableState {
    shards: Arc<Vec<Mutex<StateShard>>>,
    baselines: Arc<RwLock<BaselineProfiles>>,
    max_capacity_per_shard: usize,
}

impl Default for CentralCallableState {
    fn default() -> Self {
        Self::new(DEFAULT_STATE_CAPACITY)
    }
}

impl CentralCallableState {
    pub fn new(capacity: usize) -> Self {
        let per_shard = (capacity / NUM_SHARDS).max(100);
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(Mutex::new(StateShard::default()));
        }
        Self {
            shards: Arc::new(shards),
            baselines: Arc::new(RwLock::new(BaselineProfiles::default())),
            max_capacity_per_shard: per_shard,
        }
    }

    fn shard_index(&self, key: &str) -> usize {
        let mut hash = 5381u64;
        for b in key.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u64);
        }
        (hash as usize) % NUM_SHARDS
    }

    pub fn eval_rare(
        &self,
        tenant_id: &str,
        rule_id: &str,
        value: &str,
        threshold: u64,
    ) -> bool {
        let shard_idx = self.shard_index(value);
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let key = (tenant_id.to_string(), rule_id.to_string(), value.to_string());
        let count = shard.rare_counts.entry(key.clone()).or_insert(0);
        *count = count.saturating_add(1);
        let is_rare = *count <= threshold;

        if *count == 1 {
            shard.order.push_back(StateKey::Rare(key));
            self.maybe_evict_shard(&mut shard);
        }
        is_rare
    }

    pub fn eval_unusual(
        &self,
        tenant_id: &str,
        rule_id: &str,
        entity: &str,
        value: &str,
    ) -> bool {
        let shard_idx = self.shard_index(entity);
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let key = (
            tenant_id.to_string(),
            rule_id.to_string(),
            entity.to_string(),
            value.to_string(),
        );
        let count = shard.unusual_counts.entry(key.clone()).or_insert(0);
        *count = count.saturating_add(1);
        let is_unusual = *count == 1;

        if is_unusual {
            shard.order.push_back(StateKey::Unusual(key));
            self.maybe_evict_shard(&mut shard);
        }
        is_unusual
    }

    pub fn eval_rate(
        &self,
        tenant_id: &str,
        rule_id: &str,
        value: &str,
        window_ns: u64,
        now_ns: u64,
    ) -> u64 {
        let shard_idx = self.shard_index(value);
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let key = (tenant_id.to_string(), rule_id.to_string(), value.to_string(), window_ns);
        let is_new = !shard.rate_observations.contains_key(&key);

        let count = {
            let observations = shard.rate_observations.entry(key.clone()).or_default();
            let cutoff = now_ns.saturating_sub(window_ns);

            while let Some(front) = observations.front() {
                if *front < cutoff {
                    observations.pop_front();
                } else {
                    break;
                }
            }
            observations.push_back(now_ns);
            observations.len() as u64
        };

        if is_new {
            shard.order.push_back(StateKey::Rate(key));
            self.maybe_evict_shard(&mut shard);
        }
        count
    }

    pub fn check_host_domain_baseline(&self, host_id: &str, domain: &str) -> bool {
        let lock = self.baselines.read().unwrap_or_else(|p| p.into_inner());
        if let Some(host) = lock.hosts.get(host_id) {
            host.domains.contains(domain)
        } else {
            true // Open baseline by default if not set
        }
    }

    pub fn check_host_process_baseline(&self, host_id: &str, proc: &str) -> bool {
        let lock = self.baselines.read().unwrap_or_else(|p| p.into_inner());
        if let Some(host) = lock.hosts.get(host_id) {
            host.processes.contains(proc)
        } else {
            true
        }
    }

    pub fn set_host_baseline(&self, host_id: &str, baseline: HostBaseline) {
        let mut lock = self.baselines.write().unwrap_or_else(|p| p.into_inner());
        lock.hosts.insert(host_id.to_string(), baseline);
    }

    fn maybe_evict_shard(&self, shard: &mut StateShard) {
        while shard.rare_counts.len() + shard.unusual_counts.len() > self.max_capacity_per_shard {
            if let Some(evicted) = shard.order.pop_front() {
                match evicted {
                    StateKey::Rare(k) => {
                        shard.rare_counts.remove(&k);
                    }
                    StateKey::Unusual(k) => {
                        shard.unusual_counts.remove(&k);
                    }
                    StateKey::Rate(k) => {
                        shard.rate_observations.remove(&k);
                    }
                }
            } else {
                break;
            }
        }
    }
}
