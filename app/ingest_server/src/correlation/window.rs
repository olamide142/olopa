//! High-performance sharded sliding window buffer for multi-source correlation.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::event::OwnedEvent;

const WINDOW_SHARDS: usize = 32;
const MAX_EVENTS_PER_BUCKET: usize = 500;
const MAX_TOTAL_BUCKETS_PER_SHARD: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowBucketKey {
    pub tenant_id: String,
    pub rule_id: String,
    pub source_alias: String,
    pub join_key: String,
}

#[derive(Default)]
struct WindowShard {
    buckets: HashMap<WindowBucketKey, VecDeque<OwnedEvent>>,
    bucket_lru: VecDeque<WindowBucketKey>,
}

/// Sharded in-memory sliding window manager for multi-source event correlation.
#[derive(Clone)]
pub struct SlidingWindowIndex {
    shards: Arc<Vec<Mutex<WindowShard>>>,
    max_buckets_per_shard: usize,
}

impl Default for SlidingWindowIndex {
    fn default() -> Self {
        Self::new(MAX_TOTAL_BUCKETS_PER_SHARD)
    }
}

impl SlidingWindowIndex {
    pub fn new(max_buckets_per_shard: usize) -> Self {
        let mut shards = Vec::with_capacity(WINDOW_SHARDS);
        for _ in 0..WINDOW_SHARDS {
            shards.push(Mutex::new(WindowShard::default()));
        }
        Self {
            shards: Arc::new(shards),
            max_buckets_per_shard,
        }
    }

    fn shard_for(&self, key: &WindowBucketKey) -> usize {
        let mut hash = 5381u64;
        for b in key.tenant_id.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u64);
        }
        for b in key.rule_id.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u64);
        }
        for b in key.join_key.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u64);
        }
        (hash as usize) % WINDOW_SHARDS
    }

    /// Insert an event into the sliding window.
    pub fn insert_event(
        &self,
        tenant_id: &str,
        rule_id: &str,
        source_alias: &str,
        join_key: &str,
        event: OwnedEvent,
        window_ms: u64,
    ) {
        let key = WindowBucketKey {
            tenant_id: tenant_id.to_string(),
            rule_id: rule_id.to_string(),
            source_alias: source_alias.to_string(),
            join_key: join_key.to_string(),
        };

        let shard_idx = self.shard_for(&key);
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let now_ms = event.ts_unix_ms;
        let cutoff_ms = now_ms.saturating_sub(window_ms);

        if !shard.buckets.contains_key(&key) {
            shard.bucket_lru.push_back(key.clone());
        }
        let bucket = shard.buckets.entry(key).or_default();

        // Prune expired events in this bucket
        while let Some(front) = bucket.front() {
            if front.ts_unix_ms < cutoff_ms {
                bucket.pop_front();
            } else {
                break;
            }
        }

        // Keep bucket bounded
        if bucket.len() >= MAX_EVENTS_PER_BUCKET {
            bucket.pop_front();
        }

        bucket.push_back(event);

        // Evict empty or oldest buckets if shard is over capacity
        if shard.buckets.len() > self.max_buckets_per_shard {
            if let Some(oldest_key) = shard.bucket_lru.pop_front() {
                shard.buckets.remove(&oldest_key);
            }
        }
    }

    /// Find candidate events in the window matching the join key within the time window.
    pub fn find_candidate_events(
        &self,
        tenant_id: &str,
        rule_id: &str,
        source_alias: &str,
        join_key: &str,
        target_ts_ms: u64,
        window_ms: u64,
    ) -> Vec<OwnedEvent> {
        let key = WindowBucketKey {
            tenant_id: tenant_id.to_string(),
            rule_id: rule_id.to_string(),
            source_alias: source_alias.to_string(),
            join_key: join_key.to_string(),
        };

        let shard_idx = self.shard_for(&key);
        let shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let min_ts = target_ts_ms.saturating_sub(window_ms);
        let max_ts = target_ts_ms.saturating_add(window_ms);

        let mut results = Vec::new();
        if let Some(bucket) = shard.buckets.get(&key) {
            for event in bucket.iter() {
                if event.ts_unix_ms >= min_ts && event.ts_unix_ms <= max_ts {
                    results.push(event.clone());
                }
            }
        }
        results
    }

    /// Periodic background eviction of expired events across all shards.
    pub fn prune_all_expired(&self, max_age_ms: u64) -> usize {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let cutoff_ms = now_ms.saturating_sub(max_age_ms);

        let mut total_pruned = 0;
        for shard_mutex in self.shards.iter() {
            let mut shard = shard_mutex.lock().unwrap_or_else(|p| p.into_inner());
            shard.buckets.retain(|_, bucket| {
                let before = bucket.len();
                bucket.retain(|e| e.ts_unix_ms >= cutoff_ms);
                total_pruned += before.saturating_sub(bucket.len());
                !bucket.is_empty()
            });
        }
        total_pruned
    }

    /// Approximate total active events in sliding windows.
    pub fn active_event_count(&self) -> usize {
        let mut count = 0;
        for shard_mutex in self.shards.iter() {
            let shard = shard_mutex.lock().unwrap_or_else(|p| p.into_inner());
            for bucket in shard.buckets.values() {
                count += bucket.len();
            }
        }
        count
    }
}
