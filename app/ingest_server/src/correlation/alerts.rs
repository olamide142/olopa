//! Correlated alert structures and in-memory ring buffer.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

use super::ir::RuntimeAction;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelatedEventSnippet {
    pub kind: String,
    pub host_id: String,
    pub ts_unix_ms: u64,
    pub summary: String,
    #[serde(default)]
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelatedAlert {
    pub alert_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub tenant_id: String,
    pub host_id: String,
    pub message: String,
    pub score: i32,
    pub actions: Vec<RuntimeAction>,
    pub matched_events: Vec<CorrelatedEventSnippet>,
    #[serde(default)]
    pub emitted_facts: Vec<String>,
    pub timestamp_unix_ms: u64,
}

impl CorrelatedAlert {
    /// Derive a content-addressed alert id.
    ///
    /// The id covers the rule and the exact set of events that satisfied it,
    /// and nothing about when evaluation happened. A rule firing on the same
    /// events produces the same id in the hot path and on a later replay out of
    /// a persistent store, which is what lets the two be deduplicated against
    /// each other rather than double-reported.
    pub fn derive_id<I>(rule_id: &str, tenant_id: &str, event_identities: I) -> String
    where
        I: IntoIterator<Item = String>,
    {
        let mut identities: Vec<String> = event_identities.into_iter().collect();
        // Multi-source matches arrive in map order; sort so alias iteration
        // order cannot change the id.
        identities.sort_unstable();

        let mut hash = FNV_OFFSET_BASIS;
        hash = fnv1a64_update(hash, rule_id.as_bytes());
        hash = fnv1a64_update(hash, b"\x1f");
        hash = fnv1a64_update(hash, tenant_id.as_bytes());
        for identity in &identities {
            hash = fnv1a64_update(hash, b"\x1e");
            hash = fnv1a64_update(hash, identity.as_bytes());
        }

        format!("alt_{rule_id}_{hash:016x}")
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64.
///
/// Written out rather than using `DefaultHasher`, whose output is explicitly not
/// stable across releases - these ids are compared across processes, restarts,
/// and replay runs, so the hash has to be fixed by this code.
fn fnv1a64_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

const DEFAULT_ALERTS_CAPACITY: usize = 5_000;

#[derive(Clone)]
pub struct AlertRingBuffer {
    buffer: Arc<RwLock<VecDeque<CorrelatedAlert>>>,
    capacity: usize,
}

impl Default for AlertRingBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_ALERTS_CAPACITY)
    }
}

impl AlertRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(capacity))),
            capacity: capacity.max(10),
        }
    }

    pub fn push(&self, alert: CorrelatedAlert) {
        let mut lock = self.buffer.write().unwrap_or_else(|p| p.into_inner());
        if lock.len() >= self.capacity {
            lock.pop_front();
        }
        lock.push_back(alert);
    }

    pub fn recent(
        &self,
        tenant_id: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        limit: usize,
    ) -> Vec<CorrelatedAlert> {
        let lock = self.buffer.read().unwrap_or_else(|p| p.into_inner());
        let cap = limit.clamp(1, 1_000);

        lock.iter()
            .rev()
            .filter(|a| {
                if let Some(t) = tenant_id {
                    if a.tenant_id != t {
                        return false;
                    }
                }
                if let Some(s) = severity {
                    if !a.severity.eq_ignore_ascii_case(s) {
                        return false;
                    }
                }
                if let Some(r) = rule_id {
                    if a.rule_id != r {
                        return false;
                    }
                }
                true
            })
            .take(cap)
            .cloned()
            .collect()
    }

    pub fn total_count(&self) -> usize {
        let lock = self.buffer.read().unwrap_or_else(|p| p.into_inner());
        lock.len()
    }
}
