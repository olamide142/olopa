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
