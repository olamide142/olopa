//! Central fact and intelligence store.
//!
//! Stores facts emitted by rules (`emit fact host.compromised(host.id) expires 8h`)
//! across agents and tenants with automatic TTL expiration.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CentralFact {
    pub fact_name: String,
    pub args: Vec<String>,
    pub tenant_id: String,
    pub host_id: String,
    pub emitted_at_unix_ms: u64,
    pub expires_at_unix_ms: Option<u64>,
}

impl CentralFact {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        if let Some(exp) = self.expires_at_unix_ms {
            now_ms >= exp
        } else {
            false
        }
    }

    pub fn target_entity(&self) -> Option<&str> {
        self.args.first().map(|s| s.as_str())
    }
}

/// Thread-safe central fact store.
#[derive(Clone, Default)]
pub struct CentralIntelStore {
    // (tenant_id, fact_signature) -> CentralFact
    facts: Arc<RwLock<HashMap<(String, String), CentralFact>>>,
}

impl CentralIntelStore {
    pub fn new() -> Self {
        Self {
            facts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn emit_fact(
        &self,
        tenant_id: &str,
        host_id: &str,
        fact_name: &str,
        args: Vec<String>,
        ttl_ms: Option<u64>,
    ) {
        let now_ms = current_unix_ms();
        let expires_at = ttl_ms.map(|ttl| now_ms.saturating_add(ttl));
        let signature = format!("{}({})", fact_name, args.join(","));

        let fact = CentralFact {
            fact_name: fact_name.to_string(),
            args,
            tenant_id: tenant_id.to_string(),
            host_id: host_id.to_string(),
            emitted_at_unix_ms: now_ms,
            expires_at_unix_ms: expires_at,
        };

        let mut lock = self.facts.write().unwrap_or_else(|p| p.into_inner());
        lock.insert((tenant_id.to_string(), signature), fact);
    }

    pub fn has_fact(&self, tenant_id: &str, fact_name: &str, target: Option<&str>) -> bool {
        let now_ms = current_unix_ms();
        let lock = self.facts.read().unwrap_or_else(|p| p.into_inner());

        for ((t_id, _), fact) in lock.iter() {
            if t_id == tenant_id && !fact.is_expired(now_ms) && fact.fact_name == fact_name {
                if let Some(tgt) = target {
                    if fact.args.iter().any(|a| a == tgt) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        false
    }

    pub fn get_facts_for_entity(&self, tenant_id: &str, entity_id: &str) -> Vec<CentralFact> {
        let now_ms = current_unix_ms();
        let lock = self.facts.read().unwrap_or_else(|p| p.into_inner());

        lock.values()
            .filter(|f| {
                f.tenant_id == tenant_id
                    && !f.is_expired(now_ms)
                    && f.args.iter().any(|a| a == entity_id)
            })
            .cloned()
            .collect()
    }

    pub fn list_active_facts(&self, tenant_id: Option<&str>) -> Vec<CentralFact> {
        let now_ms = current_unix_ms();
        let lock = self.facts.read().unwrap_or_else(|p| p.into_inner());

        lock.values()
            .filter(|f| {
                !f.is_expired(now_ms)
                    && tenant_id.map(|t| f.tenant_id == t).unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    pub fn prune_expired(&self) -> usize {
        let now_ms = current_unix_ms();
        let mut lock = self.facts.write().unwrap_or_else(|p| p.into_inner());
        let before = lock.len();
        lock.retain(|_, f| !f.is_expired(now_ms));
        before.saturating_sub(lock.len())
    }

    pub fn active_count(&self) -> usize {
        let lock = self.facts.read().unwrap_or_else(|p| p.into_inner());
        lock.len()
    }
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
