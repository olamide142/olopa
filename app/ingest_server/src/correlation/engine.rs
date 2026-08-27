//! Core multi-source and multi-agent correlation engine.
//!
//! Evaluates single-event and sliding-window multi-event join rules against incoming
//! telemetry batches using vectorized filtering, sharded state, and central fact stores.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::info;

use crate::telemetry::IngestBatchRequest;
use super::alerts::{AlertRingBuffer, CorrelatedAlert, CorrelatedEventSnippet};
use super::event::{EventFamily, OwnedEvent, UnifiedEventRef};
use super::intel::CentralIntelStore;
use super::ir::{
    parse_runtime_program, RuntimeAction, RuntimeExpr, RuntimeJoin, RuntimeProgram, RuntimeRule,
    RuntimeScore, RuntimeSource,
};
use super::state::CentralCallableState;
use super::value::Value;
use super::vectorized::BatchColumnIndex;
use super::window::SlidingWindowIndex;

#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub rule: RuntimeRule,
    pub sources: Vec<RuntimeSource>,
    pub source_families: Vec<(String, EventFamily)>,
    pub joins: Vec<RuntimeJoin>,
    /// Field-path pairs from the rule's `on` clauses that the window key is
    /// built from. Empty when the rule declares no usable equality join.
    pub join_terms: Vec<(String, String)>,
    pub window_ms: u64,
}

impl CompiledRule {
    pub fn compile(rule: RuntimeRule) -> Self {
        let mut source_families = Vec::new();
        for src in &rule.sources {
            let alias = src.effective_alias();
            let family = match (src.domain.as_str(), src.event.as_str()) {
                ("endpoint", "process") | ("process", _) | ("", "process") | ("", "spawn") => {
                    EventFamily::ProcessExec
                }
                ("endpoint", "file") | ("file", _) | ("", "file") | ("", "open") => {
                    EventFamily::File
                }
                ("network", _) | ("net", _) | ("", "network") | ("", "connect") | ("", "flow") => {
                    EventFamily::Net
                }
                ("database", _) | ("db", _) | ("", "db_query") | ("", "query") | ("", "sql") => {
                    EventFamily::DbQuery
                }
                ("agent", _) | ("heartbeat", _) | ("", "agent_heartbeat") => {
                    EventFamily::AgentHeartbeat
                }
                _ => EventFamily::ProcessExec,
            };
            source_families.push((alias, family));
        }

        if source_families.is_empty() {
            // Default to ProcessExec if sources not declared
            source_families.push(("process".to_string(), EventFamily::ProcessExec));
        }

        let window_ms = rule.window.map(|w| w.to_millis()).unwrap_or(300_000); // 5 min default

        let join_terms = extract_equi_join_terms(&rule.joins);

        Self {
            sources: rule.sources.clone(),
            source_families,
            joins: rule.joins.clone(),
            join_terms,
            window_ms,
            rule,
        }
    }

    pub fn is_multi_source(&self) -> bool {
        self.source_families.len() > 1 || !self.joins.is_empty()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CorrelationStats {
    pub rules_active: usize,
    pub events_evaluated: u64,
    /// Events correlated against batch arrival time because the sender stamped
    /// no usable event time. Non-zero means replay cannot reproduce this window.
    pub events_ts_fallback: u64,
    pub matches_total: u64,
    pub alerts_emitted: u64,
    pub window_active_events: usize,
    pub facts_active: usize,
}

/// Central multi-source and multi-agent correlation engine.
#[derive(Clone)]
pub struct CorrelationEngine {
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    pub state: CentralCallableState,
    pub intel: CentralIntelStore,
    pub window: SlidingWindowIndex,
    pub alerts: AlertRingBuffer,
    events_evaluated: Arc<AtomicU64>,
    matches_total: Arc<AtomicU64>,
    alerts_emitted: Arc<AtomicU64>,
    events_ts_fallback: Arc<AtomicU64>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            state: CentralCallableState::default(),
            intel: CentralIntelStore::new(),
            window: SlidingWindowIndex::default(),
            alerts: AlertRingBuffer::default(),
            events_evaluated: Arc::new(AtomicU64::new(0)),
            matches_total: Arc::new(AtomicU64::new(0)),
            alerts_emitted: Arc::new(AtomicU64::new(0)),
            events_ts_fallback: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn load_program(&self, program: RuntimeProgram) -> usize {
        let mut compiled = Vec::with_capacity(program.rules.len());
        for rule in program.rules {
            compiled.push(CompiledRule::compile(rule));
        }
        let count = compiled.len();
        let mut lock = self.rules.write().unwrap_or_else(|p| p.into_inner());
        *lock = compiled;
        info!(rules_count = count, "loaded runtime IR rules into correlation engine");
        count
    }

    pub fn load_from_json(&self, json_content: &str) -> Result<usize> {
        let program = parse_runtime_program(json_content)?;
        Ok(self.load_program(program))
    }

    pub fn load_from_file(&self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read runtime IR from {}", path.display()))?;
        self.load_from_json(&content)
    }

    /// Evaluates an ingested telemetry batch against all active correlation rules.
    pub fn evaluate_batch(&self, batch: &IngestBatchRequest) -> Vec<CorrelatedAlert> {
        let total_rows = batch.row_count();
        if total_rows == 0 {
            return Vec::new();
        }

        self.events_evaluated
            .fetch_add(total_rows as u64, Ordering::Relaxed);

        let rules = {
            let lock = self.rules.read().unwrap_or_else(|p| p.into_inner());
            if lock.is_empty() {
                return Vec::new();
            }
            lock.clone()
        };

        let now_ms = current_unix_ms();
        let col_index = BatchColumnIndex::build(batch, now_ms);
        if col_index.ts_fallback_count > 0 {
            self.events_ts_fallback
                .fetch_add(col_index.ts_fallback_count as u64, Ordering::Relaxed);
        }

        let mut emitted_alerts = Vec::new();

        for compiled in &rules {
            if compiled.is_multi_source() {
                let multi_alerts = self.evaluate_multi_source_rule(compiled, &col_index, now_ms);
                emitted_alerts.extend(multi_alerts);
            } else {
                let single_alerts = self.evaluate_single_source_rule(compiled, &col_index, now_ms);
                emitted_alerts.extend(single_alerts);
            }
        }

        for alert in &emitted_alerts {
            self.alerts.push(alert.clone());
        }

        if !emitted_alerts.is_empty() {
            self.alerts_emitted
                .fetch_add(emitted_alerts.len() as u64, Ordering::Relaxed);
        }

        emitted_alerts
    }

    fn evaluate_single_source_rule(
        &self,
        compiled: &CompiledRule,
        col_index: &BatchColumnIndex<'_>,
        now_ms: u64,
    ) -> Vec<CorrelatedAlert> {
        let (alias, target_family) = &compiled.source_families[0];
        let family_mask = col_index.mask_for_family(*target_family);
        if family_mask.is_empty() {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        for idx in family_mask.iter_indices() {
            let event = col_index.events[idx];

            let mut env = HashMap::new();
            env.insert(alias.clone(), event);
            // Also alias "event", "e", and bare
            env.insert("event".to_string(), event);
            env.insert("e".to_string(), event);

            let mut lets = HashMap::new();
            let all_predicates_match = compiled.rule.predicates.iter().all(|pred| {
                self.eval_bool(pred, &env, &lets, event.tenant_id, event.host_id, now_ms)
            });

            if !all_predicates_match {
                continue;
            }

            self.matches_total.fetch_add(1, Ordering::Relaxed);

            // Evaluate lets
            for l in &compiled.rule.lets {
                let val = self.eval_expr(&l.value, &env, &lets, event.tenant_id, event.host_id, now_ms);
                lets.insert(l.name.clone(), val);
            }

            // Evaluate requirements
            let reqs_passed = compiled.rule.require.iter().all(|req| {
                self.eval_bool(req, &env, &lets, event.tenant_id, event.host_id, now_ms)
            });

            if !reqs_passed {
                continue;
            }

            // Compute score
            let score = self.eval_score(&compiled.rule.score, &env, &lets, event.tenant_id, event.host_id, now_ms);

            // Fact emissions
            let mut emitted_fact_strings = Vec::new();
            for emit in &compiled.rule.emit {
                let args = emit
                    .args
                    .iter()
                    .map(|arg| {
                        self.eval_expr(arg, &env, &lets, event.tenant_id, event.host_id, now_ms)
                            .to_string_lossy()
                    })
                    .collect::<Vec<_>>();
                let ttl_ms = emit.expires.map(|e| e.to_millis());
                self.intel
                    .emit_fact(event.tenant_id, event.host_id, &emit.fact_name, args.clone(), ttl_ms);
                emitted_fact_strings.push(format!("{}({})", emit.fact_name, args.join(", ")));
            }

            // Response plan actions
            let actions = self.resolve_actions(&compiled.rule.respond, &env, &lets, score, event.tenant_id, event.host_id, now_ms);

            let severity = actions
                .iter()
                .find_map(|a| match a {
                    RuntimeAction::Alert { severity, .. } => Some(severity.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "high".to_string());

            let message = actions
                .iter()
                .find_map(|a| match a {
                    RuntimeAction::Alert { message, .. } => message.clone(),
                    _ => None,
                })
                .unwrap_or_else(|| compiled.rule.name.clone());

            let snippet = CorrelatedEventSnippet {
                kind: event.kind.as_str().to_string(),
                host_id: event.host_id.to_string(),
                ts_unix_ms: event.ts_unix_ms,
                summary: format!("{}: {:?}", event.kind.as_str(), event.get_field("comm", None)),
                details: HashMap::new(),
            };

            let alert = CorrelatedAlert {
                alert_id: CorrelatedAlert::derive_id(
                    &compiled.rule.id,
                    event.tenant_id,
                    [event.identity_key()],
                ),
                rule_id: compiled.rule.id.clone(),
                rule_name: compiled.rule.name.clone(),
                severity,
                tenant_id: event.tenant_id.to_string(),
                host_id: event.host_id.to_string(),
                message,
                score,
                actions,
                matched_events: vec![snippet],
                emitted_facts: emitted_fact_strings,
                timestamp_unix_ms: now_ms,
            };

            alerts.push(alert);
        }

        alerts
    }

    fn evaluate_multi_source_rule(
        &self,
        compiled: &CompiledRule,
        col_index: &BatchColumnIndex<'_>,
        now_ms: u64,
    ) -> Vec<CorrelatedAlert> {
        let mut alerts = Vec::new();

        // For each source defined in the rule
        for (alias, family) in &compiled.source_families {
            let mask = col_index.mask_for_family(*family);
            if mask.is_empty() {
                continue;
            }

            for idx in mask.iter_indices() {
                let incoming_event = col_index.events[idx];

                // Derive join key from incoming event
                let join_key = self.resolve_event_join_key(&incoming_event, alias, compiled);

                // Insert into sliding window
                self.window.insert_event(
                    incoming_event.tenant_id,
                    &compiled.rule.id,
                    alias,
                    &join_key,
                    incoming_event.to_owned_event(),
                    compiled.window_ms,
                );

                // Probe sliding window for other required aliases
                let mut alias_candidates: Vec<(String, Vec<OwnedEvent>)> = Vec::new();
                let mut found_all = true;

                for (other_alias, _) in &compiled.source_families {
                    if other_alias == alias {
                        continue;
                    }
                    let candidates = self.window.find_candidate_events(
                        incoming_event.tenant_id,
                        &compiled.rule.id,
                        other_alias,
                        &join_key,
                        incoming_event.ts_unix_ms,
                        compiled.window_ms,
                    );
                    if candidates.is_empty() {
                        found_all = false;
                        break;
                    }
                    alias_candidates.push((other_alias.clone(), candidates));
                }

                if !found_all {
                    continue;
                }

                // Cartesian product / join combination across found candidates
                let matched_tuples = self.find_matching_join_tuples(
                    compiled,
                    alias,
                    &incoming_event,
                    &alias_candidates,
                    now_ms,
                );

                for tuple in matched_tuples {
                    self.matches_total.fetch_add(1, Ordering::Relaxed);

                    let mut lets = HashMap::new();
                    for l in &compiled.rule.lets {
                        let val = self.eval_expr(
                            &l.value,
                            &tuple,
                            &lets,
                            incoming_event.tenant_id,
                            incoming_event.host_id,
                            now_ms,
                        );
                        lets.insert(l.name.clone(), val);
                    }

                    let reqs_passed = compiled.rule.require.iter().all(|req| {
                        self.eval_bool(
                            req,
                            &tuple,
                            &lets,
                            incoming_event.tenant_id,
                            incoming_event.host_id,
                            now_ms,
                        )
                    });

                    if !reqs_passed {
                        continue;
                    }

                    let score = self.eval_score(
                        &compiled.rule.score,
                        &tuple,
                        &lets,
                        incoming_event.tenant_id,
                        incoming_event.host_id,
                        now_ms,
                    );

                    let mut emitted_fact_strings = Vec::new();
                    for emit in &compiled.rule.emit {
                        let args = emit
                            .args
                            .iter()
                            .map(|arg| {
                                self.eval_expr(
                                    arg,
                                    &tuple,
                                    &lets,
                                    incoming_event.tenant_id,
                                    incoming_event.host_id,
                                    now_ms,
                                )
                                .to_string_lossy()
                            })
                            .collect::<Vec<_>>();
                        let ttl_ms = emit.expires.map(|e| e.to_millis());
                        self.intel.emit_fact(
                            incoming_event.tenant_id,
                            incoming_event.host_id,
                            &emit.fact_name,
                            args.clone(),
                            ttl_ms,
                        );
                        emitted_fact_strings.push(format!("{}({})", emit.fact_name, args.join(", ")));
                    }

                    let actions = self.resolve_actions(
                        &compiled.rule.respond,
                        &tuple,
                        &lets,
                        score,
                        incoming_event.tenant_id,
                        incoming_event.host_id,
                        now_ms,
                    );

                    let severity = actions
                        .iter()
                        .find_map(|a| match a {
                            RuntimeAction::Alert { severity, .. } => Some(severity.clone()),
                            _ => None,
                        })
                        .unwrap_or_else(|| "high".to_string());

                    let message = actions
                        .iter()
                        .find_map(|a| match a {
                            RuntimeAction::Alert { message, .. } => message.clone(),
                            _ => None,
                        })
                        .unwrap_or_else(|| compiled.rule.name.clone());

                    let snippets = tuple
                        .iter()
                        .map(|(a, ev)| CorrelatedEventSnippet {
                            kind: format!("{} ({})", ev.kind.as_str(), a),
                            host_id: ev.host_id.to_string(),
                            ts_unix_ms: ev.ts_unix_ms,
                            summary: format!("{}: {:?}", a, ev.get_field("comm", None)),
                            details: HashMap::new(),
                        })
                        .collect();

                    let alert = CorrelatedAlert {
                        alert_id: CorrelatedAlert::derive_id(
                            &compiled.rule.id,
                            incoming_event.tenant_id,
                            tuple.values().map(|ev| ev.identity_key()),
                        ),
                        rule_id: compiled.rule.id.clone(),
                        rule_name: compiled.rule.name.clone(),
                        severity,
                        tenant_id: incoming_event.tenant_id.to_string(),
                        host_id: incoming_event.host_id.to_string(),
                        message,
                        score,
                        actions,
                        matched_events: snippets,
                        emitted_facts: emitted_fact_strings,
                        timestamp_unix_ms: now_ms,
                    };

                    alerts.push(alert);
                }
            }
        }

        alerts
    }

    /// Derive the sliding-window bucket key for one event.
    ///
    /// Prefers the equality fields the rule actually declared in its `on`
    /// clause: those keys are tenant-scoped, so a rule joining on something
    /// shared between machines - a destination address, an account - correlates
    /// across agents, which is the point of declaring the join.
    ///
    /// With no declared join there is nothing to key on but the process id, and
    /// a bare pid means nothing across machines: pid 1001 on two hosts is two
    /// unrelated processes. Those keys are host-scoped so they cannot collide
    /// into one false cross-host match.
    /// Derive the sliding-window bucket key for one event.
    ///
    /// Prefers the equality fields the rule actually declared in its `on`
    /// clause: those keys are tenant-scoped, so a rule joining on something
    /// shared between machines - a destination address, an account - correlates
    /// across agents, which is the point of declaring the join.
    ///
    /// Falls back to the process id when the rule declares no join, or when it
    /// declares one whose fields this event cannot resolve. A bare pid means
    /// nothing across machines - pid 1001 on two hosts is two unrelated
    /// processes - so those keys are host-scoped and cannot collide into one
    /// false cross-host match.
    fn resolve_event_join_key(
        &self,
        event: &UnifiedEventRef<'_>,
        alias: &str,
        compiled: &CompiledRule,
    ) -> String {
        if !compiled.join_terms.is_empty() {
            let mut parts = Vec::with_capacity(compiled.join_terms.len());
            let mut any_resolved = false;

            for (left_path, right_path) in &compiled.join_terms {
                // Each side of the equality names a different source. Resolving
                // against this event's own alias picks out its side and leaves
                // the other Null, so both sides of the join land on the same key.
                let value = match event.get_field(left_path, Some(alias)) {
                    Value::Null => event.get_field(right_path, Some(alias)),
                    resolved => resolved,
                };
                any_resolved |= !matches!(value, Value::Null);
                parts.push(value.to_key_string());
            }

            // A join whose fields resolve on no event would bucket the entire
            // rule under one all-null key and join everything with everything.
            if any_resolved {
                return parts.join("\u{1f}");
            }
        }

        let pid = event.get_field("pid", None);
        if let Value::Int(p) = pid {
            if p > 0 {
                return format!("host_{}_pid_{}", event.host_id, p);
            }
        }

        format!("host_{}", event.host_id)
    }

    fn find_matching_join_tuples<'a>(
        &self,
        compiled: &CompiledRule,
        primary_alias: &str,
        primary_event: &'a UnifiedEventRef<'a>,
        other_candidates: &'a [(String, Vec<OwnedEvent>)],
        now_ms: u64,
    ) -> Vec<HashMap<String, UnifiedEventRef<'a>>> {
        let mut results = Vec::new();

        if other_candidates.len() == 1 {
            let (other_alias, candidates) = &other_candidates[0];
            for candidate in candidates {
                let other_ref = candidate.as_ref();
                let mut env = HashMap::new();
                env.insert(primary_alias.to_string(), *primary_event);
                env.insert(other_alias.clone(), other_ref);

                let dummy_lets = HashMap::new();
                let predicates_match = compiled.rule.predicates.iter().all(|pred| {
                    self.eval_bool(
                        pred,
                        &env,
                        &dummy_lets,
                        primary_event.tenant_id,
                        primary_event.host_id,
                        now_ms,
                    )
                });

                if predicates_match {
                    results.push(env);
                }
            }
        } else if other_candidates.len() == 2 {
            let (alias_1, cand_1) = &other_candidates[0];
            let (alias_2, cand_2) = &other_candidates[1];
            for c1 in cand_1 {
                for c2 in cand_2 {
                    let mut env = HashMap::new();
                    env.insert(primary_alias.to_string(), *primary_event);
                    env.insert(alias_1.clone(), c1.as_ref());
                    env.insert(alias_2.clone(), c2.as_ref());

                    let dummy_lets = HashMap::new();
                    let predicates_match = compiled.rule.predicates.iter().all(|pred| {
                        self.eval_bool(
                            pred,
                            &env,
                            &dummy_lets,
                            primary_event.tenant_id,
                            primary_event.host_id,
                            now_ms,
                        )
                    });

                    if predicates_match {
                        results.push(env);
                    }
                }
            }
        }

        results
    }

    pub fn eval_expr(
        &self,
        expr: &RuntimeExpr,
        env: &HashMap<String, UnifiedEventRef<'_>>,
        lets: &HashMap<String, Value>,
        tenant_id: &str,
        host_id: &str,
        now_ms: u64,
    ) -> Value {
        match expr {
            RuntimeExpr::Bool { value } => Value::Bool(*value),
            RuntimeExpr::Null => Value::Null,
            RuntimeExpr::Int { value } => Value::Int(*value),
            RuntimeExpr::Float { value } => Value::Float(*value),
            RuntimeExpr::Str { value } => Value::Str(value.clone()),
            RuntimeExpr::Duration { value, unit } => {
                let dur = super::ir::RuntimeDuration {
                    value: *value,
                    unit: *unit,
                };
                Value::DurationNs(dur.to_nanos())
            }
            RuntimeExpr::List { items } => {
                let evaluated = items
                    .iter()
                    .map(|item| self.eval_expr(item, env, lets, tenant_id, host_id, now_ms))
                    .collect();
                Value::List(evaluated)
            }
            RuntimeExpr::Field { path } => {
                // Check let-bindings first
                if let Some(val) = lets.get(path) {
                    return val.clone();
                }

                // Check alias dotted path (e.g. `p.name` or `f.path`)
                if let Some((alias, subpath)) = path.split_once('.') {
                    if let Some(event) = env.get(alias) {
                        return event.get_field(subpath, None);
                    }
                }

                // Check direct fields against any event in env
                for (alias, event) in env {
                    let v = event.get_field(path, Some(alias));
                    if v != Value::Null {
                        return v;
                    }
                }
                Value::Null
            }
            RuntimeExpr::Not { expr } => {
                let v = self.eval_expr(expr, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(!v.is_truthy())
            }
            RuntimeExpr::And { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                if !l.is_truthy() {
                    return Value::Bool(false);
                }
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(r.is_truthy())
            }
            RuntimeExpr::Or { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                if l.is_truthy() {
                    return Value::Bool(true);
                }
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(r.is_truthy())
            }
            RuntimeExpr::Eq { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(l.op_eq(&r))
            }
            RuntimeExpr::Ne { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(l.op_ne(&r))
            }
            RuntimeExpr::Lt { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(l.op_lt(&r))
            }
            RuntimeExpr::Le { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(l.op_le(&r))
            }
            RuntimeExpr::Gt { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(l.op_gt(&r))
            }
            RuntimeExpr::Ge { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(l.op_ge(&r))
            }
            RuntimeExpr::Add { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                l.op_add(&r)
            }
            RuntimeExpr::Sub { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                l.op_sub(&r)
            }
            RuntimeExpr::Mul { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                l.op_mul(&r)
            }
            RuntimeExpr::Div { lhs, rhs } => {
                let l = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let r = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                l.op_div(&r)
            }
            RuntimeExpr::In { lhs, rhs } => {
                let target = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let evaluated_list: Vec<Value> = rhs
                    .iter()
                    .map(|item| self.eval_expr(item, env, lets, tenant_id, host_id, now_ms))
                    .collect();
                Value::Bool(target.op_in(&evaluated_list))
            }
            RuntimeExpr::Contains { lhs, rhs } => {
                let container = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let item = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(container.op_contains(&item))
            }
            RuntimeExpr::StartsWith { lhs, rhs } => {
                let s = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let prefix = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(s.op_starts_with(&prefix))
            }
            RuntimeExpr::EndsWith { lhs, rhs } => {
                let s = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                let suffix = self.eval_expr(rhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(s.op_ends_with(&suffix))
            }
            RuntimeExpr::Matches { lhs, pattern } => {
                let s = self.eval_expr(lhs, env, lets, tenant_id, host_id, now_ms);
                Value::Bool(s.op_matches(pattern))
            }
            RuntimeExpr::Call { name, args } => {
                self.eval_call(name, args, env, lets, tenant_id, host_id, now_ms)
            }
            RuntimeExpr::Project { base, field } => {
                let base_val = self.eval_expr(base, env, lets, tenant_id, host_id, now_ms);
                match base_val {
                    Value::Str(s) => match field.as_str() {
                        "len" | "length" => Value::Int(s.len() as i64),
                        _ => Value::Null,
                    },
                    Value::List(l) => match field.as_str() {
                        "len" | "count" => Value::Int(l.len() as i64),
                        _ => Value::Null,
                    },
                    _ => Value::Null,
                }
            }
            RuntimeExpr::Unsupported { .. } => Value::Null,
        }
    }

    fn eval_call(
        &self,
        name: &str,
        args: &[RuntimeExpr],
        env: &HashMap<String, UnifiedEventRef<'_>>,
        lets: &HashMap<String, Value>,
        tenant_id: &str,
        host_id: &str,
        now_ms: u64,
    ) -> Value {
        let eval_arg = |idx: usize| -> Value {
            args.get(idx)
                .map(|a| self.eval_expr(a, env, lets, tenant_id, host_id, now_ms))
                .unwrap_or(Value::Null)
        };

        match name {
            "rare" => {
                let val = eval_arg(0).to_string_lossy();
                let is_rare = self.state.eval_rare(tenant_id, "default", &val, 3);
                Value::Bool(is_rare)
            }
            "unusual" => {
                let entity = eval_arg(0).to_string_lossy();
                let val = eval_arg(1).to_string_lossy();
                let is_unusual = self.state.eval_unusual(tenant_id, "default", &entity, &val);
                Value::Bool(is_unusual)
            }
            "rate" => {
                let val = eval_arg(0).to_string_lossy();
                let window_ns = eval_arg(1).as_i64().unwrap_or(60_000_000_000) as u64;
                let now_ns = now_ms.saturating_mul(1_000_000);
                let count = self.state.eval_rate(tenant_id, "default", &val, window_ns, now_ns);
                Value::Int(count as i64)
            }
            "has_fact" | "fact" => {
                let fact_name = eval_arg(0).to_string_lossy();
                let target = args.get(1).map(|a| {
                    self.eval_expr(a, env, lets, tenant_id, host_id, now_ms)
                        .to_string_lossy()
                });
                let exists = self.intel.has_fact(tenant_id, &fact_name, target.as_deref());
                Value::Bool(exists)
            }
            "host_domain_baseline" => {
                let h_id = eval_arg(0).to_string_lossy();
                let domain = eval_arg(1).to_string_lossy();
                Value::Bool(self.state.check_host_domain_baseline(&h_id, &domain))
            }
            "host_process_baseline" => {
                let h_id = eval_arg(0).to_string_lossy();
                let proc = eval_arg(1).to_string_lossy();
                Value::Bool(self.state.check_host_process_baseline(&h_id, &proc))
            }
            "len" | "count" => {
                let val = eval_arg(0);
                match val {
                    Value::List(l) => Value::Int(l.len() as i64),
                    Value::Str(s) => Value::Int(s.len() as i64),
                    _ => Value::Int(0),
                }
            }
            _ => Value::Null,
        }
    }

    pub fn eval_bool(
        &self,
        expr: &RuntimeExpr,
        env: &HashMap<String, UnifiedEventRef<'_>>,
        lets: &HashMap<String, Value>,
        tenant_id: &str,
        host_id: &str,
        now_ms: u64,
    ) -> bool {
        self.eval_expr(expr, env, lets, tenant_id, host_id, now_ms).is_truthy()
    }

    fn eval_score(
        &self,
        score_plan: &RuntimeScore,
        env: &HashMap<String, UnifiedEventRef<'_>>,
        lets: &HashMap<String, Value>,
        tenant_id: &str,
        host_id: &str,
        now_ms: u64,
    ) -> i32 {
        let mut total = score_plan.base;
        for modifier in &score_plan.modifiers {
            let matches = if let Some(cond) = &modifier.condition {
                self.eval_bool(cond, env, lets, tenant_id, host_id, now_ms)
            } else {
                true
            };
            if matches {
                total = total.saturating_add(modifier.delta);
            }
        }
        total
    }

    fn resolve_actions(
        &self,
        respond: &super::ir::RuntimeRespondPlan,
        env: &HashMap<String, UnifiedEventRef<'_>>,
        lets: &HashMap<String, Value>,
        score: i32,
        tenant_id: &str,
        host_id: &str,
        now_ms: u64,
    ) -> Vec<RuntimeAction> {
        let mut actions = Vec::new();
        let mut scope_lets = lets.clone();
        scope_lets.insert("score".to_string(), Value::Int(score as i64));

        for branch in &respond.branches {
            let branch_matches = if let Some(cond) = &branch.condition {
                self.eval_bool(cond, env, &scope_lets, tenant_id, host_id, now_ms)
            } else {
                true
            };

            if branch_matches {
                actions.extend(branch.actions.clone());
                break; // First matching branch executes
            }
        }

        if actions.is_empty() {
            actions.push(RuntimeAction::Alert {
                severity: if score >= 80 {
                    "critical".to_string()
                } else if score >= 60 {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                message: None,
            });
        }

        actions
    }

    pub fn stats(&self) -> CorrelationStats {
        let rules_count = {
            let lock = self.rules.read().unwrap_or_else(|p| p.into_inner());
            lock.len()
        };

        CorrelationStats {
            rules_active: rules_count,
            events_evaluated: self.events_evaluated.load(Ordering::Relaxed),
            events_ts_fallback: self.events_ts_fallback.load(Ordering::Relaxed),
            matches_total: self.matches_total.load(Ordering::Relaxed),
            alerts_emitted: self.alerts_emitted.load(Ordering::Relaxed),
            window_active_events: self.window.active_event_count(),
            facts_active: self.intel.active_count(),
        }
    }
}

/// Collect the field pairs a rule's `on` clauses join on.
///
/// Only equalities between two fields can key a window bucket, so `a.pid ==
/// b.pid` is collected while a comparison against a literal is not - that is a
/// filter, and the predicate pass already applies it. Conjunctions are walked so
/// a compound join contributes every one of its terms; anything else is left
/// alone rather than guessed at, and the caller falls back to pid keying.
fn extract_equi_join_terms(joins: &[RuntimeJoin]) -> Vec<(String, String)> {
    fn walk(expr: &RuntimeExpr, out: &mut Vec<(String, String)>) {
        match expr {
            RuntimeExpr::And { lhs, rhs } => {
                walk(lhs, out);
                walk(rhs, out);
            }
            RuntimeExpr::Eq { lhs, rhs } => {
                if let (RuntimeExpr::Field { path: l }, RuntimeExpr::Field { path: r }) =
                    (lhs.as_ref(), rhs.as_ref())
                {
                    if l != r {
                        // Sorted so the pair is the same regardless of which way
                        // round the rule author wrote the equality.
                        let (a, b) = if l <= r { (l, r) } else { (r, l) };
                        out.push((a.clone(), b.clone()));
                    }
                }
            }
            _ => {}
        }
    }

    let mut terms = Vec::new();
    for join in joins {
        if let Some(on) = &join.on {
            walk(on, &mut terms);
        }
    }
    // Every event must build its key in the same term order.
    terms.sort();
    terms.dedup();
    terms
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
