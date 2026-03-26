//! Olopa agent userspace entrypoint.
//!
//! Responsibilities in this file:
//! - Parse runtime CLI options.
//! - Bootstrap eBPF probe attachment.
//! - Wire concrete implementations into the orchestrator traits.
//! - Start the long-running `OlopaAgent::run(...)` loop.

mod agent;
mod budget_tracker;
mod probe_manager;
mod data;
mod runtime_ir;

use anyhow::Result;
use clap::Parser;
use log::{info, warn};
use std::time::{Duration, Instant};

use crate::agent::{
    BatcherLike, BatcherPush, EventStoreLike, GraphLike, IngestEvent,
    MetricAggregatorLike, OlopaAgent, RelevanceScorerLike, RuleEngineLike, RuleMatch,
    SchedulerLike, SenderLike, SenderStats,
};
use crate::budget_tracker::{BudgetSnapshot as RuntimeBudgetSnapshot, BudgetTracker};
use crate::data::csr_graph::{CsrGraph, EdgeKind, EdgeProps};
use crate::data::event_store::{ColdEvent, EventStore, HotEvent};
use crate::data::mdkp_scheduler::{
    BudgetSnapshot as SchedulerBudgetSnapshot, N_RESOURCES, Scheduler, SolverTier, TelemetryItem,
};
use crate::data::metric_aggregator::{MetricAggregator, MetricSummary};
use crate::data::relevance_scorer::RelevanceScorer;
use crate::probe_manager::ProbeManager;
use crate::runtime_ir::RuntimeIrRuleEngine;

#[derive(Debug, Parser)]
#[command(name = "olopa-agent", about = "Olopa kernel security agent")]
struct Opt {
    /// Network interface used by attach helpers.
    #[arg(short, long, default_value = "wlo1")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("olopa-agent starting | iface={}", opt.iface);

    // 1) Load eBPF object and attach default probes.
    let mut agent = OlopaAgent::new()?;
    let mut probe_manager = ProbeManager::new();
    probe_manager.attach_defaults(agent.bpf_mut(), &opt.iface)?;
    info!("olopa-agent initialized and probes attached");

    // 2) Wire concrete runtime components (adapters + default implementations).
    let mut relevance_scorer = RealRelevanceScorer::default();
    let mut event_store = RealEventStore::default();
    let mut graph = RealGraph::default();
    let mut metric_aggregator = RealMetricAggregator::default();
    let mut rule_engine = ActiveRuleEngine::from_env();
    let mut scheduler = RealScheduler::default();
    let mut batcher = SimpleBatcher::default();
    let mut sender = SimpleSender::default();
    let mut budget_tracker = BudgetTracker::new();

    // 3) Main runtime loops live inside agent.run(...).
    agent
        .run(
            &mut relevance_scorer,
            &mut event_store,
            &mut graph,
            &mut metric_aggregator,
            &mut rule_engine,
            &mut scheduler,
            &mut batcher,
            &mut sender,
            &mut budget_tracker,
        )
        .await
}

// --- Concrete adapters for orchestrator traits ---

#[derive(Default)]
struct RealRelevanceScorer {
    inner: RelevanceScorer,
    // Monotonic synthetic event id passed into scorer state machine.
    next_event_id: usize,
}
impl Default for RelevanceScorer {
    fn default() -> Self {
        RelevanceScorer::with_default_epsilon()
    }
}
impl RelevanceScorerLike for RealRelevanceScorer {
    fn score(&mut self, event: &mut IngestEvent) {
        // Current bridge passes core numeric fields only; richer context wiring
        // can be layered later without changing orchestrator contract.
        let scored = self.inner.score(
            self.next_event_id,
            event.vertex_id,
            event.risk_score,
            event.ts_ns,
            0,
        );
        self.next_event_id = self.next_event_id.saturating_add(1);

        // Map scorer output back into event risk used downstream.
        event.risk_score = scored.map(|s| s.relevance).unwrap_or(0.0);
    }
}

struct RealEventStore {
    inner: EventStore,
}
impl Default for RealEventStore {
    fn default() -> Self {
        Self {
            inner: EventStore::with_capacity(1_000_000),
        }
    }
}
impl EventStoreLike for RealEventStore {
    fn push(&mut self, event: IngestEvent) -> Option<usize> {
        // Split event into hot/cold representations expected by EventStore.
        let hot = HotEvent {
            ts_ns: event.ts_ns,
            pid: event.pid,
            risk_score: event.risk_score,
        };
        let cold = ColdEvent {
            argv_hash: [0; 32],
            path_hash: [0; 32],
            env_hash: [0; 32],
            ppid: event.dst_vertex_id,
            uid: event.uid,
            gid: 0,
            comm_id: event.comm_id,
            _pad: [0; 16],
        };

        let id = self.inner.push(hot, cold)?;
        info!(
            "ingest->store event_id={} type={} pid={} risk={:.3}",
            id, event.event_type, event.pid, event.risk_score
        );
        Some(id)
    }

    fn serialize_event(&self, event_id: usize) -> Option<Vec<u8>> {
        // Bootstrap wire format: plain text line; replace with protobuf later.
        let hot = self.inner.hot_events().get(event_id)?;
        let cold = self.inner.cold_event(event_id)?;
        Some(
            format!(
                "evt ts={} pid={} uid={} risk={:.3} src={} dst={} comm={}",
                hot.ts_ns, hot.pid, cold.uid, hot.risk_score, hot.pid, cold.ppid, cold.comm_id
            )
            .into_bytes(),
        )
    }

    fn unscheduled_event_ids(&self, from: usize) -> Vec<usize> {
        (from..self.inner.hot_events().len()).collect()
    }

    fn last_event_id(&self) -> usize {
        self.inner.hot_events().len().saturating_sub(1)
    }
}

struct RealGraph {
    inner: CsrGraph,
}
impl Default for RealGraph {
    fn default() -> Self {
        Self {
            inner: CsrGraph::new(65_536, 262_144),
        }
    }
}
impl GraphLike for RealGraph {
    fn write_edge(&mut self, event: &IngestEvent) {
        // Map lightweight event discriminator to graph edge kind.
        let kind = match event.event_type {
            1 => EdgeKind::Spawned,
            2 => EdgeKind::ReadFile,
            3 => EdgeKind::ConnectedTo,
            _ => EdgeKind::DataFlow,
        };

        let props = EdgeProps {
            ts_ns: event.ts_ns,
            kind,
            causal: true,
            risk_weight: (event.risk_score.clamp(0.0, 1.0) * 255.0) as u8,
            _pad: 0,
            bytes: 0,
        };

        self.inner.write_edge(event.vertex_id, event.dst_vertex_id, props);
    }

    fn merge_deltas(&mut self) {
        self.inner.merge_deltas();
    }
}

struct RealMetricAggregator {
    inner: MetricAggregator,
}
impl Default for RealMetricAggregator {
    fn default() -> Self {
        Self {
            inner: MetricAggregator::new(5_000),
        }
    }
}
impl MetricAggregatorLike for RealMetricAggregator {
    fn record(&mut self, event: &IngestEvent) {
        // Risk metric keyed by comm_id to preserve low cardinality.
        self.inner.record_risk(event.comm_id, event.risk_score);
    }

    fn flush(&mut self) -> Vec<Vec<u8>> {
        self.inner.flush().into_iter().map(serialize_metric_summary).collect()
    }
}

struct RealScheduler {
    inner: Scheduler,
}
impl Default for RealScheduler {
    fn default() -> Self {
        Self {
            inner: Scheduler::new(SchedulerBudgetSnapshot::default_budgets()),
        }
    }
}
impl SchedulerLike for RealScheduler {
    fn update_budget(&mut self, snapshot: RuntimeBudgetSnapshot) {
        // Convert runtime tracker snapshot into scheduler-local budget type.
        let converted = SchedulerBudgetSnapshot {
            total: snapshot.total,
            remaining: snapshot.remaining,
            weights: snapshot.weights,
        };
        self.inner.update_budget(converted);
    }

    fn enqueue(&mut self, event_id: usize) {
        // Placeholder relevance/cost mapping until full scorer->scheduler bridge is wired.
        let item = TelemetryItem::new(event_id, 0.5, [1.0; N_RESOURCES]);
        self.inner.enqueue(item);
    }

    fn solve(&mut self) -> Vec<usize> {
        let selected = self.inner.solve(SolverTier::Greedy).event_ids;
        info!("scheduler.solve selected={} events", selected.len());
        selected
    }
}

// --- Bootstrap components for rule engine, batching, and transport ---

struct SimpleRuleEngine;
impl RuleEngineLike for SimpleRuleEngine {
    fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch> {
        if event.risk_score >= 0.95 {
            vec![RuleMatch {
                rule_id: "simple:fallback".to_string(),
                rule_name: "simple_fallback_threshold".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

enum ActiveRuleEngine {
    // Compiler-emitted runtime IR evaluator.
    RuntimeIr(RuntimeIrRuleEngine),
    // Minimal fallback matcher when runtime IR cannot be loaded.
    Simple(SimpleRuleEngine),
}

impl ActiveRuleEngine {
    fn from_env() -> Self {
        const DEFAULT_RUNTIME_IR_PATH: &str = "/etc/olopa/runtime-ir.json";
        // Explicit env var overrides default deployment path.
        let path = std::env::var("OLOPA_RUNTIME_IR")
            .unwrap_or_else(|_| DEFAULT_RUNTIME_IR_PATH.to_string());

        match RuntimeIrRuleEngine::from_file(std::path::Path::new(&path)) {
            Ok(engine) => {
                info!(
                    "rule engine loaded runtime-ir from {} (rules={})",
                    path,
                    engine.rule_count()
                );
                Self::RuntimeIr(engine)
            }
            Err(e) => {
                warn!("failed to load runtime-ir from {}: {}", path, e);
                info!("rule engine using SimpleRuleEngine fallback");
                Self::Simple(SimpleRuleEngine)
            }
        }
    }
}

impl RuleEngineLike for ActiveRuleEngine {
    fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch> {
        match self {
            ActiveRuleEngine::RuntimeIr(engine) => engine.evaluate_matches(event),
            ActiveRuleEngine::Simple(engine) => engine.evaluate(event),
        }
    }
}

struct SimpleBatcher {
    // Accumulated serialized telemetry events.
    pending: Vec<Vec<u8>>,
    // Last time a flush happened (used for periodic flush trigger).
    last_flush: Instant,
}
impl Default for SimpleBatcher {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            last_flush: Instant::now(),
        }
    }
}
impl BatcherLike for SimpleBatcher {
    fn push(&mut self, serialized_event: &[u8], _budget: &RuntimeBudgetSnapshot) -> BatcherPush {
        // Bootstrap threshold-only batching policy.
        self.pending.push(serialized_event.to_vec());
        if self.pending.len() >= 64 {
            BatcherPush::FlushNeeded
        } else {
            BatcherPush::Ok
        }
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        if self.pending.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for item in self.pending.drain(..) {
            out.extend_from_slice(&item);
            out.push(b'\n');
        }
        self.last_flush = Instant::now();
        Some(out)
    }

    fn flush_if_time_triggered(&mut self) -> Option<Vec<u8>> {
        if self.last_flush.elapsed() >= Duration::from_millis(500) {
            self.flush()
        } else {
            None
        }
    }
}

#[derive(Default)]
struct SimpleSender {
    // Count of payloads sent directly (non-spooled).
    sent: u64,
    // In-memory spool used while sender is in spooling mode.
    spooled: Vec<Vec<u8>>,
    // Toggle for degraded transport mode.
    spooling: bool,
}
impl SenderLike for SimpleSender {
    fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()> {
        if self.spooling {
            self.spooled.push(payload);
        } else {
            self.sent += 1;
            info!("sent payload #{}", self.sent);
        }
        Ok(())
    }

    fn stats(&self) -> SenderStats {
        let pending: u64 = self.spooled.iter().map(|b| b.len() as u64).sum();
        SenderStats {
            spool_pending_bytes: pending,
            spooling: self.spooling,
        }
    }

    fn drain_spool(&mut self, deadline: Instant) -> Result<usize> {
        let mut drained = 0usize;
        while !self.spooled.is_empty() && Instant::now() < deadline {
            self.spooled.remove(0);
            drained += 1;
        }
        Ok(drained)
    }
}

fn serialize_metric_summary(s: MetricSummary) -> Vec<u8> {
    // Bootstrap text wire format for metric snapshots.
    format!(
        "metric comm_id={} count={} min={:.4} max={:.4} mean={:.4} p50={:.4} p95={:.4} p99={:.4}",
        s.comm_id, s.count, s.min, s.max, s.mean, s.p50, s.p95, s.p99
    )
    .into_bytes()
}
