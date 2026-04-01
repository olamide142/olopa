//! Olopa agent userspace entrypoint.
//!
//! Responsibilities in this file:
//! - Parse runtime CLI options.
//! - Bootstrap eBPF probe attachment.
//! - Wire concrete implementations into the orchestrator traits.
//! - Start the long-running `OlopaAgent::run(...)` loop.

mod agent;
mod budget_tracker;
mod data;
mod probe_manager;
mod runtime_ir;
mod transport;

use anyhow::{bail, Context, Result};
use aya::maps::HashMap as BpfHashMap;
use clap::Parser;
use log::{info, warn};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use olopa_common::{TcEgressPolicyKey, TC_POLICY_ACTION_DENY};

use crate::agent::{
    BatcherLike, BatcherPush, EventStoreLike, GraphLike, IngestEvent, MetricAggregatorLike,
    OlopaAgent, RelevanceScorerLike, RuleEngineLike, RuleMatch, SchedulerLike,
};
use crate::budget_tracker::{BudgetSnapshot as RuntimeBudgetSnapshot, BudgetTracker};
use crate::data::batcher_compressor::{
    Batcher as CompressorBatcher, PushResult as CompressorPushResult,
};
use crate::data::csr_graph::{CsrGraph, EdgeKind, EdgeProps, NodeLabel};
use crate::data::event_store::{ColdEvent, EventStore, HotEvent};
use crate::data::mdkp_scheduler::{
    BudgetSnapshot as SchedulerBudgetSnapshot, Scheduler, SolverTier, TelemetryItem, N_RESOURCES,
};
use crate::data::metric_aggregator::{MetricAggregator, MetricSummary};
use crate::data::relevance_scorer::RelevanceScorer;
use crate::probe_manager::{ProbeManager, ProbeSelection};
use crate::runtime_ir::RuntimeIrRuleEngine;
use crate::transport::http_sender::HttpIngestSender;

/// CLI enum for selecting which probe groups to attach at startup.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProbeEventArg {
    Fork,
    Exec,
    File,
    Net,
    Xdp,
    Tc,
}

impl ProbeEventArg {
    /// Map CLI arg variant to probe manager selection enum.
    fn as_selection(self) -> ProbeSelection {
        match self {
            ProbeEventArg::Fork => ProbeSelection::Fork,
            ProbeEventArg::Exec => ProbeSelection::Exec,
            ProbeEventArg::File => ProbeSelection::File,
            ProbeEventArg::Net => ProbeSelection::Net,
            ProbeEventArg::Xdp => ProbeSelection::Xdp,
            ProbeEventArg::Tc => ProbeSelection::Tc,
        }
    }
}

/// Command line options for userspace agent runtime.
#[derive(Debug, Parser)]
#[command(name = "olopa-agent", about = "Olopa kernel security agent")]
struct Opt {
    /// Network interface used by attach helpers.
    #[arg(short, long, default_value = "wlo1")]
    iface: String,
    /// Comma-separated probe groups to attach (fork,exec,file,net,xdp,tc).
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_values_t = [
            ProbeEventArg::Fork,
            ProbeEventArg::Exec,
            ProbeEventArg::File,
            ProbeEventArg::Net
        ]
    )]
    probe_events: Vec<ProbeEventArg>,
    /// Output file path for userspace graph JSON dumps.
    #[arg(long, default_value = "/tmp/olopa_graph.json")]
    graph_dump_path: String,
    /// Minimum interval between graph dump writes in milliseconds.
    #[arg(long, default_value_t = 1000)]
    graph_dump_interval_ms: u64,
}

/// Agent process entrypoint.
///
/// Initializes runtime dependencies, attaches selected probes, and
/// delegates control to the long-running orchestrator loop.
#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("olopa-agent starting | iface={}", opt.iface);

    // 1) Load eBPF object and attach selected probes.
    let mut agent = OlopaAgent::new()?;
    let mut probe_manager = ProbeManager::new();
    let probe_selections = opt
        .probe_events
        .iter()
        .copied()
        .map(ProbeEventArg::as_selection)
        .collect::<Vec<_>>();
    probe_manager.attach_selected(agent.bpf_mut(), &opt.iface, &probe_selections)?;
    if probe_selections.contains(&ProbeSelection::Tc) {
        install_tc_deny_rules_from_env(agent.bpf_mut())?;
    } else if std::env::var("OLOPA_TC_DENY_RULES").is_ok() {
        warn!(
            "OLOPA_TC_DENY_RULES is set but tc probe was not selected; deny rules are not enforced"
        );
    }
    info!(
        "olopa-agent initialized and probes attached | probe_events={}",
        format_probe_selections(&probe_selections)
    );

    // 2) Wire concrete runtime components (adapters + default implementations).
    let mut relevance_scorer = RealRelevanceScorer::default();
    let mut event_store = RealEventStore::default();
    let mut graph = RealGraph::with_dump(
        PathBuf::from(&opt.graph_dump_path),
        Duration::from_millis(opt.graph_dump_interval_ms),
    );
    info!(
        "graph dumps enabled | path={} interval_ms={}",
        opt.graph_dump_path, opt.graph_dump_interval_ms
    );
    let mut metric_aggregator = RealMetricAggregator::default();
    let mut rule_engine = ActiveRuleEngine::from_env()?;
    let mut scheduler = RealScheduler::default();
    let mut batcher = RealBatcher::default();
    let mut sender = HttpIngestSender::from_env();
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
/// Adapter around `RelevanceScorer` that tracks synthetic event ids.
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
    /// Score one event and update its `risk_score` with computed relevance.
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

/// Adapter around persistent hot/cold event storage.
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
    /// Persist one event and return the assigned event id.
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

    /// Serialize one stored event into transport-ready bytes.
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

    /// Return event ids that have not yet been scheduled.
    fn unscheduled_event_ids(&self, from: usize) -> Vec<usize> {
        (from..self.inner.hot_events().len()).collect()
    }

    /// Return last valid event id.
    fn last_event_id(&self) -> usize {
        self.inner.hot_events().len().saturating_sub(1)
    }
}

/// Adapter around RCU CSR graph plus optional periodic graph dump writer.
struct RealGraph {
    inner: Arc<CsrGraph>,
    graph_dumper: Option<GraphDumpWriter>,
    recent_events: VecDeque<GraphDumpEvent>,
    last_span_by_pid: HashMap<u32, u64>,
    next_span_id: u64,
}

impl Default for RealGraph {
    fn default() -> Self {
        Self {
            inner: Arc::new(CsrGraph::new(65_536, 262_144)),
            graph_dumper: None,
            recent_events: VecDeque::with_capacity(MAX_DUMP_EVENTS),
            last_span_by_pid: HashMap::new(),
            next_span_id: 1,
        }
    }
}

impl RealGraph {
    /// Construct graph adapter with JSON dump support enabled.
    fn with_dump(path: PathBuf, min_interval: Duration) -> Self {
        Self {
            inner: Arc::new(CsrGraph::new(65_536, 262_144)),
            graph_dumper: Some(GraphDumpWriter::new(path, min_interval)),
            recent_events: VecDeque::with_capacity(MAX_DUMP_EVENTS),
            last_span_by_pid: HashMap::new(),
            next_span_id: 1,
        }
    }

    /// Cache an event for graph dump rendering and event lineage visualization.
    fn record_event(&mut self, event: &IngestEvent) {
        let graph_source_id = normalize_graph_vertex(event.vertex_id);
        let graph_target_id = normalize_graph_vertex(event.dst_vertex_id);
        let span_id = self.next_span_id;
        self.next_span_id = self.next_span_id.saturating_add(1);
        let parent_span_id = self.last_span_by_pid.insert(event.pid, span_id);

        self.recent_events.push_back(GraphDumpEvent {
            event_id: span_id,
            ts_ns: event.ts_ns,
            event_type: event_type_name(event.event_type).to_string(),
            event_type_code: event.event_type,
            span_id,
            parent_span_id,
            parent_id: event.dst_vertex_id,
            graph_parent_id: graph_target_id,
            pid: event.pid,
            uid: event.uid,
            source_id: event.vertex_id,
            target_id: event.dst_vertex_id,
            graph_source_id,
            graph_target_id,
            comm: event_comm_to_string(&event.comm),
            comm_id: event.comm_id,
            risk_score: event.risk_score,
        });
        while self.recent_events.len() > MAX_DUMP_EVENTS {
            self.recent_events.pop_front();
        }
    }
}

impl GraphLike for RealGraph {
    /// Insert graph edge for one event and trigger optional dump write.
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

        self.inner.write_edge(
            normalize_graph_vertex(event.vertex_id),
            normalize_graph_vertex(event.dst_vertex_id),
            props,
        );
        self.record_event(event);
        if let Some(dumper) = self.graph_dumper.as_mut() {
            if let Err(err) = dumper.maybe_dump(&self.inner, &self.recent_events) {
                warn!("graph dump write failed: {}", err);
            }
        }
    }

    /// Merge queued graph deltas into new snapshot and optionally dump.
    fn merge_deltas(&mut self) {
        self.inner.merge_deltas();
        if let Some(dumper) = self.graph_dumper.as_mut() {
            if let Err(err) = dumper.maybe_dump(&self.inner, &self.recent_events) {
                warn!("graph dump write failed: {}", err);
            }
        }
    }
}

/// Adapter around userspace metric aggregator.
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
    /// Record one event into metric aggregates.
    fn record(&mut self, event: &IngestEvent) {
        // Risk metric keyed by comm_id to preserve low cardinality.
        self.inner.record_risk(event.comm_id, event.risk_score);
    }

    /// Flush metric summaries and serialize each summary into payload bytes.
    fn flush(&mut self) -> Vec<Vec<u8>> {
        self.inner
            .flush()
            .into_iter()
            .map(serialize_metric_summary)
            .collect()
    }
}

/// Adapter around MDKP scheduler.
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
    /// Apply latest budget snapshot to scheduler.
    fn update_budget(&mut self, snapshot: RuntimeBudgetSnapshot) {
        // Convert runtime tracker snapshot into scheduler-local budget type.
        let converted = SchedulerBudgetSnapshot {
            total: snapshot.total,
            remaining: snapshot.remaining,
            weights: snapshot.weights,
        };
        self.inner.update_budget(converted);
    }

    /// Enqueue one event id as scheduler candidate.
    fn enqueue(&mut self, event_id: usize) {
        // Placeholder relevance/cost mapping until full scorer->scheduler bridge is wired.
        let item = TelemetryItem::new(event_id, 0.5, [1.0; N_RESOURCES]);
        self.inner.enqueue(item);
    }

    /// Solve scheduling window and return selected event ids.
    fn solve(&mut self) -> Vec<usize> {
        let selected = self.inner.solve(SolverTier::Greedy).event_ids;
        info!("scheduler.solve selected={} events", selected.len());
        selected
    }
}

// --- Bootstrap components for rule engine, batching, and transport ---

/// Extremely small fallback matcher used only when explicitly enabled.
struct SimpleRuleEngine;

impl RuleEngineLike for SimpleRuleEngine {
    fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch> {
        if event.risk_score >= 0.95 {
            vec![RuleMatch {
                rule_id: "simple:fallback".to_string(),
                rule_name: "simple_fallback_threshold".to_string(),
                enforce_block_egress: false,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Active rule engine mode for the running process.
enum ActiveRuleEngine {
    // Compiler-emitted runtime IR evaluator.
    RuntimeIr(RuntimeIrRuleEngine),
    // Minimal fallback matcher when runtime IR cannot be loaded.
    Simple(SimpleRuleEngine),
}

impl ActiveRuleEngine {
    /// Load runtime-ir rule engine from disk with optional fallback behavior.
    fn from_env() -> Result<Self> {
        const DEFAULT_RUNTIME_IR_PATH: &str = "/etc/olopa/runtime-ir.json";
        // Explicit env var overrides default deployment path.
        let path = std::env::var("OLOPA_RUNTIME_IR")
            .unwrap_or_else(|_| DEFAULT_RUNTIME_IR_PATH.to_string());
        let allow_simple_fallback = env_flag("OLOPA_ALLOW_SIMPLE_RULE_FALLBACK");

        match RuntimeIrRuleEngine::from_file(std::path::Path::new(&path)) {
            Ok(engine) => {
                info!(
                    "rule engine loaded runtime-ir from {} (rules={})",
                    path,
                    engine.rule_count()
                );
                Ok(Self::RuntimeIr(engine))
            }
            Err(e) => {
                if allow_simple_fallback {
                    warn!("failed to load runtime-ir from {}: {}", path, e);
                    warn!(
                        "rule engine using SimpleRuleEngine fallback (OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1)"
                    );
                    Ok(Self::Simple(SimpleRuleEngine))
                } else {
                    bail!(
                        "failed to load runtime-ir from {} (set OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1 to force simple fallback): {}",
                        path,
                        e
                    );
                }
            }
        }
    }
}

/// Read permissive boolean environment flag values (`1/true/yes/on`).
fn env_flag(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let value = v.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone, Copy)]
/// Parsed userspace representation of one deny rule from `OLOPA_TC_DENY_RULES`.
struct TcDenyRule {
    /// Process id to match in TC enforcement key.
    pid: u32,
    /// Canonical IPv4 `u32` form (`u32::from(Ipv4Addr)`).
    dst_ip: u32,
    /// Host-order destination port.
    dst_port: u16,
    /// Layer-4 protocol number (6=tcp, 17=udp).
    proto: u8,
}

impl TcDenyRule {
    /// Convert parsed userspace rule into shared map key format.
    fn as_policy_key(self) -> TcEgressPolicyKey {
        TcEgressPolicyKey {
            pid: self.pid,
            dst_ip: self.dst_ip,
            dst_port: self.dst_port,
            proto: self.proto,
            _pad: 0,
        }
    }
}

/// Load deny policy rules from environment into the kernel TC policy map.
///
/// Env format:
/// - `OLOPA_TC_DENY_RULES='pid=123,ip=1.2.3.4,port=443,proto=tcp;pid=77,ip=8.8.8.8,port=53,proto=udp'`
///
/// Behavior:
/// - Missing env var: no-op.
/// - Parse errors: startup fails loudly to avoid silently partial policy.
/// - Successful parse: each rule inserted with deny action byte.
fn install_tc_deny_rules_from_env(bpf: &mut aya::Ebpf) -> Result<()> {
    let raw = match std::env::var("OLOPA_TC_DENY_RULES") {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let rules = parse_tc_deny_rules(&raw)?;
    if rules.is_empty() {
        warn!("OLOPA_TC_DENY_RULES is set but no rules were parsed");
        return Ok(());
    }

    let map_data = bpf
        .map_mut("TC_EGRESS_POLICY")
        .context("TC_EGRESS_POLICY map not found in loaded eBPF object")?;
    let mut policy_map: BpfHashMap<_, TcEgressPolicyKey, u8> =
        BpfHashMap::try_from(map_data).context("failed to open TC_EGRESS_POLICY map")?;

    for rule in rules {
        let key = rule.as_policy_key();
        policy_map
            .insert(key, TC_POLICY_ACTION_DENY, 0)
            .with_context(|| {
                format!(
                    "failed to insert tc deny rule pid={} dst_ip={} dst_port={} proto={}",
                    rule.pid,
                    Ipv4Addr::from(rule.dst_ip),
                    rule.dst_port,
                    rule.proto
                )
            })?;
        info!(
            "tc-policy deny installed pid={} dst={}:{} proto={}",
            rule.pid,
            Ipv4Addr::from(rule.dst_ip),
            rule.dst_port,
            rule.proto
        );
    }

    Ok(())
}

/// Parse deny rule spec string into normalized rule structs.
///
/// Grammar (semicolon-separated entries):
/// - entry = `pid=<u32>,ip=<ipv4>,port=<u16>[,proto=<tcp|udp|6|17>]`
/// - supported key aliases: `dst_ip`, `dst_port`
///
/// Notes:
/// - `proto` defaults to tcp (`6`) when omitted.
/// - unknown keys and missing required keys are treated as hard errors.
fn parse_tc_deny_rules(raw: &str) -> Result<Vec<TcDenyRule>> {
    let mut out = Vec::new();
    for (idx, entry_raw) in raw.split(';').enumerate() {
        let entry = entry_raw.trim();
        if entry.is_empty() {
            continue;
        }

        let mut pid: Option<u32> = None;
        let mut dst_ip: Option<u32> = None;
        let mut dst_port: Option<u16> = None;
        let mut proto: Option<u8> = None;

        for part in entry.split(',') {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            let Some((k, v)) = token.split_once('=') else {
                bail!(
                    "invalid TC deny rule token '{}': expected key=value format in rule '{}'",
                    token,
                    entry
                );
            };
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim();
            match key.as_str() {
                "pid" => {
                    pid = Some(value.parse::<u32>().with_context(|| {
                        format!("invalid pid '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                "ip" | "dst_ip" => {
                    let ip = value.parse::<Ipv4Addr>().with_context(|| {
                        format!("invalid IPv4 '{}' in TC deny rule '{}'", value, entry)
                    })?;
                    dst_ip = Some(u32::from(ip));
                }
                "port" | "dst_port" => {
                    dst_port = Some(value.parse::<u16>().with_context(|| {
                        format!("invalid port '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                "proto" => {
                    proto = Some(parse_l4_proto(value).with_context(|| {
                        format!("invalid proto '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                _ => {
                    bail!(
                        "unsupported key '{}' in TC deny rule '{}' (supported: pid, ip, port, proto)",
                        key,
                        entry
                    );
                }
            }
        }

        let pid = pid.with_context(|| format!("missing pid in TC deny rule '{}'", entry))?;
        let dst_ip = dst_ip.with_context(|| format!("missing ip in TC deny rule '{}'", entry))?;
        let dst_port =
            dst_port.with_context(|| format!("missing port in TC deny rule '{}'", entry))?;
        let proto = proto.unwrap_or(6);

        out.push(TcDenyRule {
            pid,
            dst_ip,
            dst_port,
            proto,
        });

        if out.len() > 32_768 {
            bail!("too many TC deny rules parsed (>{}) at rule index {}", 32_768, idx);
        }
    }

    Ok(out)
}

/// Parse protocol string token into numeric protocol id used by TC map keys.
fn parse_l4_proto(raw: &str) -> Result<u8> {
    let value = raw.trim().to_ascii_lowercase();
    match value.as_str() {
        "tcp" | "6" => Ok(6),
        "udp" | "17" => Ok(17),
        _ => bail!("unsupported proto '{}', expected tcp|udp|6|17", raw),
    }
}

#[cfg(test)]
mod tc_policy_tests {
    use super::*;

    #[test]
    fn parse_tc_deny_rules_accepts_valid_entries() {
        let spec = "pid=123,ip=1.2.3.4,port=443,proto=tcp;pid=7,ip=8.8.8.8,port=53,proto=17";
        let rules = parse_tc_deny_rules(spec).expect("valid tc deny rule spec should parse");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pid, 123);
        assert_eq!(rules[0].dst_ip, u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(rules[0].dst_port, 443);
        assert_eq!(rules[0].proto, 6);
        assert_eq!(rules[1].proto, 17);
    }

    #[test]
    fn parse_tc_deny_rules_rejects_missing_required_fields() {
        let spec = "pid=123,port=443,proto=tcp";
        let err = parse_tc_deny_rules(spec).expect_err("missing ip should fail");
        assert!(
            err.to_string().contains("missing ip"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_l4_proto_supports_names_and_numbers() {
        assert_eq!(parse_l4_proto("tcp").expect("tcp should parse"), 6);
        assert_eq!(parse_l4_proto("17").expect("17 should parse"), 17);
        assert!(parse_l4_proto("icmp").is_err());
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

/// Adapter around compression batcher.
struct RealBatcher {
    inner: CompressorBatcher,
}

impl Default for RealBatcher {
    fn default() -> Self {
        let agent_id = std::env::var("OLOPA_AGENT_ID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        Self {
            inner: CompressorBatcher::new(agent_id, 4_096),
        }
    }
}

impl BatcherLike for RealBatcher {
    /// Push one event payload into compression batcher.
    fn push(&mut self, serialized_event: &[u8], _budget: &RuntimeBudgetSnapshot) -> BatcherPush {
        let budget = SchedulerBudgetSnapshot {
            total: _budget.total,
            remaining: _budget.remaining,
            weights: _budget.weights,
        };

        match self.inner.push(serialized_event, &budget) {
            CompressorPushResult::Ok => BatcherPush::Ok,
            CompressorPushResult::FlushNeeded | CompressorPushResult::QueueFull => {
                BatcherPush::FlushNeeded
            }
        }
    }

    /// Force flush currently buffered payloads.
    fn flush(&mut self) -> Option<Vec<u8>> {
        self.inner.flush().map(|batch| batch.payload.to_vec())
    }

    /// Flush only if time-based trigger has elapsed.
    fn flush_if_time_triggered(&mut self) -> Option<Vec<u8>> {
        self.inner
            .flush_if_ready()
            .map(|batch| batch.payload.to_vec())
    }
}

/// Encode metric summary in current text wire format.
fn serialize_metric_summary(s: MetricSummary) -> Vec<u8> {
    // Bootstrap text wire format for metric snapshots.
    format!(
        "metric comm_id={} count={} min={:.4} max={:.4} mean={:.4} p50={:.4} p95={:.4} p99={:.4}",
        s.comm_id, s.count, s.min, s.max, s.mean, s.p50, s.p95, s.p99
    )
    .into_bytes()
}

/// JSON node model for graph dumps consumed by UI/debug tools.
#[derive(Serialize)]
struct GraphDumpNode {
    id: u32,
    display_label: String,
    kind: String,
    risk_score: f32,
    is_internal: bool,
    is_canary: bool,
    out_degree: u32,
}

/// JSON edge model for graph dumps.
#[derive(Serialize)]
struct GraphDumpEdge {
    source: u32,
    target: u32,
    kind: String,
    edge_origin: String,
    risk_weight: u8,
    ts_ns: u64,
    causal: bool,
    bytes: u32,
    event_type: Option<String>,
    span_id: Option<u64>,
    parent_span_id: Option<u64>,
}

/// Top-level graph dump payload persisted by userspace runtime.
#[derive(Serialize)]
struct GraphDumpPayload {
    generated_at_unix_ns: u64,
    total_nodes: u32,
    total_edges: u32,
    graph_edges: usize,
    event_edges: usize,
    snapshot_nodes: u32,
    snapshot_edges: u32,
    total_events: usize,
    nodes: Vec<GraphDumpNode>,
    edges: Vec<GraphDumpEdge>,
    events: Vec<GraphDumpEvent>,
}

/// Recent event record embedded alongside graph topology in dumps.
#[derive(Serialize, Clone)]
struct GraphDumpEvent {
    event_id: u64,
    ts_ns: u64,
    event_type: String,
    event_type_code: u8,
    span_id: u64,
    parent_span_id: Option<u64>,
    parent_id: u32,
    graph_parent_id: u32,
    pid: u32,
    uid: u32,
    source_id: u32,
    target_id: u32,
    graph_source_id: u32,
    graph_target_id: u32,
    comm: String,
    comm_id: u32,
    risk_score: f32,
}

/// File writer responsible for periodic graph snapshot dumps.
struct GraphDumpWriter {
    path: PathBuf,
    min_interval: Duration,
    last_dump_at: Option<Instant>,
}

impl GraphDumpWriter {
    /// Create dump writer bound to output file and rate limit interval.
    fn new(path: PathBuf, min_interval: Duration) -> Self {
        Self {
            path,
            min_interval,
            last_dump_at: None,
        }
    }

    /// Persist graph dump only when minimum interval has elapsed.
    fn maybe_dump(
        &mut self,
        graph: &CsrGraph,
        recent_events: &VecDeque<GraphDumpEvent>,
    ) -> Result<()> {
        if let Some(last_dump_at) = self.last_dump_at {
            if last_dump_at.elapsed() < self.min_interval {
                return Ok(());
            }
        }

        let payload = build_graph_dump_payload(graph, recent_events);
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let tmp_path = self.path.with_extension("tmp");
        let body = serde_json::to_vec_pretty(&payload)?;
        fs::write(&tmp_path, body)?;
        fs::rename(&tmp_path, &self.path)?;

        self.last_dump_at = Some(Instant::now());
        Ok(())
    }
}

/// Build a dump payload by combining graph snapshot + recent events.
fn build_graph_dump_payload(
    graph: &CsrGraph,
    recent_events: &VecDeque<GraphDumpEvent>,
) -> GraphDumpPayload {
    let snapshot = graph.snapshot();
    let mut active_nodes = HashSet::new();
    let mut latest_comm_by_graph_pid: HashMap<u32, String> = HashMap::new();

    let mut graph_edge_count = 0usize;
    let mut edges = Vec::with_capacity(snapshot.num_edges as usize);
    for src in 0..snapshot.num_nodes {
        let neighbors = snapshot.neighbors(src);
        let props = snapshot.neighbor_props(src);
        for (idx, &dst) in neighbors.iter().enumerate() {
            active_nodes.insert(src);
            active_nodes.insert(dst);
            let p = props[idx];
            edges.push(GraphDumpEdge {
                source: src,
                target: dst,
                kind: edge_kind_name(p.kind).to_string(),
                edge_origin: "graph".to_string(),
                risk_weight: p.risk_weight,
                ts_ns: p.ts_ns,
                causal: p.causal,
                bytes: p.bytes,
                event_type: None,
                span_id: None,
                parent_span_id: None,
            });
            graph_edge_count = graph_edge_count.saturating_add(1);
        }
    }

    for event in recent_events {
        active_nodes.insert(event.graph_source_id);
        active_nodes.insert(event.graph_target_id);
        active_nodes.insert(event.graph_parent_id);
        latest_comm_by_graph_pid
            .entry(normalize_graph_vertex(event.pid))
            .or_insert_with(|| event.comm.clone());

        edges.push(GraphDumpEdge {
            source: event.graph_source_id,
            target: event.graph_target_id,
            kind: format!("event.{}", event.event_type),
            edge_origin: "event".to_string(),
            risk_weight: (event.risk_score.clamp(0.0, 1.0) * 255.0) as u8,
            ts_ns: event.ts_ns,
            causal: true,
            bytes: 0,
            event_type: Some(event.event_type.clone()),
            span_id: Some(event.span_id),
            parent_span_id: event.parent_span_id,
        });
    }
    let event_edge_count = edges.len().saturating_sub(graph_edge_count);

    let mut ordered_nodes = active_nodes.into_iter().collect::<Vec<_>>();
    ordered_nodes.sort_unstable();

    let mut nodes = Vec::with_capacity(ordered_nodes.len());
    for id in ordered_nodes {
        let n = snapshot.node(id);
        let display_label = if n.label == NodeLabel::Process {
            if let Some(comm) = latest_comm_by_graph_pid.get(&id) {
                if !comm.is_empty() {
                    format!("Process {} (#{})", comm, id)
                } else {
                    format!("Process #{}", id)
                }
            } else {
                format!("Process #{}", id)
            }
        } else {
            format!("{} #{}", node_label_name(n.label), id)
        };

        nodes.push(GraphDumpNode {
            id,
            display_label,
            kind: node_label_name(n.label).to_string(),
            risk_score: n.risk_score,
            is_internal: n.is_internal,
            is_canary: n.is_canary,
            out_degree: snapshot.degree(id),
        });
    }

    GraphDumpPayload {
        generated_at_unix_ns: now_unix_ns(),
        total_nodes: nodes.len() as u32,
        total_edges: edges.len() as u32,
        graph_edges: graph_edge_count,
        event_edges: event_edge_count,
        snapshot_nodes: snapshot.num_nodes,
        snapshot_edges: snapshot.num_edges,
        total_events: recent_events.len(),
        nodes,
        edges,
        events: recent_events.iter().cloned().collect(),
    }
}

/// Current wall-clock timestamp in nanoseconds since UNIX epoch.
fn now_unix_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

/// Render node label as human-readable name.
fn node_label_name(label: NodeLabel) -> &'static str {
    match label {
        NodeLabel::Process => "Process",
        NodeLabel::File => "File",
        NodeLabel::NetworkEndpoint => "NetworkEndpoint",
        NodeLabel::User => "User",
        NodeLabel::Host => "Host",
        NodeLabel::Secret => "Secret",
        NodeLabel::AgentSession => "AgentSession",
        NodeLabel::ToolCall => "ToolCall",
        NodeLabel::Container => "Container",
        NodeLabel::DomainName => "DomainName",
    }
}

/// Render edge kind as human-readable name.
fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Spawned => "Spawned",
        EdgeKind::ReadFile => "ReadFile",
        EdgeKind::WroteFile => "WroteFile",
        EdgeKind::ConnectedTo => "ConnectedTo",
        EdgeKind::AccessedSecret => "AccessedSecret",
        EdgeKind::LateralMove => "LateralMove",
        EdgeKind::RanAs => "RanAs",
        EdgeKind::DataFlow => "DataFlow",
        EdgeKind::CalledTool => "CalledTool",
        EdgeKind::ResolvedDns => "ResolvedDns",
        EdgeKind::ExecIn => "ExecIn",
        EdgeKind::HasProcess => "HasProcess",
    }
}

/// Render numeric event type to stable string label.
fn event_type_name(event_type: u8) -> &'static str {
    match event_type {
        1 => "exec",
        2 => "file",
        3 => "net",
        _ => "unknown",
    }
}

/// Convert 16-byte null-terminated comm buffer into UTF-8 string.
fn event_comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    std::str::from_utf8(&comm[..end]).unwrap_or("").to_string()
}

/// Maximum number of recent events retained in dump payload.
const MAX_DUMP_EVENTS: usize = 10_000;
/// Fixed graph id space used by current bootstrap graph allocator.
const GRAPH_NODE_SPACE: u32 = 65_536;

/// Map arbitrary vertex ids into current fixed graph id space.
fn normalize_graph_vertex(vertex_id: u32) -> u32 {
    if GRAPH_NODE_SPACE == 0 {
        return 0;
    }
    vertex_id % GRAPH_NODE_SPACE
}

/// Format attached probe selections for startup logs.
fn format_probe_selections(selections: &[ProbeSelection]) -> String {
    selections
        .iter()
        .map(|selection| probe_selection_name(*selection))
        .collect::<Vec<_>>()
        .join(",")
}

/// Render one probe selection as CLI-style token.
fn probe_selection_name(selection: ProbeSelection) -> &'static str {
    match selection {
        ProbeSelection::Fork => "fork",
        ProbeSelection::Exec => "exec",
        ProbeSelection::File => "file",
        ProbeSelection::Net => "net",
        ProbeSelection::Xdp => "xdp",
        ProbeSelection::Tc => "tc",
    }
}
