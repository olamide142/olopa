//! Olopa agent — userspace orchestrator.
//!
//! Loads the compiled eBPF ELF, attaches each program to its kernel hook,
//! and reads events from the shared ring buffer in an async Tokio loop.
//!
//! Attachment map:
//!   xdp_filter  → XDP hook on <iface>        (NIC driver level, ~150ns)
//!   tc_egress   → TC clsact egress on <iface> (after routing, has PID context)
//!   on_sched_process_fork → tracepoint sched/sched_process_fork
//!   on_execve   → tracepoint syscalls/sys_enter_execve
//!   on_openat   → tracepoint syscalls/sys_enter_openat
//!   on_connect  → tracepoint syscalls/sys_enter_connect
//!
//! WiFi vs Ethernet:
//!   XDP native mode requires driver support — most wired NICs support it.
//!   WiFi drivers (wlo1, wlan0) almost never do. The agent automatically
//!   falls back to XDP SKB_MODE which works on all interfaces but is slower.
//!   TC works on all interface types without a fallback needed.
mod agent;
mod budget_tracker;
mod probe_manager;
mod data;

use anyhow::Result;

use clap::Parser;
use log::info;
use std::time::{
    Duration, Instant
};

use crate::agent::{
    BatcherLike, BatcherPush, 
    EventStoreLike, GraphLike, 
    IngestEvent, MetricAggregatorLike, 
    OlopaAgent, RelevanceScorerLike, 
    RuleEngineLike, SchedulerLike,
    SenderLike, SenderStats,
};
use crate::budget_tracker::{
    BudgetSnapshot, BudgetTracker
};
use crate::probe_manager::ProbeManager;


// ── CLI

#[derive(Debug, Parser)]
#[command(name = "olopa-agent", about = "Olopa kernel security agent")]
struct Opt {
    /// Network interface to attach XDP and TC programs to.
    /// Use `ip link show` to find your interface name.
    /// Examples: eth0, ens3, wlo1, wlan0
    #[arg(short, long, default_value = "wlo1")]
    iface: String,
}

// ── Entry point 

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI args and initialize logger first so every later step is observable.
    let opt = Opt::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    info!("olopa-agent starting | iface={}", opt.iface);

    // 1) Load embedded eBPF object + maps into userspace handle.
    let mut agent: OlopaAgent = OlopaAgent::new()?;

    // 2) Attach kernel probes (tracepoint/XDP/TC depending on ProbeManager policy).
    let mut probe_manager = ProbeManager::new();
    probe_manager.attach_defaults(agent.bpf_mut(), &opt.iface)?;
    info!("olopa-agent initialized and probes attached");

    // 3) Wire concrete runtime components.
    // These `Simple*` implementations are intentionally lightweight bootstrap
    // adapters so we can run the orchestrator loop end-to-end today.
    let mut relevance_scorer = SimpleRelevanceScorer;
    let mut event_store = SimpleEventStore::default();
    let mut graph = SimpleGraph::default();
    let mut metric_aggregator = SimpleMetricAggregator::default();
    let mut rule_engine = SimpleRuleEngine;
    let mut scheduler = SimpleScheduler::default();
    let mut batcher = SimpleBatcher::default();
    let mut sender = SimpleSender::default();
    let mut budget_tracker = BudgetTracker::new();

    // 4) Hand control to the orchestrator. This call blocks until shutdown
    // (Ctrl-C) and runs ingest/scheduler/housekeeping loops internally.
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
        .await?;

    Ok(())
    // When bpf drops here, Aya automatically detaches all attached programs.
}

// --- Simple bootstrap components ---
// These keep main.rs runnable while the full production components are being
// wired. They satisfy the trait contracts expected by `agent.run(...)`.

// Minimal scorer: only clamps risk into [0,1].
#[derive(Default)]
struct SimpleRelevanceScorer;
impl RelevanceScorerLike for SimpleRelevanceScorer {
    fn score(&mut self, event: &mut IngestEvent) {
        event.risk_score = event.risk_score.clamp(0.0, 1.0);
    }
}

// In-memory event buffer used by scheduler/batcher path in bootstrap mode.
#[derive(Default)]
struct SimpleEventStore {
    // Append-only list of events; index serves as event_id.
    events: Vec<IngestEvent>,
}
impl EventStoreLike for SimpleEventStore {
    fn push(&mut self, event: IngestEvent) -> Option<usize> {
        // Store event and return its index so scheduler can reference it later.
        self.events.push(event);
        Some(self.events.len() - 1)
    }

    fn serialize_event(&self, event_id: usize) -> Option<Vec<u8>> {
        // Convert selected event into wire-ready bytes.
        self.events.get(event_id).map(|e| {
            format!(
                "evt ts={} pid={} uid={} type={} risk={:.3} src={} dst={} comm={}",
                e.ts_ns, e.pid, e.uid, e.event_type, e.risk_score, e.vertex_id, e.dst_vertex_id, e.comm_id
            )
            .into_bytes()
        })
    }

    fn unscheduled_event_ids(&self, from: usize) -> Vec<usize> {
        // Return all new event indices since the caller's cursor.
        (from..self.events.len()).collect()
    }

    fn last_event_id(&self) -> usize {
        // Defensive helper (currently unused in bootstrap path).
        self.events.len().saturating_sub(1)
    }
}

// Minimal graph sink: just counts pending writes until merge.
#[derive(Default)]
struct SimpleGraph {
    pending_edges: usize,
}
impl GraphLike for SimpleGraph {
    fn write_edge(&mut self, _event: &IngestEvent) {
        // Production graph would persist src->dst with metadata here.
        self.pending_edges += 1;
    }

    fn merge_deltas(&mut self) {
        // Housekeeping fold: clear pending count.
        self.pending_edges = 0;
    }
}

// Minimal metrics collector: counts samples and emits one summary blob per flush.
#[derive(Default)]
struct SimpleMetricAggregator {
    samples: u64,
}
impl MetricAggregatorLike for SimpleMetricAggregator {
    fn record(&mut self, _event: &IngestEvent) {
        // Production implementation would digest risk/latency distributions.
        self.samples += 1;
    }

    fn flush(&mut self) -> Vec<Vec<u8>> {
        // Emit a single compact summary payload if any samples were observed.
        if self.samples == 0 {
            return Vec::new();
        }
        let out = vec![format!("metric samples={}", self.samples).into_bytes()];
        self.samples = 0;
        out
    }
}

// Minimal rule engine: fires only at very high risk.
struct SimpleRuleEngine;
impl RuleEngineLike for SimpleRuleEngine {
    fn evaluate(&mut self, event: &IngestEvent) -> bool {
        event.risk_score >= 0.95
    }
}

// Minimal scheduler:
// - queue event_ids during ingest
// - on solve(), select everything queued (no optimization yet)
struct SimpleScheduler {
    pending: Vec<usize>,
    // Kept to honor update_budget() contract.
    _budget: BudgetSnapshot,
}
impl Default for SimpleScheduler {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            _budget: BudgetSnapshot::default_budgets(),
        }
    }
}
impl SchedulerLike for SimpleScheduler {
    fn update_budget(&mut self, snapshot: BudgetSnapshot) {
        // In production this influences solve decisions.
        self._budget = snapshot;
    }

    fn enqueue(&mut self, event_id: usize) {
        // Save candidate event_id for next 500ms scheduler solve.
        self.pending.push(event_id);
    }

    fn solve(&mut self) -> Vec<usize> {
        // Return all currently queued IDs and clear queue.
        std::mem::take(&mut self.pending)
    }
}

// Minimal batcher:
// - buffers serialized events
// - triggers flush by size (64 entries) or 500ms timer
struct SimpleBatcher {
    pending: Vec<Vec<u8>>,
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
    fn push(&mut self, serialized_event: &[u8], _budget: &BudgetSnapshot) -> BatcherPush {
        // Copy event bytes into pending queue.
        self.pending.push(serialized_event.to_vec());
        if self.pending.len() >= 64 {
            BatcherPush::FlushNeeded
        } else {
            BatcherPush::Ok
        }
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        // Join all pending frames into one payload separated by newlines.
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
        // Independent periodic trigger used by scheduler tick.
        if self.last_flush.elapsed() >= Duration::from_millis(500) {
            self.flush()
        } else {
            None
        }
    }
}

// Minimal sender:
// - if spooling=false, counts "sent" payloads
// - if spooling=true, stores payloads in memory spool
#[derive(Default)]
struct SimpleSender {
    sent: u64,
    spooled: Vec<Vec<u8>>,
    spooling: bool,
}
impl SenderLike for SimpleSender {
    fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()> {
        // Fast path sends immediately unless backpressure mode is enabled.
        if self.spooling {
            self.spooled.push(payload);
        } else {
            self.sent += 1;
            info!("sent payload #{}", self.sent);
        }
        Ok(())
    }

    fn stats(&self) -> SenderStats {
        // Expose spool depth so housekeeping can decide replay behavior.
        let pending: u64 = self.spooled.iter().map(|b| b.len() as u64).sum();
        SenderStats {
            spool_pending_bytes: pending,
            spooling: self.spooling,
        }
    }

    fn drain_spool(&mut self, deadline: Instant) -> Result<usize> {
        // Best-effort replay until queue drained or deadline expires.
        let mut drained = 0usize;
        while !self.spooled.is_empty() && Instant::now() < deadline {
            self.spooled.remove(0);
            drained += 1;
        }
        Ok(drained)
    }
}
