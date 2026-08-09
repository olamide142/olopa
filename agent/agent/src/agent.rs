//! Core userspace orchestrator.
//!
//! This module owns the hot ingest loop and periodic maintenance loops:
//! - ingest: decode ring-buffer events, score/store/graph/metrics/rules.
//! - scheduler tick: select and send budgeted telemetry.
//! - housekeeping tick: update budgets, flush metrics, merge graph, drain spool.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::RingBuf, Ebpf};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use olopa_common::{DnsEvent, ExecEvent, FileEvent, NetEvent, SqlEvent, SslEvent};
use serde::Serialize;
use tokio::signal;

use crate::budget_tracker::{BudgetTracker, BW, CPU, MEM};

const DEFAULT_STATUS_PATH: &str = "/tmp/olopa/agent/status.json";
const DEFAULT_CPU_BUDGET_PCT: f32 = 5.0;

// Canonical in-memory event representation used by the orchestrator.
// This struct is what flows through the hot ingest pipeline.
#[derive(Clone, Copy, Debug)]
pub struct IngestEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u8, // 1=exec, 2=file, 3=net, 4=sql, 5=ssl, 6=dns
    pub vertex_id: u32,
    pub dst_vertex_id: u32,
    // Host-endian IPv4 destination and destination port for net events.
    pub net_dst_ip: u32,
    pub net_dst_port: u16,
    pub comm: [u8; 16],
    pub comm_id: u32,
    pub risk_score: f32,
    // SQL event fields (event_type == 4); zeroed for other event types.
    pub sql_query_hash: u32,  // FNV-1a hash of query text
    pub sql_query_class: u8,  // 0=other 1=select 2=dml 3=ddl 4=admin
    pub sql_db_port: u16,     // 5432 or 3306
    // SSL event fields (event_type == 5); zeroed for other event types.
    pub ssl_data_len: u32,    // bytes processed in this EVP_Encrypt/DecryptUpdate call
    pub ssl_operation: u8,    // 0=encrypt 1=decrypt
    pub _pad_aux: [u8; 2],
    // DNS event fields (event_type == 6); zeroed for other event types.
    pub dns_query_hash: u32,  // FNV-1a hash of queried hostname
    pub dns_query: [u8; 64],  // NUL-terminated queried hostname
}

// Hand-written because `[u8; 64]` has no std `Default` impl. Lets callers and
// fixtures set only the fields their event family populates and leave the
// rest zeroed, which is exactly the ring-buffer decoding contract.
impl Default for IngestEvent {
    fn default() -> Self {
        Self {
            ts_ns: 0,
            pid: 0,
            uid: 0,
            event_type: 0,
            vertex_id: 0,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            sql_query_hash: 0,
            sql_query_class: 0,
            sql_db_port: 0,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 0,
            dns_query: [0; 64],
        }
    }
}

// Minimal sender state queried by housekeeping to decide spool replay behavior.
#[derive(Clone, Debug, Default)]
pub struct SenderStats {
    pub spool_pending_bytes: u64,
    pub spooling: bool,
    pub backend_reachable: Option<bool>,
    pub backend_rtt_ms: Option<u64>,
}

// Return value from batcher.push() so caller knows whether to flush now.
pub enum BatcherPush {
    Ok,
    FlushNeeded,
}

// Structured rule-match output for one event evaluation.
#[derive(Clone, Debug)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    // Rule contains an explicit `block egress ...` response action.
    pub enforce_block_egress: bool,
}

// Scorer contract used by ingest loop.
pub trait RelevanceScorerLike {
    /// Mutate event in place with updated risk/relevance score.
    fn score(&mut self, event: &mut IngestEvent);
}

// Event store contract used by ingest/scheduler loops.
pub trait EventStoreLike {
    /// Persist one event and return its ID.
    fn push(&mut self, event: IngestEvent) -> Option<usize>;
    /// Serialize persisted event by ID for telemetry transport.
    fn serialize_event(&self, event_id: usize) -> Option<Vec<u8>>;
    /// Return event IDs not yet scheduled, starting from cursor.
    fn unscheduled_event_ids(&self, from: usize) -> Vec<usize>;
    /// Return most recent event ID.
    fn last_event_id(&self) -> usize;
}

// Graph contract used by ingest (write) and housekeeping (merge).
pub trait GraphLike {
    /// Project event into graph delta structures.
    fn write_edge(&mut self, event: &IngestEvent);
    /// Merge buffered graph deltas into read snapshot.
    fn merge_deltas(&mut self);
}

// Metrics contract used by ingest and housekeeping flush.
pub trait MetricAggregatorLike {
    /// Record event metrics into rolling aggregation state.
    fn record(&mut self, event: &IngestEvent);
    /// Flush aggregated summaries into transport-ready payloads.
    fn flush(&mut self) -> Vec<Vec<u8>>;
}

// Rule evaluation contract; returns all matching rules for the event.
pub trait RuleEngineLike {
    /// Evaluate event and return all matching rules.
    fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch>;
}

// Scheduler contract for telemetry selection (not alert path).
pub trait SchedulerLike {
    /// Refresh scheduler budgets from runtime controller.
    fn update_budget(&mut self, snapshot: crate::budget_tracker::BudgetSnapshot);
    /// Add event ID as candidate for next solve window.
    fn enqueue(&mut self, event_id: usize);
    /// Solve and return selected event IDs.
    fn solve(&mut self) -> Vec<usize>;
}

// Batcher contract for scheduler-selected telemetry payloads.
pub trait BatcherLike {
    /// Push serialized telemetry bytes into batch accumulator.
    fn push(
        &mut self,
        serialized_event: &[u8],
        budget: &crate::budget_tracker::BudgetSnapshot,
    ) -> BatcherPush;
    /// Flush current batch immediately.
    fn flush(&mut self) -> Option<Vec<u8>>;
    /// Flush current batch when time trigger fires.
    fn flush_if_time_triggered(&mut self) -> Option<Vec<u8>>;
}

// Sender contract for alert fast-lane + telemetry batches + spool recovery.
pub trait SenderLike {
    /// Send payload immediately or spool based on sender health/backpressure.
    fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()>;
    /// Return sender/spool status for housekeeping logic.
    fn stats(&self) -> SenderStats;
    /// Replay spooled payloads until deadline.
    fn drain_spool(&mut self, deadline: Instant) -> Result<usize>;
}

#[derive(Default)]
struct IngestLoopStats {
    processed: usize,
    firewall_allow: u64,
    firewall_deny: u64,
    firewall_approve: u64,
}

#[derive(Default)]
struct SchedulerLoopStats {
    candidates: usize,
    selected: usize,
    selected_bytes: u64,
}

#[derive(Serialize)]
struct RuntimeStatusSnapshot {
    version: u8,
    generated_at_unix_ms: u64,
    pid: u32,
    running: bool,
    iface: String,
    probes: Vec<String>,
    backend: RuntimeBackendStatus,
    resources: RuntimeResourceStatus,
    window_5s: RuntimeWindowStatus,
    firewall: RuntimeFirewallStatus,
}

#[derive(Serialize)]
struct RuntimeBackendStatus {
    reachable: bool,
    rtt_ms: Option<u64>,
}

#[derive(Serialize)]
struct RuntimeResourceStatus {
    cpu_pct: f32,
    cpu_budget_pct: f32,
    mem_mb: f32,
    mem_ceiling_mb: f32,
    bw_mb_s: f32,
    bw_limit_pct: f32,
}

#[derive(Serialize)]
struct RuntimeWindowStatus {
    captured: u64,
    transmitted: u64,
    dropped_budget: u64,
}

#[derive(Serialize)]
struct RuntimeFirewallStatus {
    allow: u64,
    deny: u64,
    approve: u64,
}

struct StatusReporter {
    path: PathBuf,
    iface: String,
    probes: Vec<String>,
}

impl StatusReporter {
    fn from_env() -> Self {
        let path = std::env::var("OLOPA_STATUS_PATH")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_STATUS_PATH.to_string());
        let iface = std::env::var("OLOPA_ACTIVE_IFACE")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let probes = std::env::var("OLOPA_PROBE_EVENTS_ACTIVE")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Self {
            path: PathBuf::from(path),
            iface,
            probes,
        }
    }

    fn write(&self, snapshot: &RuntimeStatusSnapshot) {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(err) = fs::create_dir_all(parent) {
                    warn!(
                        "status snapshot mkdir failed path={}: {}",
                        parent.display(),
                        err
                    );
                    return;
                }
            }
        }

        let tmp = self.path.with_extension("tmp");
        let body = match serde_json::to_vec_pretty(snapshot) {
            Ok(v) => v,
            Err(err) => {
                warn!("status snapshot serialize failed: {}", err);
                return;
            }
        };

        if let Err(err) = fs::write(&tmp, body) {
            warn!(
                "status snapshot write failed path={}: {}",
                tmp.display(),
                err
            );
            return;
        }
        if let Err(err) = fs::rename(&tmp, &self.path) {
            warn!(
                "status snapshot rename failed {} -> {}: {}",
                tmp.display(),
                self.path.display(),
                err
            );
        }
    }

    fn build_snapshot(
        &self,
        budget_tracker: &BudgetTracker,
        sender_stats: &SenderStats,
        captured: u64,
        transmitted: u64,
        dropped_budget: u64,
        transmitted_bytes: u64,
        firewall_allow: u64,
        firewall_deny: u64,
        firewall_approve: u64,
    ) -> RuntimeStatusSnapshot {
        let snapshot = budget_tracker.snapshot();
        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get() as f32)
            .unwrap_or(1.0)
            .max(1.0);
        let cpu_util = if snapshot.total[CPU] > 0.0 {
            1.0 - (snapshot.remaining[CPU] / snapshot.total[CPU]).clamp(0.0, 1.0)
        } else {
            0.0
        };
        // Convert host-normalized process utilization into per-core normalized
        // percentage so one saturated core is shown as ~100%.
        let cpu_pct_per_core = cpu_util * 100.0 * logical_cores;
        let cpu_budget_pct_per_core = DEFAULT_CPU_BUDGET_PCT * logical_cores;
        let bw_limit_pct = if snapshot.total[BW] > 0.0 {
            ((transmitted_bytes as f32 / snapshot.total[BW]) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        RuntimeStatusSnapshot {
            version: 1,
            generated_at_unix_ms: now_unix_ms(),
            pid: std::process::id(),
            running: true,
            iface: self.iface.clone(),
            probes: self.probes.clone(),
            backend: RuntimeBackendStatus {
                reachable: sender_stats.backend_reachable.unwrap_or(false),
                rtt_ms: sender_stats.backend_rtt_ms,
            },
            resources: RuntimeResourceStatus {
                cpu_pct: cpu_pct_per_core,
                cpu_budget_pct: cpu_budget_pct_per_core,
                mem_mb: (snapshot.total[MEM] - snapshot.remaining[MEM]) / 1_048_576.0,
                mem_ceiling_mb: snapshot.total[MEM] / 1_048_576.0,
                bw_mb_s: transmitted_bytes as f32 / 5.0 / 1_048_576.0,
                bw_limit_pct,
            },
            window_5s: RuntimeWindowStatus {
                captured,
                transmitted,
                dropped_budget,
            },
            firewall: RuntimeFirewallStatus {
                allow: firewall_allow,
                deny: firewall_deny,
                approve: firewall_approve,
            },
        }
    }
}

// Main agent owner. Holds loaded eBPF object and orchestrates all loops.
pub struct OlopaAgent {
    bpf: Ebpf,
}

impl OlopaAgent {
    // Build agent by loading embedded eBPF bytes from build OUT_DIR.
    pub fn new() -> Result<Self> {
        let bpf = Self::load_ebpf_program()?;
        Ok(Self { bpf })
    }

    fn load_ebpf_program() -> Result<Ebpf> {
        // Helpful for debugging embedded-object build path issues.
        info!("{:?}", env!("OUT_DIR"));
        let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/olopa-ebpf-bin"
        )))
        .context("failed to load embedded eBPF object")?;

        if let Err(e) = EbpfLogger::init(&mut bpf) {
            // Logging is optional; keep running if unavailable.
            warn!("eBPF logger unavailable (kernel too old?): {e}");
        }
        Ok(bpf)
    }

    // Open ring buffer map that all kernel probes write into.
    pub fn load_ring_buffer(&mut self) -> Result<RingBuf<&mut aya::maps::MapData>> {
        let ring_map = self
            .bpf
            .map_mut("EVENTS")
            .context("EVENTS ring buffer map not found")?;
        let ring = RingBuf::try_from(ring_map).context("failed to open EVENTS as RingBuf")?;
        info!("opened EVENTS ring buffer");
        Ok(ring)
    }

    // Expose mutable access for probe attachment during bootstrap.
    pub fn bpf_mut(&mut self) -> &mut Ebpf {
        &mut self.bpf
    }

    /// The orchestrator:
    /// - Task 1: hot ingest loop (no sleep)
    /// - Task 2: scheduler loop every 500ms
    /// - Task 3: housekeeping loop every 5s
    ///
    /// `OlapaAgent` is the single owner of all mutable data-plane references.
    #[allow(clippy::too_many_arguments)]
    pub async fn run<R, ES, G, MA, RE, SCH, BA, SN>(
        &mut self,
        relevance_scorer: &mut R,
        event_store: &mut ES,
        graph: &mut G,
        metric_aggregator: &mut MA,
        rule_engine: &mut RE,
        scheduler: &mut SCH,
        batcher: &mut BA,
        sender: &mut SN,
        budget_tracker: &mut BudgetTracker,
    ) -> Result<()>
    where
        R: RelevanceScorerLike,
        ES: EventStoreLike,
        G: GraphLike,
        MA: MetricAggregatorLike,
        RE: RuleEngineLike,
        SCH: SchedulerLike,
        BA: BatcherLike,
        SN: SenderLike,
    {
        // Ring buffer must live for entire runtime; borrowed from self.bpf.
        let mut ring: RingBuf<&mut aya::maps::MapData> = self.load_ring_buffer()?;

        // Scheduler window: every 500ms.
        let mut next_scheduler_tick = Instant::now() + Duration::from_millis(500);
        // Housekeeping window: every 5 seconds.
        let mut next_housekeeping_tick = Instant::now() + Duration::from_secs(5);
        // Cursor for feeding scheduler with newly persisted events.
        let mut scheduler_cursor = 0usize;
        // Debug visibility: how many kernel events were consumed in the
        // current housekeeping window.
        let mut ingested_since_housekeeping = 0u64;
        // Per-window status counters consumed by `olopa status --verbose`.
        let mut window_captured = 0u64;
        let mut window_transmitted = 0u64;
        let mut window_dropped_budget = 0u64;
        let mut window_transmitted_bytes = 0u64;
        // Lifetime firewall counters for the current agent process.
        let mut lifetime_firewall_allow = 0u64;
        let mut lifetime_firewall_deny = 0u64;
        let mut lifetime_firewall_approve = 0u64;
        let status_reporter = StatusReporter::from_env();

        // Capture ctrl-c once and poll it alongside a cooperative yield.
        // Note: `tokio::select! { ... else => ... }` does NOT behave like a
        // "default branch" when futures are pending, so we explicitly add a
        // yield branch to keep the ingest loop running while waiting for Ctrl-C.
        let shutdown = signal::ctrl_c();
        tokio::pin!(shutdown);

        // Single orchestrator loop:
        // - always drain ingest path
        // - periodically run scheduler tick
        // - periodically run housekeeping tick
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutdown signal received");
                    // Best-effort final flush.
                    if let Some(batch) = batcher.flush() {
                        let _ = sender.send_or_spool(batch);
                    }
                    let _ = sender.drain_spool(Instant::now() + Duration::from_secs(2));
                    break;
                }
                _ = tokio::task::yield_now() => {
                    // Keep ingest work on the fast path between periodic ticks.
                }
            }

            // Task 1 — Hot ingest loop body (never sleeps by design).
            let ingested = Self::ingest_once(
                &mut ring,
                relevance_scorer,
                event_store,
                graph,
                metric_aggregator,
                rule_engine,
                sender,
            )?;
            ingested_since_housekeeping =
                ingested_since_housekeeping.saturating_add(ingested.processed as u64);
            window_captured = window_captured.saturating_add(ingested.processed as u64);
            lifetime_firewall_allow =
                lifetime_firewall_allow.saturating_add(ingested.firewall_allow);
            lifetime_firewall_deny = lifetime_firewall_deny.saturating_add(ingested.firewall_deny);
            lifetime_firewall_approve =
                lifetime_firewall_approve.saturating_add(ingested.firewall_approve);

            let now = Instant::now();

            // Task 2 — Scheduler loop every 500ms.
            if now >= next_scheduler_tick {
                let sched = Self::scheduler_tick(
                    budget_tracker,
                    event_store,
                    scheduler,
                    batcher,
                    sender,
                    &mut scheduler_cursor,
                )?;
                window_transmitted = window_transmitted.saturating_add(sched.selected as u64);
                window_dropped_budget = window_dropped_budget
                    .saturating_add(sched.candidates.saturating_sub(sched.selected) as u64);
                window_transmitted_bytes =
                    window_transmitted_bytes.saturating_add(sched.selected_bytes);
                // Preserve cadence by stepping from previous target,
                // not "now", so drift does not accumulate.
                next_scheduler_tick += Duration::from_millis(500);
            }

            // Task 3 — Housekeeping loop every 5s.
            if now >= next_housekeeping_tick {
                info!(
                    "ringbuf heartbeat: ingested_events_last_5s={}",
                    ingested_since_housekeeping
                );
                ingested_since_housekeeping = 0;
                let sender_stats =
                    Self::housekeeping_tick(budget_tracker, metric_aggregator, graph, sender)?;
                let snapshot = status_reporter.build_snapshot(
                    budget_tracker,
                    &sender_stats,
                    window_captured,
                    window_transmitted,
                    window_dropped_budget,
                    window_transmitted_bytes,
                    lifetime_firewall_allow,
                    lifetime_firewall_deny,
                    lifetime_firewall_approve,
                );
                status_reporter.write(&snapshot);
                window_captured = 0;
                window_transmitted = 0;
                window_dropped_budget = 0;
                window_transmitted_bytes = 0;
                // Same cadence discipline for housekeeping.
                next_housekeeping_tick += Duration::from_secs(5);
            }

            // Avoid hot spinning when no ring-buffer events are available.
            // This keeps idle CPU utilization low while preserving sub-ms
            // reaction time for the next ingest pass.
            if ingested.processed == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_once<R, ES, G, MA, RE, SN>(
        ring: &mut RingBuf<&mut aya::maps::MapData>,
        relevance_scorer: &mut R,
        event_store: &mut ES,
        graph: &mut G,
        metric_aggregator: &mut MA,
        rule_engine: &mut RE,
        sender: &mut SN,
    ) -> Result<IngestLoopStats>
    where
        R: RelevanceScorerLike,
        ES: EventStoreLike,
        G: GraphLike,
        MA: MetricAggregatorLike,
        RE: RuleEngineLike,
        SN: SenderLike,
    {
        use core::mem::size_of;

        // Drain all currently available ring items before returning.
        let mut stats = IngestLoopStats::default();
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            // Decode based on fixed struct byte lengths.
            let event = if bytes.len() == size_of::<ExecEvent>() {
                // SAFETY: ring item length is exactly ExecEvent size and layout
                // matches the shared `olopa_common` repr(C) type.
                let raw = unsafe { &*(bytes.as_ptr() as *const ExecEvent) };
                log_exec_ingest(raw);
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 1,
                    vertex_id: raw.pid,
                    dst_vertex_id: raw.ppid,
                    net_dst_ip: 0,
                    net_dst_port: 0,
                    comm: raw.comm,
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: 0.5,
                    sql_query_hash: 0,
                    sql_query_class: 0,
                    sql_db_port: 0,
                    ssl_data_len: 0,
                    ssl_operation: 0,
                    _pad_aux: [0; 2],
                    dns_query_hash: 0,
                    dns_query: [0; 64],
                }
            } else if bytes.len() == size_of::<FileEvent>() {
                // SAFETY: ring item length is exactly FileEvent size.
                let raw = unsafe { &*(bytes.as_ptr() as *const FileEvent) };
                log_file_ingest(raw);
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 2,
                    vertex_id: raw.pid,
                    dst_vertex_id: fnv1a_32(&raw.filename),
                    net_dst_ip: 0,
                    net_dst_port: 0,
                    comm: raw.comm,
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: if raw.flags & 0x3 == 0 { 0.35 } else { 0.60 },
                    sql_query_hash: 0,
                    sql_query_class: 0,
                    sql_db_port: 0,
                    ssl_data_len: 0,
                    ssl_operation: 0,
                    _pad_aux: [0; 2],
                    dns_query_hash: 0,
                    dns_query: [0; 64],
                }
            } else if bytes.len() == size_of::<NetEvent>() {
                // SAFETY: ring item length is exactly NetEvent size.
                let raw = unsafe { &*(bytes.as_ptr() as *const NetEvent) };
                log_net_ingest(raw);
                // Compact destination vertex key for network endpoint.
                let dst = ((u16::from_be(raw.dst_port) as u32) << 16) ^ u32::from_be(raw.dst_ip);
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 3,
                    vertex_id: raw.pid,
                    dst_vertex_id: dst,
                    net_dst_ip: u32::from_be(raw.dst_ip),
                    net_dst_port: u16::from_be(raw.dst_port),
                    comm: raw.comm,
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: 0.7,
                    sql_query_hash: 0,
                    sql_query_class: 0,
                    sql_db_port: 0,
                    ssl_data_len: 0,
                    ssl_operation: 0,
                    _pad_aux: [0; 2],
                    dns_query_hash: 0,
                    dns_query: [0; 64],
                }
            } else if bytes.len() == size_of::<SqlEvent>() {
                // SAFETY: ring item length is exactly SqlEvent size.
                let raw = unsafe { &*(bytes.as_ptr() as *const SqlEvent) };
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 4,
                    vertex_id: raw.pid,
                    dst_vertex_id: raw.query_hash,
                    net_dst_ip: 0,
                    net_dst_port: 0,
                    comm: raw.comm,
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: match raw.query_class {
                        3 => 0.85, // DDL
                        4 => 0.90, // admin
                        _ => 0.40,
                    },
                    sql_query_hash: raw.query_hash,
                    sql_query_class: raw.query_class,
                    sql_db_port: raw.db_port,
                    ssl_data_len: 0,
                    ssl_operation: 0,
                    _pad_aux: [0; 2],
                    dns_query_hash: 0,
                    dns_query: [0; 64],
                }
            } else if bytes.len() == size_of::<SslEvent>() {
                // SAFETY: ring item length is exactly SslEvent size.
                let raw = unsafe { &*(bytes.as_ptr() as *const SslEvent) };
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 5,
                    vertex_id: raw.pid,
                    dst_vertex_id: raw.data_len,
                    net_dst_ip: 0,
                    net_dst_port: 0,
                    comm: raw.comm,
                    comm_id: fnv1a_32(&raw.comm),
                    // High risk when a single call encrypts > 1 MiB —
                    // consistent with ransomware bulk-encrypt patterns.
                    risk_score: if raw.data_len > 1_048_576 { 0.85 } else { 0.55 },
                    sql_query_hash: 0,
                    sql_query_class: 0,
                    sql_db_port: 0,
                    ssl_data_len: raw.data_len,
                    ssl_operation: raw.operation,
                    _pad_aux: [0; 2],
                    dns_query_hash: 0,
                    dns_query: [0; 64],
                }
            } else if bytes.len() == size_of::<DnsEvent>() {
                // SAFETY: ring item length is exactly DnsEvent size.
                let raw = unsafe { &*(bytes.as_ptr() as *const DnsEvent) };
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 6,
                    vertex_id: raw.pid,
                    // dst_vertex_id encodes the query hash for graph edge uniqueness.
                    dst_vertex_id: raw.query_hash,
                    net_dst_ip: 0,
                    net_dst_port: 0,
                    comm: raw.comm,
                    comm_id: fnv1a_32(&raw.comm),
                    // Elevated base risk: any DNS query deserves inspection.
                    // Long names (likely tunnelling/DGA) score higher.
                    risk_score: if raw.query_len > 40 { 0.70 } else { 0.45 },
                    sql_query_hash: 0,
                    sql_query_class: 0,
                    sql_db_port: 0,
                    ssl_data_len: 0,
                    ssl_operation: 0,
                    _pad_aux: [0; 2],
                    dns_query_hash: raw.query_hash,
                    dns_query: raw.query,
                }
            } else {
                // Unknown payload size: skip for hot-path resilience.
                warn!(
                    "ringbuf unknown payload size={} bytes; skipping",
                    bytes.len()
                );
                continue;
            };

            let event_stats = Self::process_event(
                event,
                relevance_scorer,
                event_store,
                graph,
                metric_aggregator,
                rule_engine,
                sender,
            )?;
            stats.processed = stats.processed.saturating_add(1);
            stats.firewall_allow = stats
                .firewall_allow
                .saturating_add(event_stats.firewall_allow);
            stats.firewall_deny = stats
                .firewall_deny
                .saturating_add(event_stats.firewall_deny);
            stats.firewall_approve = stats
                .firewall_approve
                .saturating_add(event_stats.firewall_approve);
        }

        Ok(stats)
    }

    // Process exactly one decoded event through the hot-path ingest pipeline.
    // This helper is also used by unit tests to exercise ingest behavior
    // without constructing a live kernel ring buffer.
    fn process_event<R, ES, G, MA, RE, SN>(
        mut event: IngestEvent,
        relevance_scorer: &mut R,
        event_store: &mut ES,
        graph: &mut G,
        metric_aggregator: &mut MA,
        rule_engine: &mut RE,
        sender: &mut SN,
    ) -> Result<IngestLoopStats>
    where
        R: RelevanceScorerLike,
        ES: EventStoreLike,
        G: GraphLike,
        MA: MetricAggregatorLike,
        RE: RuleEngineLike,
        SN: SenderLike,
    {
        // Required Task 1 call order (do not reorder):
        // score -> store -> graph -> metrics -> rules
        relevance_scorer.score(&mut event);
        let _ = event_store.push(event);
        graph.write_edge(&event);
        metric_aggregator.record(&event);
        let matches = rule_engine.evaluate(&event);
        let fired = !matches.is_empty();
        debug!(
            "ingest event: type={} pid={} uid={} risk={:.3} src={} dst={} fired={} matches={}",
            event.event_type,
            event.pid,
            event.uid,
            event.risk_score,
            event.vertex_id,
            event.dst_vertex_id,
            fired,
            matches.len()
        );

        // Incident path: bypass scheduler entirely, send immediately.
        let mut stats = IngestLoopStats::default();
        // Record one firewall verdict per network event.
        if event.event_type == 3 {
            if let Some(block_rule) = matches.iter().find(|m| m.enforce_block_egress) {
                enforce_block_egress_pid(&event, block_rule);
                stats.firewall_deny = stats.firewall_deny.saturating_add(1);
            } else {
                stats.firewall_allow = stats.firewall_allow.saturating_add(1);
            }
        }

        for matched_rule in &matches {
            sender.send_or_spool(encode_alert_payload(&event, matched_rule))?;
        }

        Ok(stats)
    }

    #[allow(clippy::too_many_arguments)]
    fn scheduler_tick<ES, SCH, BA, SN>(
        budget_tracker: &BudgetTracker,
        event_store: &ES,
        scheduler: &mut SCH,
        batcher: &mut BA,
        sender: &mut SN,
        scheduler_cursor: &mut usize,
    ) -> Result<SchedulerLoopStats>
    where
        ES: EventStoreLike,
        SCH: SchedulerLike,
        BA: BatcherLike,
        SN: SenderLike,
    {
        // 1) Snapshot dynamic budgets (used by scheduler + batcher level selection).
        let snapshot = budget_tracker.snapshot();

        // Feed scheduler with newly persisted event_ids since last cursor position.
        let new_candidates = event_store.unscheduled_event_ids(*scheduler_cursor);
        for event_id in &new_candidates {
            scheduler.enqueue(*event_id);
            *scheduler_cursor = (*scheduler_cursor).max(*event_id + 1);
        }

        // 2) Solve telemetry selection for this 500ms window.
        scheduler.update_budget(snapshot.clone());
        let selected_event_ids = scheduler.solve();

        // 3) Serialize selected events and batch them for transport.
        let mut selected_bytes = 0u64;
        let selected_count = selected_event_ids.len();
        for event_id in selected_event_ids {
            if let Some(bytes) = event_store.serialize_event(event_id) {
                selected_bytes = selected_bytes.saturating_add(bytes.len() as u64);
                let push = batcher.push(&bytes, &snapshot);
                if matches!(push, BatcherPush::FlushNeeded) {
                    if let Some(batch) = batcher.flush() {
                        // Telemetry send path (budget-governed).
                        sender.send_or_spool(batch)?;
                    }
                }
            }
        }

        // Time trigger is independent of push-trigger.
        if let Some(batch) = batcher.flush_if_time_triggered() {
            sender.send_or_spool(batch)?;
        }

        Ok(SchedulerLoopStats {
            candidates: new_candidates.len(),
            selected: selected_count,
            selected_bytes,
        })
    }

    fn housekeeping_tick<MA, G, SN>(
        budget_tracker: &mut BudgetTracker,
        metric_aggregator: &mut MA,
        graph: &mut G,
        sender: &mut SN,
    ) -> Result<SenderStats>
    where
        MA: MetricAggregatorLike,
        G: GraphLike,
        SN: SenderLike,
    {
        // 1) PI controller update from /proc sampling.
        let _ = budget_tracker.update()?;

        // 2) Flush metric summaries and ship them.
        for summary in metric_aggregator.flush() {
            sender.send_or_spool(summary)?;
        }

        // 3) Merge graph deltas queued by ingest writes.
        graph.merge_deltas();

        // 4) If sender is healthy and spool has pending bytes, replay backlog.
        let stats = sender.stats();
        if stats.spool_pending_bytes > 0 && !stats.spooling {
            let deadline = Instant::now() + Duration::from_secs(2);
            let _ = sender.drain_spool(deadline)?;
        }

        Ok(stats)
    }
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(_) => 0,
    }
}

fn comm_to_str(comm: &[u8; 16]) -> &str {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end]).unwrap_or("")
}

// Bootstrap enforcement path:
// if a matched rule includes `block egress`, terminate the offending process.
// This immediately stops further outbound attempts from that PID.
fn enforce_block_egress_pid(event: &IngestEvent, matched_rule: &RuleMatch) {
    // Only meaningful for network events.
    if event.event_type != 3 {
        warn!(
            "block-egress requested by rule={} on non-network event_type={}; skipping",
            matched_rule.rule_name, event.event_type
        );
        return;
    }

    let pid = event.pid as i32;
    if pid <= 1 {
        warn!(
            "block-egress requested by rule={} for protected pid={}; skipping",
            matched_rule.rule_name, pid
        );
        return;
    }

    let self_pid = std::process::id() as i32;
    if pid == self_pid {
        warn!(
            "block-egress requested by rule={} for agent pid={}; refusing self-terminate",
            matched_rule.rule_name, pid
        );
        return;
    }

    // SAFETY: libc::kill is an FFI syscall wrapper; arguments are plain ints.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 {
        warn!(
            "enforcement: rule={} terminated pid={} to block egress",
            matched_rule.rule_name, pid
        );
    } else {
        let err = std::io::Error::last_os_error();
        warn!(
            "enforcement: rule={} failed to terminate pid={} ({})",
            matched_rule.rule_name, pid, err
        );
    }
}

fn log_exec_ingest(e: &ExecEvent) {
    info!(
        "[ringbuf][exec] pid={} ppid={} uid={} gid={} comm={} file={}",
        e.pid,
        e.ppid,
        e.uid,
        e.gid,
        cstr_to_str(&e.comm),
        cstr_to_str(&e.filename)
    );
}

fn log_file_ingest(e: &FileEvent) {
    let mode = if e.flags & 0x3 == 0 { "R" } else { "W" };
    info!(
        "[ringbuf][file] pid={} uid={} comm={} flags={}({}) file={}",
        e.pid,
        e.uid,
        cstr_to_str(&e.comm),
        e.flags,
        mode,
        cstr_to_str(&e.filename)
    );
}

fn log_net_ingest(e: &NetEvent) {
    info!(
        "[ringbuf][net] pid={} uid={} comm={} dst={}:{} proto={}",
        e.pid,
        e.uid,
        cstr_to_str(&e.comm),
        core::net::Ipv4Addr::from(u32::from_be(e.dst_ip)),
        u16::from_be(e.dst_port),
        e.proto
    );
}

fn cstr_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("<invalid utf8>")
}

// Versioned binary alert payload encoding for incident fast-lane sends.
//
// Fixed header (little-endian), identical across v1 and v2:
// [magic:4][version:u16][event_type:u8][reserved:u8]
// [ts_ns:u64][pid:u32][uid:u32][vertex_id:u32][dst_vertex_id:u32][comm_id:u32][risk_score:f32]
// [rule_id_len:u16][rule_name_len:u16][rule_id:utf8 bytes][rule_name:utf8 bytes]
//
// v2 appends a per-family extension block after `rule_name`, so SQL/TLS/DNS
// probe detail survives the hop into the ingest sender instead of being
// collapsed into `dst_vertex_id`:
// [comm_len:u8][comm:utf8 bytes]
// [sql_query_hash:u32][sql_query_class:u8][sql_db_port:u16]
// [ssl_data_len:u32][ssl_operation:u8]
// [dns_query_hash:u32][dns_query_len:u8][dns_query:utf8 bytes]
//
// The extension is strictly additive: a v1 decoder reads the same header
// offsets and stops at `rule_name`.
fn encode_alert_payload(event: &IngestEvent, matched_rule: &RuleMatch) -> Vec<u8> {
    const ALERT_MAGIC: [u8; 4] = *b"OLRT";
    const ALERT_WIRE_VERSION: u16 = 2;

    let rule_id = matched_rule.rule_id.as_bytes();
    let rule_name = matched_rule.rule_name.as_bytes();
    let rule_id_len = rule_id.len().min(u16::MAX as usize);
    let rule_name_len = rule_name.len().min(u16::MAX as usize);

    let comm = cstr_to_str(&event.comm).as_bytes();
    let comm_len = comm.len().min(u8::MAX as usize);
    let dns_query = cstr_to_str(&event.dns_query).as_bytes();
    let dns_query_len = dns_query.len().min(u8::MAX as usize);

    let mut out = Vec::with_capacity(64 + rule_id_len + rule_name_len + comm_len + dns_query_len);
    out.extend_from_slice(&ALERT_MAGIC);
    out.extend_from_slice(&ALERT_WIRE_VERSION.to_le_bytes());
    out.push(event.event_type);
    out.push(0); // reserved for alignment/future flags
    out.extend_from_slice(&event.ts_ns.to_le_bytes());
    out.extend_from_slice(&event.pid.to_le_bytes());
    out.extend_from_slice(&event.uid.to_le_bytes());
    out.extend_from_slice(&event.vertex_id.to_le_bytes());
    out.extend_from_slice(&event.dst_vertex_id.to_le_bytes());
    out.extend_from_slice(&event.comm_id.to_le_bytes());
    out.extend_from_slice(&event.risk_score.to_le_bytes());
    out.extend_from_slice(&(rule_id_len as u16).to_le_bytes());
    out.extend_from_slice(&(rule_name_len as u16).to_le_bytes());
    out.extend_from_slice(&rule_id[..rule_id_len]);
    out.extend_from_slice(&rule_name[..rule_name_len]);

    // v2 extension block.
    out.push(comm_len as u8);
    out.extend_from_slice(&comm[..comm_len]);
    out.extend_from_slice(&event.sql_query_hash.to_le_bytes());
    out.push(event.sql_query_class);
    out.extend_from_slice(&event.sql_db_port.to_le_bytes());
    out.extend_from_slice(&event.ssl_data_len.to_le_bytes());
    out.push(event.ssl_operation);
    out.extend_from_slice(&event.dns_query_hash.to_le_bytes());
    out.push(dns_query_len as u8);
    out.extend_from_slice(&dns_query[..dns_query_len]);
    out
}

// FNV-1a 32-bit hash used for compact deterministic IDs from byte arrays.
fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for b in bytes {
        if *b == 0 {
            break;
        }
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_ir::RuntimeIrRuleEngine;
    use crate::transport::http_sender::payload_to_batches_for_tests;
    use serde::Deserialize;
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_runtime_ir_path() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("olopa_agent_rule_payload_test_{ts}.json"))
    }

    fn temp_runtime_ir_dir() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("olopa_agent_e2e_rule_flow_{ts}"))
    }

    #[derive(Debug)]
    struct DecodedAlertPayload {
        ts_ns: u64,
        pid: u32,
        uid: u32,
        event_type: u8,
        vertex_id: u32,
        dst_vertex_id: u32,
        comm_id: u32,
        risk_score: f32,
        rule_id: String,
        rule_name: String,
        comm: String,
        sql_query_hash: u32,
        sql_query_class: u8,
        sql_db_port: u16,
        dns_query: String,
    }

    fn decode_alert_payload(payload: &[u8]) -> DecodedAlertPayload {
        const MAGIC: &[u8; 4] = b"OLRT";
        assert!(payload.len() >= 40, "payload too short");
        assert_eq!(&payload[0..4], MAGIC, "invalid alert magic");
        let version = u16::from_le_bytes([payload[4], payload[5]]);
        assert_eq!(version, 2, "unsupported alert version");

        let event_type = payload[6];
        let ts_ns = u64::from_le_bytes(payload[8..16].try_into().expect("ts"));
        let pid = u32::from_le_bytes(payload[16..20].try_into().expect("pid"));
        let uid = u32::from_le_bytes(payload[20..24].try_into().expect("uid"));
        let vertex_id = u32::from_le_bytes(payload[24..28].try_into().expect("vertex"));
        let dst_vertex_id = u32::from_le_bytes(payload[28..32].try_into().expect("dst"));
        let comm_id = u32::from_le_bytes(payload[32..36].try_into().expect("comm"));
        let risk_score = f32::from_le_bytes(payload[36..40].try_into().expect("risk"));
        let rule_id_len =
            u16::from_le_bytes(payload[40..42].try_into().expect("rule_id_len")) as usize;
        let rule_name_len =
            u16::from_le_bytes(payload[42..44].try_into().expect("rule_name_len")) as usize;
        let mut cursor = 44usize;
        let end_rule_id = cursor + rule_id_len;
        assert!(end_rule_id <= payload.len(), "invalid rule_id_len");
        let rule_id =
            String::from_utf8(payload[cursor..end_rule_id].to_vec()).expect("rule_id utf8");
        cursor = end_rule_id;
        let end_rule_name = cursor + rule_name_len;
        assert!(end_rule_name <= payload.len(), "invalid rule_name_len");
        let rule_name =
            String::from_utf8(payload[cursor..end_rule_name].to_vec()).expect("rule_name utf8");
        cursor = end_rule_name;

        // v2 extension block.
        let comm_len = payload[cursor] as usize;
        cursor += 1;
        let comm = String::from_utf8(payload[cursor..cursor + comm_len].to_vec()).expect("comm");
        cursor += comm_len;
        let sql_query_hash =
            u32::from_le_bytes(payload[cursor..cursor + 4].try_into().expect("sql hash"));
        cursor += 4;
        let sql_query_class = payload[cursor];
        cursor += 1;
        let sql_db_port =
            u16::from_le_bytes(payload[cursor..cursor + 2].try_into().expect("db port"));
        cursor += 2;
        // ssl_data_len(4) + ssl_operation(1) + dns_query_hash(4)
        cursor += 9;
        let dns_query_len = payload[cursor] as usize;
        cursor += 1;
        let dns_query =
            String::from_utf8(payload[cursor..cursor + dns_query_len].to_vec()).expect("dns query");

        DecodedAlertPayload {
            ts_ns,
            pid,
            uid,
            event_type,
            vertex_id,
            dst_vertex_id,
            comm_id,
            risk_score,
            rule_id,
            rule_name,
            comm,
            sql_query_hash,
            sql_query_class,
            sql_db_port,
            dns_query,
        }
    }

    #[test]
    fn alert_payload_uses_rule_identity_from_runtime_ir_match() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:pid_42",
      "name": "pid_42",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "pid" },
          "rhs": { "op": "int", "value": 42 }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 100,
            pid: 42,
            uid: 7,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 1,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 123,
            risk_score: 0.9,
            sql_query_hash: 0,
            sql_query_class: 0,
            sql_db_port: 0,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 0,
            dns_query: [0; 64],
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        let payload = encode_alert_payload(&event, &matches[0]);
        let decoded = decode_alert_payload(&payload);
        assert_eq!(decoded.rule_id, "rule:0:pid_42");
        assert_eq!(decoded.rule_name, "pid_42");
        assert_eq!(decoded.pid, 42);
        assert_eq!(decoded.uid, 7);
        assert_eq!(decoded.event_type, 1);
        assert_eq!(decoded.ts_ns, 100);
        assert_eq!(decoded.vertex_id, 42);
        assert_eq!(decoded.dst_vertex_id, 1);
        assert_eq!(decoded.comm_id, 123);
        assert!((decoded.risk_score - 0.9).abs() < 0.0001);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sql_alert_payload_carries_query_detail_through_wire() {
        let path = temp_runtime_ir_path();
        // Rule addresses the SQL field family directly, proving uprobe-derived
        // DDL is both matchable and preserved across the alert encoding.
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:sql_ddl",
      "name": "sql_ddl",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "sql.query_class" },
          "rhs": { "op": "int", "value": 3 }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"psql");

        let event = IngestEvent {
            ts_ns: 500,
            pid: 900,
            uid: 1000,
            event_type: 4,
            vertex_id: 900,
            dst_vertex_id: 0xdead_beef,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 55,
            risk_score: 0.85,
            sql_query_hash: 0xdead_beef,
            sql_query_class: 3,
            sql_db_port: 5432,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 0,
            dns_query: [0; 64],
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1, "sql.query_class rule should match");

        let payload = encode_alert_payload(&event, &matches[0]);
        let decoded = decode_alert_payload(&payload);
        assert_eq!(decoded.event_type, 4);
        assert_eq!(decoded.comm, "psql");
        assert_eq!(decoded.sql_query_hash, 0xdead_beef);
        assert_eq!(decoded.sql_query_class, 3);
        assert_eq!(decoded.sql_db_port, 5432);

        // The same payload must land in the db_query family on the wire.
        let batches = payload_to_batches_for_tests(&payload, "acme", "host-01");
        assert_eq!(batches.len(), 1);
        let db_events = batches[0]["db_query_events"]
            .as_array()
            .expect("db_query_events array");
        assert_eq!(db_events.len(), 1);
        assert_eq!(db_events[0]["db_engine"], "postgresql");
        assert_eq!(db_events[0]["operation"], "ddl");
        assert_eq!(db_events[0]["statement_fingerprint"], "deadbeef");
        assert_eq!(db_events[0]["comm"], "psql");
        assert_eq!(db_events[0]["pid"], 900);
        assert!(batches[0]["process_exec_events"]
            .as_array()
            .expect("process array")
            .is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn dns_alert_payload_maps_to_net_family_with_query_name() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:any_dns",
      "name": "any_dns",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "event.event_type" },
          "rhs": { "op": "int", "value": 6 }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut dns_query = [0u8; 64];
        dns_query[..11].copy_from_slice(b"evil.c2.net");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"curl");

        let event = IngestEvent {
            ts_ns: 700,
            pid: 1200,
            uid: 0,
            event_type: 6,
            vertex_id: 1200,
            dst_vertex_id: 7,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 12,
            risk_score: 0.7,
            sql_query_hash: 0,
            sql_query_class: 0,
            sql_db_port: 0,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 7,
            dns_query,
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);

        let payload = encode_alert_payload(&event, &matches[0]);
        assert_eq!(decode_alert_payload(&payload).dns_query, "evil.c2.net");

        let batches = payload_to_batches_for_tests(&payload, "acme", "host-01");
        let net_events = batches[0]["net_events"].as_array().expect("net array");
        assert_eq!(net_events.len(), 1);
        assert_eq!(net_events[0]["protocol"], "dns");
        assert_eq!(net_events[0]["dst_port"], 53);
        assert_eq!(net_events[0]["attrs"]["dns_query"], "evil.c2.net");
        assert_eq!(net_events[0]["comm"], "curl");

        let _ = fs::remove_file(path);
    }

    struct NoopScorer;
    impl RelevanceScorerLike for NoopScorer {
        fn score(&mut self, _event: &mut IngestEvent) {}
    }

    struct NoopStore;
    impl EventStoreLike for NoopStore {
        fn push(&mut self, _event: IngestEvent) -> Option<usize> {
            Some(0)
        }

        fn serialize_event(&self, _event_id: usize) -> Option<Vec<u8>> {
            None
        }

        fn unscheduled_event_ids(&self, _from: usize) -> Vec<usize> {
            Vec::new()
        }

        fn last_event_id(&self) -> usize {
            0
        }
    }

    struct NoopGraph;
    impl GraphLike for NoopGraph {
        fn write_edge(&mut self, _event: &IngestEvent) {}
        fn merge_deltas(&mut self) {}
    }

    struct NoopMetrics;
    impl MetricAggregatorLike for NoopMetrics {
        fn record(&mut self, _event: &IngestEvent) {}
        fn flush(&mut self) -> Vec<Vec<u8>> {
            Vec::new()
        }
    }

    struct TwoMatchRuleEngine;
    impl RuleEngineLike for TwoMatchRuleEngine {
        fn evaluate(&mut self, _event: &IngestEvent) -> Vec<RuleMatch> {
            vec![
                RuleMatch {
                    rule_id: "rule:one".to_string(),
                    rule_name: "rule_one".to_string(),
                    enforce_block_egress: false,
                },
                RuleMatch {
                    rule_id: "rule:two".to_string(),
                    rule_name: "rule_two".to_string(),
                    enforce_block_egress: false,
                },
            ]
        }
    }

    struct RuntimeRuleEngineAdapter {
        inner: RuntimeIrRuleEngine,
    }
    impl RuleEngineLike for RuntimeRuleEngineAdapter {
        fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch> {
            self.inner.evaluate_matches(event)
        }
    }

    #[derive(Default)]
    struct CaptureSender {
        payloads: Vec<Vec<u8>>,
    }
    impl SenderLike for CaptureSender {
        fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()> {
            self.payloads.push(payload);
            Ok(())
        }

        fn stats(&self) -> SenderStats {
            SenderStats::default()
        }

        fn drain_spool(&mut self, _deadline: Instant) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn ingest_path_sends_one_alert_per_rule_match() {
        let event = IngestEvent {
            ts_ns: 1,
            pid: 123,
            uid: 42,
            event_type: 1,
            vertex_id: 123,
            dst_vertex_id: 7,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 9,
            risk_score: 0.8,
            sql_query_hash: 0,
            sql_query_class: 0,
            sql_db_port: 0,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 0,
            dns_query: [0; 64],
        };

        let mut scorer = NoopScorer;
        let mut store = NoopStore;
        let mut graph = NoopGraph;
        let mut metrics = NoopMetrics;
        let mut rules = TwoMatchRuleEngine;
        let mut sender = CaptureSender::default();

        OlopaAgent::process_event(
            event,
            &mut scorer,
            &mut store,
            &mut graph,
            &mut metrics,
            &mut rules,
            &mut sender,
        )
        .expect("process event");

        assert_eq!(sender.payloads.len(), 2);
        let payload0 = decode_alert_payload(&sender.payloads[0]);
        let payload1 = decode_alert_payload(&sender.payloads[1]);
        assert_eq!(payload0.rule_id, "rule:one");
        assert_eq!(payload0.rule_name, "rule_one");
        assert_eq!(payload1.rule_id, "rule:two");
        assert_eq!(payload1.rule_name, "rule_two");
    }

    #[test]
    fn e2e_rule_to_ir_to_agent_executes_on_event() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let source = dir.join("rule.oil");
        let runtime_ir = dir.join("runtime-ir.json");
        let src: &str = r#"
rule "critical_pid_4242" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid == 4242
  respond alert high
}
"#;
        fs::write(&source, src).expect("write oil source");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root");
        let oilc_manifest = repo_root.join("oilc").join("Cargo.toml");

        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(&oilc_manifest)
            .arg("--")
            .arg("--source")
            .arg(&source)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let mut rules = RuntimeRuleEngineAdapter {
            inner: RuntimeIrRuleEngine::from_file(&runtime_ir).expect("load runtime ir"),
        };
        let mut scorer = NoopScorer;
        let mut store = NoopStore;
        let mut graph = NoopGraph;
        let mut metrics = NoopMetrics;
        let mut sender = CaptureSender::default();

        let event = IngestEvent {
            ts_ns: 999,
            pid: 4242,
            uid: 1000,
            event_type: 1,
            vertex_id: 4242,
            dst_vertex_id: 1,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 7,
            risk_score: 0.85,
            sql_query_hash: 0,
            sql_query_class: 0,
            sql_db_port: 0,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 0,
            dns_query: [0; 64],
        };
        OlopaAgent::process_event(
            event,
            &mut scorer,
            &mut store,
            &mut graph,
            &mut metrics,
            &mut rules,
            &mut sender,
        )
        .expect("process event");

        assert_eq!(sender.payloads.len(), 1);
        let payload = decode_alert_payload(&sender.payloads[0]);
        assert_eq!(payload.rule_name, "critical_pid_4242");
        assert_eq!(payload.pid, 4242);
        assert_eq!(payload.event_type, 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[derive(Debug, Deserialize)]
    struct RecentIngestRowView {
        event_kind: String,
        event: serde_json::Value,
        tenant_id: String,
        host_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct RecentIngestResponseView {
        returned: usize,
        rows: Vec<RecentIngestRowView>,
    }

    #[derive(Debug, Deserialize)]
    struct AckResponseView {
        accepted: bool,
    }

    struct ChildGuard {
        child: Child,
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // Best-effort cleanup to avoid leaked background server processes
            // when assertions fail mid-test.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn acquire_local_port() -> u16 {
        // Ask the OS for an ephemeral port, then hand that exact port to the
        // spawned ingest server process.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test port");
        let port = listener.local_addr().expect("read local addr").port();
        drop(listener);
        port
    }

    async fn wait_for_ingest_health(client: &reqwest::Client, base_url: &str, child: &mut Child) {
        // Poll health until server boot completes, while also failing fast if
        // the child process exits early.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
        loop {
            if let Some(status) = child.try_wait().expect("check ingest process status") {
                panic!("ingest server exited before becoming healthy: {status}");
            }
            if let Ok(resp) = client.get(format!("{base_url}/health")).send().await {
                if resp.status().is_success() {
                    return;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out waiting for ingest server health endpoint");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires local TCP bind + external ingest server process"]
    async fn e2e_rule_to_runtime_to_sender_to_ingest_runtime() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let source = dir.join("rule.oil");
        let runtime_ir = dir.join("runtime-ir.json");
        let src: &str = r#"
rule "critical_pid_4242" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid == 4242
  respond alert high
}
"#;
        fs::write(&source, src).expect("write oil source");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root");
        let oilc_manifest = repo_root.join("oilc").join("Cargo.toml");

        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(&oilc_manifest)
            .arg("--")
            .arg("--source")
            .arg(&source)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let mut rules = RuntimeRuleEngineAdapter {
            inner: RuntimeIrRuleEngine::from_file(&runtime_ir).expect("load runtime ir"),
        };
        let mut scorer = NoopScorer;
        let mut store = NoopStore;
        let mut graph = NoopGraph;
        let mut metrics = NoopMetrics;
        let mut sender = CaptureSender::default();

        let event = IngestEvent {
            ts_ns: 1_000,
            pid: 4242,
            uid: 1000,
            event_type: 1,
            vertex_id: 4242,
            dst_vertex_id: 1,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 7,
            risk_score: 0.85,
            sql_query_hash: 0,
            sql_query_class: 0,
            sql_db_port: 0,
            ssl_data_len: 0,
            ssl_operation: 0,
            _pad_aux: [0; 2],
            dns_query_hash: 0,
            dns_query: [0; 64],
        };
        OlopaAgent::process_event(
            event,
            &mut scorer,
            &mut store,
            &mut graph,
            &mut metrics,
            &mut rules,
            &mut sender,
        )
        .expect("process event");
        assert_eq!(sender.payloads.len(), 1);

        // Convert the captured alert payload using the same sender transform
        // that production uses before posting to ingest.
        let batches_json =
            payload_to_batches_for_tests(&sender.payloads[0], "tenant-e2e", "host-e2e");
        assert_eq!(batches_json.len(), 1);

        let ingest_manifest = repo_root
            .join("app")
            .join("ingest_server")
            .join("Cargo.toml");
        let ingest_port = acquire_local_port();
        let ingest_base_url = format!("http://127.0.0.1:{ingest_port}");
        let persist_path = dir.join("ingest-e2e.jsonl");

        let ingest_child = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(&ingest_manifest)
            .current_dir(&repo_root)
            .env("SERVER_HOST", "127.0.0.1")
            .env("SERVER_PORT", ingest_port.to_string())
            .env("INGEST_QUEUE_MAXSIZE", "16")
            .env("INGEST_FLUSH_INTERVAL_MS", "25")
            .env("INGEST_FLUSH_MAX_ROWS", "1")
            .env("INGEST_RECENT_EVENTS_MAX", "16")
            .env("INGEST_PERSIST_JSONL_PATH", &persist_path)
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start ingest server");
        let mut ingest_guard = ChildGuard {
            child: ingest_child,
        };

        let client = reqwest::Client::new();
        wait_for_ingest_health(&client, &ingest_base_url, &mut ingest_guard.child).await;

        let ack = client
            .post(format!("{ingest_base_url}/api/v1/ingest/batches"))
            .json(&batches_json[0])
            .send()
            .await
            .expect("post converted sender batch")
            .error_for_status()
            .expect("ingest endpoint should accept request")
            .json::<AckResponseView>()
            .await
            .expect("parse ingest ack response");
        assert!(
            ack.accepted,
            "ingest endpoint rejected converted sender batch"
        );

        // Ingest is async; poll recent rows until the flush worker indexes the
        // posted event row.
        let recent_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let recent_view = loop {
            let recent_resp = client
                .get(format!("{ingest_base_url}/api/v1/ingest/recent?limit=10"))
                .send()
                .await
                .expect("request recent ingest rows")
                .error_for_status()
                .expect("recent endpoint should return success")
                .json::<RecentIngestResponseView>()
                .await
                .expect("parse recent ingest response");
            if recent_resp.returned >= 1 {
                break recent_resp;
            }
            if tokio::time::Instant::now() >= recent_deadline {
                panic!("timed out waiting for ingested rows");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };

        let matched_rule_row = recent_view.rows.iter().find(|row| {
            row.event_kind == "process_exec"
                && row.tenant_id == "tenant-e2e"
                && row.host_id == "host-e2e"
                && row
                    .event
                    .get("attrs")
                    .and_then(|attrs| attrs.get("rule_name"))
                    == Some(&serde_json::Value::String("critical_pid_4242".to_string()))
        });
        assert!(
            matched_rule_row.is_some(),
            "recent ingest rows did not include the expected rule-marked process event"
        );

        drop(ingest_guard);
        let _ = fs::remove_dir_all(dir);
    }
}
