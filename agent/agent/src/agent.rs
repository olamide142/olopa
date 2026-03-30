//! Core userspace orchestrator.
//!
//! This module owns the hot ingest loop and periodic maintenance loops:
//! - ingest: decode ring-buffer events, score/store/graph/metrics/rules.
//! - scheduler tick: select and send budgeted telemetry.
//! - housekeeping tick: update budgets, flush metrics, merge graph, drain spool.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::RingBuf, Ebpf};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use olopa_common::{ExecEvent, FileEvent, NetEvent};
use tokio::signal;

use crate::budget_tracker::BudgetTracker;

// Canonical in-memory event representation used by the orchestrator.
// This struct is what flows through the hot ingest pipeline.
#[derive(Clone, Copy, Debug)]
pub struct IngestEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u8, // 1=exec, 2=file, 3=net
    pub vertex_id: u32,
    pub dst_vertex_id: u32,
    // Host-endian IPv4 destination and destination port for net events.
    pub net_dst_ip: u32,
    pub net_dst_port: u16,
    pub comm: [u8; 16],
    pub comm_id: u32,
    pub risk_score: f32,
}

// Minimal sender state queried by housekeeping to decide spool replay behavior.
#[derive(Clone, Debug, Default)]
pub struct SenderStats {
    pub spool_pending_bytes: u64,
    pub spooling: bool,
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
                ingested_since_housekeeping.saturating_add(ingested as u64);

            let now = Instant::now();

            // Task 2 — Scheduler loop every 500ms.
            if now >= next_scheduler_tick {
                Self::scheduler_tick(
                    budget_tracker,
                    event_store,
                    scheduler,
                    batcher,
                    sender,
                    &mut scheduler_cursor,
                )?;
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
                Self::housekeeping_tick(budget_tracker, metric_aggregator, graph, sender)?;
                // Same cadence discipline for housekeeping.
                next_housekeeping_tick += Duration::from_secs(5);
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
    ) -> Result<usize>
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
        let mut processed = 0usize;
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
                }
            } else {
                // Unknown payload size: skip for hot-path resilience.
                warn!(
                    "ringbuf unknown payload size={} bytes; skipping",
                    bytes.len()
                );
                continue;
            };

            Self::process_event(
                event,
                relevance_scorer,
                event_store,
                graph,
                metric_aggregator,
                rule_engine,
                sender,
            )?;
            processed = processed.saturating_add(1);
        }

        Ok(processed)
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
    ) -> Result<()>
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
        for matched_rule in &matches {
            if matched_rule.enforce_block_egress {
                enforce_block_egress_pid(&event, matched_rule);
            }
            sender.send_or_spool(encode_alert_payload(&event, matched_rule))?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn scheduler_tick<ES, SCH, BA, SN>(
        budget_tracker: &BudgetTracker,
        event_store: &ES,
        scheduler: &mut SCH,
        batcher: &mut BA,
        sender: &mut SN,
        scheduler_cursor: &mut usize,
    ) -> Result<()>
    where
        ES: EventStoreLike,
        SCH: SchedulerLike,
        BA: BatcherLike,
        SN: SenderLike,
    {
        // 1) Snapshot dynamic budgets (used by scheduler + batcher level selection).
        let snapshot = budget_tracker.snapshot();

        // Feed scheduler with newly persisted event_ids since last cursor position.
        for event_id in event_store.unscheduled_event_ids(*scheduler_cursor) {
            scheduler.enqueue(event_id);
            *scheduler_cursor = (*scheduler_cursor).max(event_id + 1);
        }

        // 2) Solve telemetry selection for this 500ms window.
        scheduler.update_budget(snapshot.clone());
        let selected_event_ids = scheduler.solve();

        // 3) Serialize selected events and batch them for transport.
        for event_id in selected_event_ids {
            if let Some(bytes) = event_store.serialize_event(event_id) {
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

        Ok(())
    }

    fn housekeeping_tick<MA, G, SN>(
        budget_tracker: &mut BudgetTracker,
        metric_aggregator: &mut MA,
        graph: &mut G,
        sender: &mut SN,
    ) -> Result<()>
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

        Ok(())
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
// Layout (little-endian):
// [magic:4][version:u16][event_type:u8][reserved:u8]
// [ts_ns:u64][pid:u32][uid:u32][vertex_id:u32][dst_vertex_id:u32][comm_id:u32][risk_score:f32]
// [rule_id_len:u16][rule_name_len:u16][rule_id:utf8 bytes][rule_name:utf8 bytes]
fn encode_alert_payload(event: &IngestEvent, matched_rule: &RuleMatch) -> Vec<u8> {
    const ALERT_MAGIC: [u8; 4] = *b"OLRT";
    const ALERT_WIRE_VERSION: u16 = 1;

    let rule_id = matched_rule.rule_id.as_bytes();
    let rule_name = matched_rule.rule_name.as_bytes();
    let rule_id_len = rule_id.len().min(u16::MAX as usize);
    let rule_name_len = rule_name.len().min(u16::MAX as usize);

    let mut out = Vec::with_capacity(40 + rule_id_len + rule_name_len);
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
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
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
    }

    fn decode_alert_payload(payload: &[u8]) -> DecodedAlertPayload {
        const MAGIC: &[u8; 4] = b"OLRT";
        assert!(payload.len() >= 40, "payload too short");
        assert_eq!(&payload[0..4], MAGIC, "invalid alert magic");
        let version = u16::from_le_bytes([payload[4], payload[5]]);
        assert_eq!(version, 1, "unsupported alert version");

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
}
