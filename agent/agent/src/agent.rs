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

// Scorer contract used by ingest loop.
pub trait RelevanceScorerLike {
    fn score(&mut self, event: &mut IngestEvent);
}

// Event store contract used by ingest/scheduler loops.
pub trait EventStoreLike {
    fn push(&mut self, event: IngestEvent) -> Option<usize>;
    fn serialize_event(&self, event_id: usize) -> Option<Vec<u8>>;
    fn unscheduled_event_ids(&self, from: usize) -> Vec<usize>;
    fn last_event_id(&self) -> usize;
}

// Graph contract used by ingest (write) and housekeeping (merge).
pub trait GraphLike {
    fn write_edge(&mut self, event: &IngestEvent);
    fn merge_deltas(&mut self);
}

// Metrics contract used by ingest and housekeeping flush.
pub trait MetricAggregatorLike {
    fn record(&mut self, event: &IngestEvent);
    fn flush(&mut self) -> Vec<Vec<u8>>;
}

// Rule evaluation contract; true means incident/alert.
pub trait RuleEngineLike {
    fn evaluate(&mut self, event: &IngestEvent) -> bool;
}

// Scheduler contract for telemetry selection (not alert path).
pub trait SchedulerLike {
    fn update_budget(&mut self, snapshot: crate::budget_tracker::BudgetSnapshot);
    fn enqueue(&mut self, event_id: usize);
    fn solve(&mut self) -> Vec<usize>;
}

// Batcher contract for scheduler-selected telemetry payloads.
pub trait BatcherLike {
    fn push(
        &mut self,
        serialized_event: &[u8],
        budget: &crate::budget_tracker::BudgetSnapshot,
    ) -> BatcherPush;
    fn flush(&mut self) -> Option<Vec<u8>>;
    fn flush_if_time_triggered(&mut self) -> Option<Vec<u8>>;
}

// Sender contract for alert fast-lane + telemetry batches + spool recovery.
pub trait SenderLike {
    fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()>;
    fn stats(&self) -> SenderStats;
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
        RingBuf::try_from(ring_map).context("failed to open EVENTS as RingBuf")
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

        // Capture ctrl-c once and poll it without sleeping the hot path.
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
                else => {
                    // Task 1 — Hot ingest loop body (never sleeps).
                    Self::ingest_once(
                        &mut ring,
                        relevance_scorer,
                        event_store,
                        graph,
                        metric_aggregator,
                        rule_engine,
                        sender,
                    )?;

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
                        Self::housekeeping_tick(
                            budget_tracker,
                            metric_aggregator,
                            graph,
                            sender,
                        )?;
                        // Same cadence discipline for housekeeping.
                        next_housekeeping_tick += Duration::from_secs(5);
                    }
                }
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
    ) -> Result<()>
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
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            // Decode based on fixed struct byte lengths.
            let mut event = if bytes.len() == size_of::<ExecEvent>() {
                let raw = unsafe { &*(bytes.as_ptr() as *const ExecEvent) };
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 1,
                    vertex_id: raw.pid,
                    dst_vertex_id: raw.ppid,
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: 0.5,
                }
            } else if bytes.len() == size_of::<FileEvent>() {
                let raw = unsafe { &*(bytes.as_ptr() as *const FileEvent) };
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 2,
                    vertex_id: raw.pid,
                    dst_vertex_id: fnv1a_32(&raw.filename),
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: if raw.flags & 0x3 == 0 { 0.35 } else { 0.60 },
                }
            } else if bytes.len() == size_of::<NetEvent>() {
                let raw = unsafe { &*(bytes.as_ptr() as *const NetEvent) };
                // Compact destination vertex key for network endpoint.
                let dst = ((u16::from_be(raw.dst_port) as u32) << 16) ^ u32::from_be(raw.dst_ip);
                IngestEvent {
                    ts_ns: raw.ts_ns,
                    pid: raw.pid,
                    uid: raw.uid,
                    event_type: 3,
                    vertex_id: raw.pid,
                    dst_vertex_id: dst,
                    comm_id: fnv1a_32(&raw.comm),
                    risk_score: 0.7,
                }
            } else {
                // Unknown payload size: skip for hot-path resilience.
                continue;
            };

            // Required Task 1 call order (do not reorder):
            // score -> store -> graph -> metrics -> rules
            relevance_scorer.score(&mut event);
            let _ = event_store.push(event);
            graph.write_edge(&event);
            metric_aggregator.record(&event);
            let fired = rule_engine.evaluate(&event);

            debug!(
                "ingest event: type={} pid={} uid={} risk={:.3} src={} dst={} fired={}",
                event.event_type,
                event.pid,
                event.uid,
                event.risk_score,
                event.vertex_id,
                event.dst_vertex_id,
                fired
            );

            // Incident path: bypass scheduler entirely, send immediately.
            if fired {
                sender.send_or_spool(encode_alert_payload(&event))?;
            }
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

// Minimal plain-text alert encoding for fast-lane incident sends.
fn encode_alert_payload(event: &IngestEvent) -> Vec<u8> {
    format!(
        "ALERT ts_ns={} pid={} uid={} type={} risk={:.3} src={} dst={} comm_id={}",
        event.ts_ns,
        event.pid,
        event.uid,
        event.event_type,
        event.risk_score,
        event.vertex_id,
        event.dst_vertex_id,
        event.comm_id
    )
    .into_bytes()
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
