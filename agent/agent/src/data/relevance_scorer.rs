// ============================================================
// OLOPA — RelevanceScorer
// ============================================================
// Sits between the eBPF ring buffer consumer and the MDKP
// scheduler. Every event that comes off the ring buffer passes
// through here before it is enqueued for scheduling.
//
// Two jobs:
//   1. Dead-band filter  — suppress events where nothing changed.
//      If risk_delta < epsilon for this process, return None.
//      This eliminates the majority of low-value telemetry before
//      it ever reaches the scheduler.
//
//   2. Relevance score   — assign a 0.0–1.0 score to each event
//      that survives the filter. The score is the MDKP objective
//      value for that item. Higher score = higher priority to
//      transmit under budget pressure.
//
// Score formula (four weighted components):
//   severity  (30%) — raw risk_score from EPL / node baseline
//   delta     (40%) — normalised change from last seen value
//   recency   (20%) — exponential decay by event age
//   context   (10%) — chain depth bonus
//
// Per-process state:
//   The scorer maintains a HashMap<vertex_id, ProcessState>
//   that tracks the last seen risk score and timestamp per
//   process. This is how delta is computed.
//   State entries expire after STALE_THRESHOLD to prevent
//   unbounded growth from short-lived processes.
// ============================================================

use crossbeam_utils::CachePadded;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ── Constants ────────────────────────────────────────────────
// Default dead-band: suppress events where risk changed < 5%
const DEFAULT_DEAD_BAND: f32 = 0.05;

// State entries older than this are evicted on the next housekeeping pass
const STALE_THRESHOLD: Duration = Duration::from_secs(300); // 5 minutes

// Recency half-life: score halves every 5,000ms of age
const RECENCY_HALF_LIFE_MS: f32 = 5_000.0;

// Component weights — must sum to 1.0
const W_SEVERITY: f32 = 0.30;
const W_DELTA: f32 = 0.40;
const W_RECENCY: f32 = 0.20;
const W_CONTEXT: f32 = 0.10;

const _: () = assert!(((W_SEVERITY + W_DELTA + W_RECENCY + W_CONTEXT) - 1.0).abs() < 1e-6);

// ── Per-process state ────────────────────────────────────────
// One entry per vertex_id seen since last eviction pass.
// Kept in a plain HashMap — no locking because the scorer is
// owned by a single ingest worker thread.
#[derive(Debug, Clone)]
struct ProcessState {
    last_risk: f32,     // risk_score at last observed event
    last_seen: Instant, // wall time of last event for this process
    event_count: u32,   // total events seen (used for novelty scoring)
}

// ── ScoredEvent — output of the scorer ───────────────────────
// Carries the relevance score and the estimated resource cost
// so the caller can construct a TelemetryItem directly.
#[derive(Debug, Clone)]
pub struct ScoredEvent {
    pub event_id: usize,             // index into EventStore
    pub vertex_id: u32,              // graph node ID
    pub relevance: f32,              // 0.0–1.0 — MDKP objective value
    pub risk_delta: f32,             // signed change from last observation
    pub components: ScoreComponents, // breakdown for observability
}

// ── Score breakdown — for Prometheus metrics and debugging ───
#[derive(Debug, Clone, Copy)]
pub struct ScoreComponents {
    pub severity: f32,
    pub delta: f32,
    pub recency: f32,
    pub context: f32,
}

impl ScoreComponents {
    pub fn total(&self) -> f32 {
        self.severity * W_SEVERITY
            + self.delta * W_DELTA
            + self.recency * W_RECENCY
            + self.context * W_CONTEXT
    }
}

// ── RelevanceScorer ───────────────────────────────────────────
pub struct RelevanceScorer {
    // Per-process state: vertex_id → ProcessState
    state: HashMap<u32, ProcessState>,

    // Dead-band threshold — configurable per deployment
    // Lower epsilon = more sensitive, more events pass through
    // Higher epsilon = more aggressive suppression
    dead_band_epsilon: f32,

    // Metrics
    pub events_in: CachePadded<AtomicU64>,
    pub events_passed: CachePadded<AtomicU64>,
    pub events_filtered: CachePadded<AtomicU64>,
    pub state_evictions: CachePadded<AtomicU64>,
}

impl RelevanceScorer {
    pub fn new(dead_band_epsilon: f32) -> Self {
        Self {
            state: HashMap::with_capacity(4096),
            dead_band_epsilon,
            events_in: CachePadded::new(AtomicU64::new(0)),
            events_passed: CachePadded::new(AtomicU64::new(0)),
            events_filtered: CachePadded::new(AtomicU64::new(0)),
            state_evictions: CachePadded::new(AtomicU64::new(0)),
        }
    }

    pub fn with_default_epsilon() -> Self {
        Self::new(DEFAULT_DEAD_BAND)
    }

    // ── Main entry point ─────────────────────────────────────
    // Called for every event coming off the ring buffer.
    // Returns None if the event is dead-band suppressed.
    // Returns Some(ScoredEvent) otherwise.
    //
    // `event_id`   — index into EventStore (already pushed)
    // `vertex_id`  — XDP-tagged graph node ID
    // `risk_score` — from EPL rule engine or node baseline
    // `ts_ns`      — kernel timestamp (nanoseconds)
    // `chain_depth`— 0 for standalone, >0 if part of a chain
    #[inline]
    pub fn score(
        &mut self,
        event_id: usize,
        vertex_id: u32,
        risk_score: f32,
        ts_ns: u64,
        chain_depth: u8,
    ) -> Option<ScoredEvent> {
        self.events_in.fetch_add(1, Ordering::Relaxed);

        let now = Instant::now();
        let risk_score = risk_score.clamp(0.0, 1.0);

        // ── Look up or create per-process state ──────────────
        let entry = self.state.entry(vertex_id).or_insert_with(|| {
            // First time we've seen this process.
            // Treat as maximum delta — new process is always interesting.
            ProcessState {
                last_risk: 0.0,
                last_seen: now,
                event_count: 0,
            }
        });

        // ── Compute delta ─────────────────────────────────────
        let risk_delta = risk_score - entry.last_risk;

        // ── Dead-band filter ──────────────────────────────────
        // Suppress if risk hasn't changed significantly AND this
        // process has been seen before (not a new process).
        // New processes always pass regardless of epsilon.
        let is_new_process = entry.event_count == 0;
        if !is_new_process && risk_delta.abs() < self.dead_band_epsilon {
            // Update last_seen even on filtered events so we don't
            // declare this process stale
            entry.last_seen = now;
            self.events_filtered.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Event age in milliseconds ─────────────────────────
        // ts_ns is the kernel-side nanosecond timestamp.
        // age = wall-clock now - kernel event time.
        // We approximate using the time since last ProcessState update.
        let age_ms = now.duration_since(entry.last_seen).as_millis() as f32;

        // ── Score components ──────────────────────────────────

        // Severity (30%): raw risk score — higher risk = more important
        let severity = risk_score;

        // Delta (40%): normalised absolute change.
        // Saturates at 1.0 — a jump from 0.0 to 1.0 scores the same as
        // a jump from 0.5 to 1.0 (both are "large changes").
        // First-time processes get delta = 1.0 (maximum novelty).
        let delta = if is_new_process {
            1.0
        } else {
            // Normalise by the maximum possible delta (1.0) and apply
            // a mild exponent to emphasise larger changes.
            (risk_delta.abs() / 1.0_f32).powf(0.7).min(1.0)
        };

        // Recency (20%): exponential decay by event age.
        // At age=0ms: recency=1.0. At age=HALF_LIFE: recency=0.5.
        // Formula: 2^(-age / half_life)
        let recency = 2.0_f32.powf(-age_ms / RECENCY_HALF_LIFE_MS);

        // Context (10%): chain depth bonus.
        // Saturates at chain_depth=8 (8 or more hops in a kill chain).
        // Each hop adds (1/8) of the context weight.
        let context = (chain_depth as f32 / 8.0).min(1.0);

        let components = ScoreComponents {
            severity,
            delta,
            recency,
            context,
        };
        let relevance = components.total().clamp(0.0, 1.0);

        // ── Update state ──────────────────────────────────────
        entry.last_risk = risk_score;
        entry.last_seen = now;
        entry.event_count += 1;

        self.events_passed.fetch_add(1, Ordering::Relaxed);

        Some(ScoredEvent {
            event_id,
            vertex_id,
            relevance,
            risk_delta,
            components,
        })
    }

    // ── Convenience: score from a HotEvent directly ──────────
    // Used by the ingest loop so it doesn't have to unpack fields.
    pub fn score_hot(
        &mut self,
        event_id: usize,
        hot: &crate::data::event_store::HotEvent,
        vertex_id: u32,
        chain_depth: u8,
    ) -> Option<ScoredEvent> {
        // HotEvent carries ts_ns and risk_score directly.
        // ts_ns is already PTP-synced nanoseconds from the kernel.
        self.score(event_id, vertex_id, hot.risk_score, hot.ts_ns, chain_depth)
    }

    // ── Evict stale per-process state ─────────────────────────
    // Called by the housekeeping loop every 5 seconds.
    // Removes entries for processes that haven't been seen in
    // STALE_THRESHOLD. Short-lived processes (scripts, one-shot
    // commands) would otherwise accumulate indefinitely.
    pub fn evict_stale(&mut self) {
        let before = self.state.len();
        let now = Instant::now();
        self.state
            .retain(|_, s| now.duration_since(s.last_seen) < STALE_THRESHOLD);
        let evicted = before - self.state.len();
        if evicted > 0 {
            self.state_evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

    // ── Reset a specific process's state ─────────────────────
    // Called when the graph sync service detects that a process
    // has exited (PROC_EXIT event). Removes the entry so if a
    // new process reuses the same vertex_id it is treated as new.
    pub fn reset_process(&mut self, vertex_id: u32) {
        self.state.remove(&vertex_id);
    }

    // ── Current filter rate ───────────────────────────────────
    // Fraction of incoming events suppressed by dead-band.
    // Healthy range: 0.70–0.95 (70–95% suppression).
    // If below 0.70: epsilon may be too low, sending too much.
    // If above 0.95: epsilon may be too high, missing signal.
    pub fn filter_rate(&self) -> f32 {
        let total = self.events_in.load(Ordering::Relaxed) as f32;
        let filtered = self.events_filtered.load(Ordering::Relaxed) as f32;
        if total < 1.0 {
            return 0.0;
        }
        filtered / total
    }

    pub fn tracked_process_count(&self) -> usize {
        self.state.len()
    }

    pub fn stats(&self) -> ScorerStats {
        let inn = self.events_in.load(Ordering::Relaxed);
        let passed = self.events_passed.load(Ordering::Relaxed);
        let filtered = self.events_filtered.load(Ordering::Relaxed);
        ScorerStats {
            events_in: inn,
            events_passed: passed,
            events_filtered: filtered,
            filter_rate: if inn == 0 {
                0.0
            } else {
                filtered as f32 / inn as f32
            },
            tracked_processes: self.state.len(),
            state_evictions: self.state_evictions.load(Ordering::Relaxed),
            dead_band_epsilon: self.dead_band_epsilon,
        }
    }
}

#[derive(Debug)]
pub struct ScorerStats {
    pub events_in: u64,
    pub events_passed: u64,
    pub events_filtered: u64,
    pub filter_rate: f32,
    pub tracked_processes: usize,
    pub state_evictions: u64,
    pub dead_band_epsilon: f32,
}

// ── Tests ─────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn scorer() -> RelevanceScorer {
        RelevanceScorer::new(0.05)
    }

    #[test]
    fn new_process_always_passes_filter() {
        let mut s = scorer();
        // First event for vertex 1 — never seen before
        let result = s.score(0, 1, 0.02, 0, 0);
        assert!(result.is_some(), "new process should always pass dead-band");
    }

    #[test]
    fn dead_band_suppresses_small_delta() {
        let mut s = scorer(); // epsilon = 0.05

        // First event — passes as new process
        s.score(0, 1, 0.50, 0, 0);

        // Second event — risk changed by 0.02 (below epsilon)
        let r = s.score(1, 1, 0.52, 1_000_000, 0);
        assert!(r.is_none(), "small delta should be filtered");
        assert_eq!(s.events_filtered.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn large_delta_passes_filter() {
        let mut s = scorer();

        s.score(0, 1, 0.10, 0, 0);

        // Risk jumps from 0.10 to 0.90 — delta = 0.80, way above epsilon
        let r = s.score(1, 1, 0.90, 1_000_000, 0);
        assert!(r.is_some(), "large delta should pass filter");
        assert!((r.unwrap().risk_delta - 0.80).abs() < 0.01);
    }

    #[test]
    fn score_components_sum_correctly() {
        let mut s = scorer();
        // First event — chain_depth=3
        let r = s.score(0, 1, 0.80, 0, 3).unwrap();
        let computed = r.components.severity * W_SEVERITY
            + r.components.delta * W_DELTA
            + r.components.recency * W_RECENCY
            + r.components.context * W_CONTEXT;
        assert!(
            (computed - r.relevance).abs() < 1e-5,
            "components.total() should equal relevance"
        );
    }

    #[test]
    fn recency_decays_with_age() {
        let mut s = scorer();

        // Two processes: one with a fresh event, one simulated as old
        // We can't directly control Instant but we can check the formula
        // at age=0 recency component should be 1.0
        let r = s.score(0, 1, 0.80, 0, 0).unwrap();
        // At age=0 the process is new so recency is computed from
        // now - entry.last_seen which is ~0ms
        assert!(
            r.components.recency > 0.95,
            "fresh event should have near-1.0 recency, got {}",
            r.components.recency
        );
    }

    #[test]
    fn chain_depth_increases_context_component() {
        let mut s1 = scorer();
        let mut s2 = scorer();

        let standalone = s1.score(0, 1, 0.5, 0, 0).unwrap();
        let in_chain = s2.score(0, 1, 0.5, 0, 8).unwrap();

        assert!(
            in_chain.components.context > standalone.components.context,
            "chain events should have higher context score"
        );
        assert!(
            (in_chain.components.context - 1.0).abs() < 1e-5,
            "depth=8 should saturate context at 1.0"
        );
    }

    #[test]
    fn new_process_gets_max_delta() {
        let mut s = scorer();
        // New process with low risk_score — delta should still be 1.0
        let r = s.score(0, 42, 0.05, 0, 0).unwrap();
        assert!(
            (r.components.delta - 1.0).abs() < 1e-5,
            "new process should get delta=1.0 regardless of risk"
        );
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let mut s = RelevanceScorer::new(0.05);

        // Record events for 3 processes
        s.score(0, 1, 0.5, 0, 0);
        s.score(1, 2, 0.5, 0, 0);
        s.score(2, 3, 0.5, 0, 0);
        assert_eq!(s.tracked_process_count(), 3);

        // Manually age the entries past STALE_THRESHOLD
        for state in s.state.values_mut() {
            state.last_seen = Instant::now()
                .checked_sub(STALE_THRESHOLD + Duration::from_secs(1))
                .unwrap_or(Instant::now());
        }

        s.evict_stale();
        assert_eq!(s.tracked_process_count(), 0);
        assert_eq!(s.state_evictions.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn reset_process_treats_next_event_as_new() {
        let mut s = scorer();

        // First event establishes state
        s.score(0, 7, 0.8, 0, 0);
        // Second event — small delta, normally filtered
        let r1 = s.score(1, 7, 0.82, 1_000, 0);
        assert!(r1.is_none(), "should be filtered");

        // Reset the process state
        s.reset_process(7);

        // Next event should be treated as new — passes regardless of delta
        let r2 = s.score(2, 7, 0.82, 2_000, 0);
        assert!(r2.is_some(), "after reset, should pass as new process");
    }

    #[test]
    fn filter_rate_tracks_correctly() {
        let mut s = scorer();

        s.score(0, 1, 0.5, 0, 0); // passes (new)
        s.score(1, 1, 0.51, 1_000, 0); // filtered (delta=0.01 < 0.05)
        s.score(2, 1, 0.52, 2_000, 0); // filtered
        s.score(3, 1, 0.90, 3_000, 0); // passes (delta=0.38 > 0.05)

        // 2 out of 4 filtered = 0.5 filter rate
        assert!((s.filter_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn relevance_is_clamped_to_unit_range() {
        let mut s = scorer();
        let r = s.score(0, 1, 1.0, 0, 8).unwrap(); // maximum inputs
        assert!(r.relevance >= 0.0 && r.relevance <= 1.0);
    }
}
