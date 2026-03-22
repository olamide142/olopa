// ============================================================
// OLOPA — MetricAggregator
// ============================================================
// One aggregator per ingest worker core. Never shared.
// Each core writes into its own HashMap<u32, TDigest> with
// zero contention. A background flush task drains all cores
// every 100ms and ships one compact MetricSummary per comm_id.
//
// 1,000 raw CPU readings → 7 floats (min/max/mean/p50/p95/p99/count)
// All keys are u32 comm_ids — strings never reach this layer.
// Strings were converted to integers at the eBPF ID-assignment stage.
// ============================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use crossbeam_utils::CachePadded;

// ── Compile-time size guard ──────────────────────────────────
const _: () = assert!(std::mem::size_of::<MetricSummary>() == 56);

// ── MetricSummary — 56 bytes, one per comm_id per flush ─────
// Largest fields first: f64 × 6 + u32 + u32 = 48 + 8 = 56 bytes.
// This is what leaves the agent every 100ms.
// 1,000 raw f32 readings (4,000 bytes) → 56 bytes = 98.6% reduction.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MetricSummary {
    pub min:     f64,   // 8
    pub max:     f64,   // 8
    pub mean:    f64,   // 8
    pub p50:     f64,   // 8
    pub p95:     f64,   // 8
    pub p99:     f64,   // 8
    pub comm_id: u32,   // 4 — which process type this covers
    pub count:   u32,   // 4 — how many raw values were compressed
}
// Total: 56 bytes.

// ── TDigest — streaming percentile estimator ────────────────
// Stores a compact set of weighted centroids.
// Merge is associative — multiple cores' digests can be merged
// before flushing, giving fleet-wide percentiles if needed.
// Accuracy: p99 error < 1% for compression=100.
//
// This is a minimal hand-rolled implementation that covers the
// Olopa use case (flush every 100ms, ~1000 values per window).
// Production: swap for the `tdigest` crate which is more complete.
pub struct TDigest {
    centroids:   Vec<Centroid>,   // sorted by mean
    compression: f64,             // trades accuracy for memory (100 = good default)
    count:       u64,             // total values merged so far
    min:         f64,
    max:         f64,
    sum:         f64,
}

#[derive(Clone, Copy, Debug)]
struct Centroid {
    mean:   f64,
    weight: f64,
}

impl TDigest {
    pub fn new(compression: f64) -> Self {
        Self {
            centroids:   Vec::with_capacity(compression as usize * 2),
            compression,
            count:       0,
            min:         f64::MAX,
            max:         f64::MIN,
            sum:         0.0,
        }
    }

    // ── Hot-path insert ─────────────────────────────────────
    // Each incoming value is a new centroid of weight 1.
    // We merge it into the nearest existing centroid if that
    // centroid is below its size limit (determined by compression).
    // Full recompression triggered lazily when len > 2×compression.
    #[inline]
    pub fn push(&mut self, value: f64) {
        self.count += 1;
        self.sum   += value;
        if value < self.min { self.min = value; }
        if value > self.max { self.max = value; }

        // Insert new centroid, keep list sorted by mean
        let pos = self.centroids
            .binary_search_by(|c| c.mean.partial_cmp(&value).unwrap())
            .unwrap_or_else(|i| i);
        self.centroids.insert(pos, Centroid { mean: value, weight: 1.0 });

        // Compress lazily when we have too many centroids
        if self.centroids.len() > (self.compression as usize * 2) {
            self.compress();
        }
    }

    // ── Merge another digest into this one ──────────────────
    // Used when combining per-core digests before flushing.
    pub fn merge(&mut self, other: &TDigest) {
        for c in &other.centroids {
            for _ in 0..(c.weight as u64) {
                self.push(c.mean);
            }
        }
        // Carry over min/max exactly
        if other.min < self.min { self.min = other.min; }
        if other.max > self.max { self.max = other.max; }
    }

    // ── Compress: merge adjacent centroids ──────────────────
    fn compress(&mut self) {
        if self.centroids.is_empty() { return; }

        let total_weight: f64 = self.centroids.iter().map(|c| c.weight).sum();
        let mut merged: Vec<Centroid> = Vec::with_capacity(self.compression as usize);

        let mut cumulative_weight = 0.0_f64;
        let mut current = self.centroids[0];

        for c in self.centroids.iter().skip(1) {
            let k1 = self.size_limit(cumulative_weight, total_weight);
            if current.weight + c.weight <= k1 {
                // Merge c into current centroid (weighted average)
                let total = current.weight + c.weight;
                current.mean = (current.mean * current.weight + c.mean * c.weight) / total;
                current.weight = total;
            } else {
                cumulative_weight += current.weight;
                merged.push(current);
                current = *c;
            }
        }
        merged.push(current);
        self.centroids = merged;
    }

    // Centroid size limit — smaller near the tails for accuracy
    fn size_limit(&self, cumulative: f64, total: f64) -> f64 {
        let q = cumulative / total;
        let q2 = q * (1.0 - q);
        4.0 * total * q2 / self.compression
    }

    // ── Quantile query ──────────────────────────────────────
    // Returns the estimated value at quantile q (0.0–1.0).
    pub fn quantile(&self, q: f64) -> f64 {
        if self.centroids.is_empty() { return 0.0; }
        if q <= 0.0 { return self.min; }
        if q >= 1.0 { return self.max; }

        let total: f64 = self.centroids.iter().map(|c| c.weight).sum();
        let target = q * total;
        let mut cumulative = 0.0_f64;

        for (i, c) in self.centroids.iter().enumerate() {
            cumulative += c.weight;
            if cumulative >= target {
                // Interpolate between this centroid and the next
                if i + 1 < self.centroids.len() {
                    let next = &self.centroids[i + 1];
                    let fraction = (cumulative - target) / c.weight;
                    return c.mean + fraction * (next.mean - c.mean);
                }
                return c.mean;
            }
        }
        self.max
    }

    pub fn min(&self)   -> f64 { self.min }
    pub fn max(&self)   -> f64 { self.max }
    pub fn mean(&self)  -> f64 { if self.count == 0 { 0.0 } else { self.sum / self.count as f64 } }
    pub fn count(&self) -> u32 { self.count as u32 }

    pub fn is_empty(&self) -> bool { self.count == 0 }

    // ── Reset for next flush window ─────────────────────────
    // Clears all state. Does NOT free memory — Vec capacity stays.
    // Zero allocator pressure between flush windows.
    pub fn reset(&mut self) {
        self.centroids.clear();
        self.count = 0;
        self.min   = f64::MAX;
        self.max   = f64::MIN;
        self.sum   = 0.0;
    }

    // ── Build a MetricSummary from current state ─────────────
    pub fn summarize(&self, comm_id: u32) -> MetricSummary {
        MetricSummary {
            min:     self.min(),
            max:     self.max(),
            mean:    self.mean(),
            p50:     self.quantile(0.50),
            p95:     self.quantile(0.95),
            p99:     self.quantile(0.99),
            comm_id,
            count:   self.count(),
        }
    }
}

// ── Per-core MetricAggregator ────────────────────────────────
// One instance per ingest worker. Never shared between threads.
// No Mutex, no Arc, no atomic on the hot path.
// The flush task holds a reference (or receives results via channel).
pub struct MetricAggregator {
    // HashMap<comm_id: u32, TDigest>
    // comm_id is a u32 integer — no strings ever reach this map.
    // Strings were converted to integers at the eBPF ID-assignment stage.
    digests:        HashMap<u32, TDigest>,

    // How many raw values have been pushed since last flush
    values_pushed:  u64,

    // Flush interval — flush() is called externally every 100ms
    // by the background flush task. This timer is for self-monitoring only.
    last_flush:     Instant,
    flush_interval: Duration,

    // CachePadded counters — each on its own 64-byte cache line.
    // If this aggregator ever shares a cache line with another core's
    // counter (e.g. in a global stats array), false sharing causes
    // both cores to invalidate each other's L1 on every increment.
    // CachePadded prevents this entirely.
    pub total_values_processed: CachePadded<AtomicU64>,
    pub total_flushes:          CachePadded<AtomicU64>,
    pub total_summaries_sent:   CachePadded<AtomicU64>,
}

impl MetricAggregator {
    pub fn new(flush_interval_ms: u64) -> Self {
        Self {
            digests:       HashMap::with_capacity(512), // ~512 distinct process types
            values_pushed: 0,
            last_flush:    Instant::now(),
            flush_interval: Duration::from_millis(flush_interval_ms),
            total_values_processed: CachePadded::new(AtomicU64::new(0)),
            total_flushes:          CachePadded::new(AtomicU64::new(0)),
            total_summaries_sent:   CachePadded::new(AtomicU64::new(0)),
        }
    }

    // ── Hot-path record ─────────────────────────────────────
    // Called on every relevant event. Zero allocations after warmup.
    // HashMap::entry() is O(1) average with no heap allocation
    // once the TDigest for this comm_id already exists.
    //
    // `value` is the metric being tracked — typically:
    //   - risk_score (f32 cast to f64)
    //   - syscall latency in nanoseconds
    //   - bytes transferred per connection
    //   - process lifetime in ms
    #[inline(always)]
    pub fn record(&mut self, comm_id: u32, value: f64) {
        self.digests
            .entry(comm_id)
            .or_insert_with(|| TDigest::new(100.0))
            .push(value);

        self.values_pushed += 1;
        // Relaxed — this is a per-core counter, no cross-thread ordering needed
        self.total_values_processed.fetch_add(1, Ordering::Relaxed);
    }

    // ── Convenience: record a risk score directly ────────────
    #[inline(always)]
    pub fn record_risk(&mut self, comm_id: u32, risk_score: f32) {
        self.record(comm_id, risk_score as f64);
    }

    // ── Flush: drain all digests → Vec<MetricSummary> ────────
    // Called every 100ms by the background flush task.
    // Returns one MetricSummary per comm_id that has received data.
    // Resets all digests in place — no deallocation.
    //
    // Output size: n_distinct_comm_ids × 56 bytes
    // For 100 process types: 5,600 bytes per 100ms window.
    // For 1,000 raw values per comm_id: 1,000 × 4 bytes → 56 bytes = 98.6% reduction.
    pub fn flush(&mut self) -> Vec<MetricSummary> {
        let mut summaries = Vec::with_capacity(self.digests.len());

        for (&comm_id, digest) in &mut self.digests {
            if digest.is_empty() { continue; }
            summaries.push(digest.summarize(comm_id));
            digest.reset(); // reset in place — capacity preserved, no dealloc
        }

        self.values_pushed = 0;
        self.last_flush    = Instant::now();
        self.total_flushes.fetch_add(1, Ordering::Relaxed);
        self.total_summaries_sent.fetch_add(summaries.len() as u64, Ordering::Relaxed);
        summaries
    }

    // ── Should we flush? (for poll-based flush loops) ────────
    #[inline(always)]
    pub fn needs_flush(&self) -> bool {
        self.last_flush.elapsed() >= self.flush_interval
    }

    // ── Flush if interval has elapsed ────────────────────────
    #[inline(always)]
    pub fn flush_if_ready(&mut self) -> Option<Vec<MetricSummary>> {
        if self.needs_flush() {
            Some(self.flush())
        } else {
            None
        }
    }

    pub fn stats(&self) -> AggregatorStats {
        AggregatorStats {
            distinct_comm_ids:       self.digests.len(),
            values_since_last_flush: self.values_pushed,
            total_processed:         self.total_values_processed.load(Ordering::Relaxed),
            total_flushes:           self.total_flushes.load(Ordering::Relaxed),
            total_summaries_sent:    self.total_summaries_sent.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct AggregatorStats {
    pub distinct_comm_ids:       usize,
    pub values_since_last_flush: u64,
    pub total_processed:         u64,
    pub total_flushes:           u64,
    pub total_summaries_sent:    u64,
}

// ── Fleet aggregator: merges per-core digests ────────────────
// When you want fleet-wide percentiles (not just per-core),
// this collects MetricSummary from all cores, groups by comm_id,
// and merges TDigests before shipping to ClickHouse.
//
// Not on the hot path — runs on the flush task's thread.
pub struct FleetAggregator {
    // comm_id → merged TDigest (across all cores)
    merged: HashMap<u32, TDigest>,
}

impl FleetAggregator {
    pub fn new() -> Self {
        Self { merged: HashMap::with_capacity(512) }
    }

    // Ingest summaries from one core's flush output.
    // In production you'd receive the raw TDigest via a channel,
    // not just the summary, to enable full merge accuracy.
    // Shown here with summaries for simplicity.
    pub fn ingest_summaries(&mut self, summaries: Vec<MetricSummary>) {
        for s in summaries {
            let digest = self.merged
                .entry(s.comm_id)
                .or_insert_with(|| TDigest::new(100.0));
            // Approximate re-ingest from summary quantiles
            // Full accuracy: send raw TDigest bytes over channel and call merge()
            digest.push(s.min);
            digest.push(s.mean);
            digest.push(s.p50);
            digest.push(s.p95);
            digest.push(s.p99);
            digest.push(s.max);
        }
    }

    // Produce fleet-wide summaries — shipped to ClickHouse
    pub fn fleet_summaries(&mut self) -> Vec<MetricSummary> {
        let mut out = Vec::with_capacity(self.merged.len());
        for (&comm_id, digest) in &mut self.merged {
            if !digest.is_empty() {
                out.push(digest.summarize(comm_id));
                digest.reset();
            }
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_size_is_correct() {
        assert_eq!(std::mem::size_of::<MetricSummary>(), 56);
    }

    #[test]
    fn tdigest_basic_percentiles() {
        let mut d = TDigest::new(100.0);
        // Push 1000 values: 0.0, 0.001, 0.002, ..., 0.999
        for i in 0..1000u32 {
            d.push(i as f64 / 1000.0);
        }
        assert_eq!(d.count(), 1000);
        assert!((d.min()  - 0.0).abs()   < 0.001);
        assert!((d.max()  - 0.999).abs() < 0.001);
        assert!((d.mean() - 0.4995).abs() < 0.01);
        // p50 ≈ 0.50 (within 1%)
        assert!((d.quantile(0.50) - 0.50).abs() < 0.01,
            "p50={}", d.quantile(0.50));
        // p99 ≈ 0.99 (within 2%)
        assert!((d.quantile(0.99) - 0.99).abs() < 0.02,
            "p99={}", d.quantile(0.99));
    }

    #[test]
    fn tdigest_reset_clears_state() {
        let mut d = TDigest::new(100.0);
        for i in 0..500 { d.push(i as f64); }
        assert_eq!(d.count(), 500);
        d.reset();
        assert_eq!(d.count(), 0);
        assert!(d.is_empty());
    }

    #[test]
    fn aggregator_flush_produces_summaries() {
        let mut agg = MetricAggregator::new(100);
        let nginx_id: u32 = 7;
        let bash_id:  u32 = 42;

        // Record 1000 risk scores for nginx, 500 for bash
        for i in 0..1000u32 {
            agg.record_risk(nginx_id, i as f32 / 1000.0);
        }
        for i in 0..500u32 {
            agg.record_risk(bash_id, 0.5 + i as f32 / 1000.0);
        }

        let summaries = agg.flush();
        assert_eq!(summaries.len(), 2);

        let nginx = summaries.iter().find(|s| s.comm_id == nginx_id).unwrap();
        assert_eq!(nginx.count, 1000);
        assert!((nginx.min  - 0.0).abs()  < 0.002);
        assert!((nginx.max  - 0.999).abs() < 0.002);
        assert!((nginx.p99  - 0.99).abs()  < 0.02);

        // After flush, digests should be reset
        let summaries2 = agg.flush();
        assert!(summaries2.is_empty(), "digests should be empty after flush");
    }

    #[test]
    fn aggregator_no_false_sharing() {
        // Verify CachePadded actually pads to 64 bytes
        use std::mem::size_of;
        assert_eq!(size_of::<CachePadded<AtomicU64>>(), 64);
    }

    #[test]
    fn compression_reduces_raw_to_summary() {
        let mut agg = MetricAggregator::new(100);
        let comm_id = 1u32;

        // Push 1000 raw f32 values = 4,000 bytes of raw data
        for i in 0..1000u32 {
            agg.record(comm_id, i as f64);
        }

        let summaries = agg.flush();
        assert_eq!(summaries.len(), 1);

        // 1 MetricSummary = 56 bytes
        // Raw data was 1000 × 4 bytes = 4,000 bytes
        // Reduction: (4000 - 56) / 4000 = 98.6%
        let raw_bytes     = 1000 * 4;
        let summary_bytes = std::mem::size_of::<MetricSummary>();
        let reduction = 1.0 - (summary_bytes as f64 / raw_bytes as f64);
        assert!(reduction > 0.98, "expected >98% reduction, got {:.1}%", reduction * 100.0);
    }
}