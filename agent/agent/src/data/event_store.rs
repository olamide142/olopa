// ============================================================
// OLOPA — EventStore (Structure of Arrays)
// ============================================================
// Two parallel arrays, same index = same event.
// Hot path only ever touches `hot`. Cold data loaded on alert.
// ============================================================

use std::sync::atomic::{AtomicU64, Ordering};
use crossbeam_utils::CachePadded;

// ── Compile-time size guards ─────────────────────────────────
// If you change a field, the assert fails loudly at compile time.
const _: () = assert!(std::mem::size_of::<HotEvent>()  == 16);
const _: () = assert!(std::mem::size_of::<ColdEvent>() == 128);

// ── HotEvent — 16 bytes, 4 per cache line ───────────────────
// Largest field first: u64, then u32, then f32.
// No padding inserted by the compiler.
// repr(C) so layout is deterministic and matches eBPF structs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HotEvent {
    pub ts_ns:      u64,   // 8 bytes — nanosecond epoch (PTP-synced)
    pub pid:        u32,   // 4 bytes — kernel PID
    pub risk_score: f32,   // 4 bytes — computed by relevance scorer
}
// Total: 16 bytes. A single cache line holds exactly 4 HotEvents.
// Sequential scan over hot[] = hardware prefetcher works perfectly.

// ── ColdEvent — 128 bytes, loaded only on alert ─────────────
// Never touched on the hot path. Stays evicted from cache.
// Loaded by index: cold[event_id] — one array lookup on alert.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ColdEvent {
    pub argv_hash: [u8; 32],  // SHA-256 of argv — never raw args
    pub path_hash: [u8; 32],  // SHA-256 of full file path
    pub env_hash:  [u8; 32],  // SHA-256 of environment block
    pub ppid:      u32,       // parent PID — for lineage, not hot path
    pub uid:       u32,       // effective UID at exec time
    pub gid:       u32,       // effective GID at exec time
    pub comm_id:   u32,       // string→int assigned at eBPF layer
    pub _pad:      [u8; 16],  // explicit padding to 128 bytes
}
// 32+32+32 = 96 bytes of hashes + 16 bytes of integers + 16 pad = 128 bytes.
// Sensitive data (argv, paths, env) is hashed — never stored raw.
// Preserves searchability: query by hash, not by string.

// ── EventStore — the container ──────────────────────────────
// Parallel arrays. hot[i] and cold[i] describe the same event.
// Indexed by a monotonic u64 event_id (wraps at u64::MAX — fine).
pub struct EventStore {
    hot:      Vec<HotEvent>,      // scanned on every event — keep cache-hot
    cold:     Vec<ColdEvent>,     // loaded by index on alert — keep cache-cold
    len:      usize,              // current number of events stored
    capacity: usize,              // fixed at construction — no realloc on hot path

    // Per-store counters. CachePadded prevents false sharing on multi-core.
    // Each counter lives on its own 64-byte cache line.
    total_written: CachePadded<AtomicU64>,
    total_dropped: CachePadded<AtomicU64>,
    alert_loads:   CachePadded<AtomicU64>, // how often cold[] was accessed
}

impl EventStore {
    // ── Construction ────────────────────────────────────────
    // Pre-allocate both arrays once. Never reallocate on the hot path.
    // Capacity should be sized to hold ~10–60s of events per agent.
    //
    //   Example: 100_000 events/sec × 30s = 3_000_000 capacity
    //   hot:  3_000_000 × 16 bytes  =  48 MB
    //   cold: 3_000_000 × 128 bytes = 384 MB  ← only loaded on alert
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            hot:  Vec::with_capacity(capacity),
            cold: Vec::with_capacity(capacity),
            len:  0,
            capacity,
            total_written: CachePadded::new(AtomicU64::new(0)),
            total_dropped: CachePadded::new(AtomicU64::new(0)),
            alert_loads:   CachePadded::new(AtomicU64::new(0)),
        }
    }

    // ── Hot-path write ───────────────────────────────────────
    // Called ~15M times/sec per core. Zero allocations. Zero locks.
    // Returns the event_id (index) so callers can reference it later.
    #[inline(always)]
    pub fn push(&mut self, hot: HotEvent, cold: ColdEvent) -> Option<usize> {
        if self.len >= self.capacity {
            // Ring-buffer wrap: overwrite from the start.
            // In production you'd use a modulo index.
            // Here we signal the drop for metrics and return None.
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let id = self.len;
        // SAFETY: capacity was pre-allocated — no realloc.
        // Both pushes always happen together — the arrays stay in sync.
        unsafe {
            let hot_ptr  = self.hot.as_mut_ptr().add(id);
            let cold_ptr = self.cold.as_mut_ptr().add(id);
            std::ptr::write(hot_ptr,  hot);
            std::ptr::write(cold_ptr, cold);
            self.hot.set_len(id + 1);
            self.cold.set_len(id + 1);
        }
        self.len += 1;
        self.total_written.fetch_add(1, Ordering::Relaxed);
        Some(id)
    }

    // ── Hot-path read — only touches hot[] ──────────────────
    // Iterate every HotEvent in the store. Cold array is never loaded.
    // The compiler can auto-vectorize this loop (SIMD) because:
    //   - HotEvent is repr(C) with predictable field offsets
    //   - The slice is contiguous in memory
    //   - No branches inside the loop body (caller filters)
    #[inline(always)]
    pub fn hot_events(&self) -> &[HotEvent] {
        &self.hot[..self.len]
    }

    // ── Alert path — loads cold[] by index ──────────────────
    // Called only when an alert fires. One cache miss is acceptable here.
    // Returns None if event_id is out of range (defensive).
    #[inline]
    pub fn cold_event(&self, event_id: usize) -> Option<&ColdEvent> {
        if event_id >= self.len {
            return None;
        }
        self.alert_loads.fetch_add(1, Ordering::Relaxed);
        // This is the first touch of cold[event_id] since it was written.
        // Expected: one cache miss (~100ns). Acceptable on alert path.
        Some(&self.cold[event_id])
    }

    // ── SIMD-ready: scan hot[] for risk threshold ────────────
    // Returns indices of events that exceed the threshold.
    // The tight loop over a flat &[HotEvent] slice is what the
    // AVX-512 batch checker in ingest/worker.rs operates on.
    pub fn events_above_risk(&self, threshold: f32) -> Vec<usize> {
        self.hot_events()
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if e.risk_score > threshold { Some(i) } else { None }
            })
            .collect()
    }

    // ── Ring-buffer reset (flush window) ────────────────────
    // Called every 60s by the time-slice rotation.
    // Does NOT free memory — just resets the length pointer.
    // Old data is overwritten on next push. Zero dealloc cost.
    pub fn reset(&mut self) {
        self.len = 0;
        // SAFETY: we track len manually. Vec capacity is unchanged.
        unsafe {
            self.hot.set_len(0);
            self.cold.set_len(0);
        }
    }

    // ── Metrics ─────────────────────────────────────────────
    pub fn stats(&self) -> EventStoreStats {
        EventStoreStats {
            len:           self.len,
            capacity:      self.capacity,
            fill_ratio:    self.len as f32 / self.capacity as f32,
            total_written: self.total_written.load(Ordering::Relaxed),
            total_dropped: self.total_dropped.load(Ordering::Relaxed),
            alert_loads:   self.alert_loads.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct EventStoreStats {
    pub len:           usize,
    pub capacity:      usize,
    pub fill_ratio:    f32,
    pub total_written: u64,
    pub total_dropped: u64,
    pub alert_loads:   u64,
}

// ── Usage example ────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_sizes_are_correct() {
        // These are load-bearing — change a field and these fail.
        assert_eq!(std::mem::size_of::<HotEvent>(),  16);
        assert_eq!(std::mem::size_of::<ColdEvent>(), 128);
        // 4 HotEvents fit in a 64-byte cache line
        assert_eq!(64 / std::mem::size_of::<HotEvent>(), 4);
    }

    #[test]
    fn hot_and_cold_stay_in_sync() {
        let mut store = EventStore::with_capacity(1024);

        let hot  = HotEvent  { ts_ns: 1_000_000, pid: 4821, risk_score: 0.85 };
        let cold = ColdEvent {
            argv_hash: [0xAA; 32],
            path_hash: [0xBB; 32],
            env_hash:  [0xCC; 32],
            ppid: 1241, uid: 33, gid: 33, comm_id: 7,
            _pad: [0; 16],
        };

        let id = store.push(hot, cold).expect("push should succeed");

        // Hot path: only touches hot[]
        assert_eq!(store.hot_events()[id].pid, 4821);
        assert!((store.hot_events()[id].risk_score - 0.85).abs() < 1e-6);

        // Alert path: loads cold[]
        let c = store.cold_event(id).expect("cold event should exist");
        assert_eq!(c.ppid, 1241);
        assert_eq!(c.argv_hash, [0xAA; 32]);
    }

    #[test]
    fn risk_threshold_scan() {
        let mut store = EventStore::with_capacity(16);
        for i in 0..8u32 {
            let risk = i as f32 * 0.125; // 0.0, 0.125, 0.25 ... 0.875
            let hot  = HotEvent { ts_ns: i as u64, pid: i, risk_score: risk };
            let cold = ColdEvent {
                argv_hash: [0; 32], path_hash: [0; 32], env_hash: [0; 32],
                ppid: 0, uid: 0, gid: 0, comm_id: 0, _pad: [0; 16],
            };
            store.push(hot, cold).unwrap();
        }
        // Events 5,6,7 have risk > 0.5
        let high_risk = store.events_above_risk(0.5);
        assert_eq!(high_risk, vec![5, 6, 7]);
    }
}
