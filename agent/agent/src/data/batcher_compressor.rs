// ============================================================
// OLOPA — Batcher + Compressor
// ============================================================
// Collects serialized telemetry frames from the scheduler,
// compresses them with zstd + a pre-trained domain dictionary,
// and flushes a single compressed batch to the gRPC sender
// when any of three triggers fire:
//
//   Size  — accumulated bytes > MAX_BATCH_BYTES
//   Time  — last flush was > FLUSH_INTERVAL_MS ago
//   Count — accumulated frames > MAX_FRAME_COUNT
//
// Compression level is chosen adaptively per window based on
// the current BudgetSnapshot from the PI controller:
//   Level 1 — CPU budget < 30% remaining   (speed over ratio)
//   Level 3 — normal operating conditions  (default)
//   Level 6 — BW budget < 40% remaining    (ratio over speed)
//   Level 9 — BW critically constrained    (maximum ratio)
//
// Dictionary training:
//   zstd dictionary trained offline on a sample of real Olopa
//   event batches (protobuf-encoded). Embedded as a static byte
//   array. Gives +10–15% ratio improvement over generic zstd.
//   Shared between the compressor (encoder) and backend (decoder).
//   Both sides must use identical dictionary (same dict_id).
// ============================================================

use bytes::{BufMut, Bytes, BytesMut};
use crossbeam_utils::CachePadded;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zstd::bulk::{Compressor, Decompressor};

// -- Flush thresholds -----------------------------------------
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024; // 4 MB
const MAX_FRAME_COUNT: usize = 1_000; // frames per batch
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

// -- Compression level thresholds ----------------------------
// Keyed on BudgetSnapshot utilization fractions.
const LEVEL_FAST: i32 = 1; // CPU < 30% remaining
const LEVEL_DEFAULT: i32 = 3; // normal
const LEVEL_BALANCED: i32 = 6; // BW < 40% remaining
const LEVEL_MAX: i32 = 9; // BW critically constrained

// -- Embedded zstd dictionary ---------------------------------
// In production: generated offline by running:
//   zstd --train /var/lib/olopa/samples/*.bin -o olopa.dict
// Then embedded here. 112 KB is the recommended dict size.
// This is a placeholder — replace with real trained dictionary.
// The dict_id is embedded in the zstd frame header automatically.
// Backend Decompressor must load the same bytes.
//
// Bootstrap runtime currently ships without a checked-in dictionary asset.
// Keep dictionary disabled until artifact management is wired.
static OLOPA_DICT: &[u8] = &[];

// -- Frame — one compressed telemetry unit --------------------
// A frame wraps one or more serialized TelemetryItems.
// Frames accumulate in the VecDeque until a flush trigger fires.
#[derive(Debug)]
pub struct Frame {
    pub compressed: Bytes, // zstd-compressed protobuf payload
    pub raw_len: u32,      // original byte count before compression
    pub frame_count: u16,  // number of events inside this frame
    pub level: i32,        // compression level used
}

// -- BatchHeader — prepended to every flushed batch -----------
// Fixed-size, repr(C), sent over the wire before the frames.
// Backend uses this to validate schema, decompress, and route.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BatchHeader {
    pub magic: [u8; 4],   // b"OLOP"
    pub schema_ver: u16,  // increment when frame format changes
    pub frame_count: u16, // number of frames in this batch
    pub raw_bytes: u32,   // total uncompressed bytes
    pub wire_bytes: u32,  // total compressed bytes (excl. header)
    pub agent_id: u32,    // which agent sent this
    pub ts_ns: u64,       // batch creation timestamp
    pub dict_id: u32,     // zstd dictionary ID (0 = no dict)
    pub _pad: [u8; 4],    // align to 40 bytes
}
const _: () = assert!(std::mem::size_of::<BatchHeader>() == 40);

// -- Batcher --------------------------------------------------
pub struct Batcher {
    // Pending compressed frames — bounded to prevent unbounded growth
    // under backpressure. When full, new frames are dropped (counted).
    queue: VecDeque<Frame>,
    queue_cap: usize,

    // Accumulated metrics for the current unflushed window
    raw_bytes: usize,
    wire_bytes: usize,
    last_flush: Instant,

    // zstd compressor — reused across frames (owns encoder state)
    // Loaded with the domain dictionary at construction.
    compressor: DictCompressor,

    // Agent identity — embedded in every BatchHeader
    agent_id: u32,

    // Metrics — each on its own cache line (no false sharing)
    pub total_frames_in: CachePadded<AtomicU64>,
    pub total_frames_out: CachePadded<AtomicU64>,
    pub total_raw_bytes: CachePadded<AtomicU64>,
    pub total_wire_bytes: CachePadded<AtomicU64>,
    pub total_flushes: CachePadded<AtomicU64>,
    pub total_dropped: CachePadded<AtomicU64>,
}

impl Batcher {
    pub fn new(agent_id: u32, queue_cap: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(queue_cap),
            queue_cap,
            raw_bytes: 0,
            wire_bytes: 0,
            last_flush: Instant::now(),
            compressor: DictCompressor::new(LEVEL_DEFAULT),
            agent_id,
            total_frames_in: CachePadded::new(AtomicU64::new(0)),
            total_frames_out: CachePadded::new(AtomicU64::new(0)),
            total_raw_bytes: CachePadded::new(AtomicU64::new(0)),
            total_wire_bytes: CachePadded::new(AtomicU64::new(0)),
            total_flushes: CachePadded::new(AtomicU64::new(0)),
            total_dropped: CachePadded::new(AtomicU64::new(0)),
        }
    }

    // -- Push serialized event bytes into the batcher ---------
    // `raw` is a protobuf-serialized TelemetryItem (or batch of items).
    // This is called by the scheduler output handler after solve().
    // Compresses immediately — the VecDeque holds compressed frames.
    //
    // Returns FlushNeeded if a flush trigger fired after this push,
    // so the caller knows to call flush() without waiting for the timer.
    pub fn push(&mut self, raw: &[u8], budget: &BudgetSnapshot) -> PushResult {
        // Adapt compression level to current budget state
        let level = self.select_level(budget);
        if level != self.compressor.level {
            self.compressor.set_level(level);
        }

        // Compress the raw bytes using the domain dictionary
        let compressed = match self.compressor.compress(raw) {
            Ok(c) => c,
            Err(e) => {
                // Compression failure — drop this frame, log, continue
                // Never panic on the hot path
                eprintln!("olopa batcher: compress error: {e}");
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
                return PushResult::Ok;
            }
        };

        let frame = Frame {
            raw_len: raw.len() as u32,
            frame_count: 1,
            level,
            compressed: Bytes::from(compressed),
        };

        self.total_frames_in.fetch_add(1, Ordering::Relaxed);
        self.total_raw_bytes
            .fetch_add(raw.len() as u64, Ordering::Relaxed);

        // Queue full — drop the frame (backpressure from sender)
        if self.queue.len() >= self.queue_cap {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return PushResult::QueueFull;
        }

        self.wire_bytes += frame.compressed.len();
        self.raw_bytes += raw.len();
        self.queue.push_back(frame);

        // Check flush triggers
        if self.should_flush() {
            PushResult::FlushNeeded
        } else {
            PushResult::Ok
        }
    }

    // -- Flush: drain queue → one BatchOutput -----------------
    // Assembles all pending frames into a single contiguous buffer
    // ready for the gRPC sender. Clears the queue.
    // Returns None if nothing is pending.
    pub fn flush(&mut self) -> Option<BatchOutput> {
        if self.queue.is_empty() {
            return None;
        }

        let n_frames = self.queue.len();
        let raw_total = self.raw_bytes;
        let wire_total = self.wire_bytes;

        // Allocate output buffer: header + all compressed frame bodies
        // Each frame is preceded by a 4-byte length prefix (u32 BE).
        let capacity = std::mem::size_of::<BatchHeader>() + wire_total + n_frames * 4; // 4-byte length prefix per frame

        let mut buf = BytesMut::with_capacity(capacity);

        // Write BatchHeader
        let header = BatchHeader {
            magic: *b"OLOP",
            schema_ver: 1,
            frame_count: n_frames as u16,
            raw_bytes: raw_total as u32,
            wire_bytes: wire_total as u32,
            agent_id: self.agent_id,
            ts_ns: now_ns(),
            dict_id: self.compressor.dict_id,
            _pad: [0; 4],
        };
        // SAFETY: BatchHeader is repr(C), all fields are initialized.
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const BatchHeader as *const u8,
                std::mem::size_of::<BatchHeader>(),
            )
        };
        buf.put_slice(header_bytes);

        // Write each frame: [u32 len BE][compressed bytes]
        let mut n_events_total = 0u32;
        while let Some(frame) = self.queue.pop_front() {
            n_events_total += frame.frame_count as u32;
            buf.put_u32(frame.compressed.len() as u32);
            buf.put_slice(&frame.compressed);
            self.total_frames_out.fetch_add(1, Ordering::Relaxed);
        }

        // Reset window state
        self.raw_bytes = 0;
        self.wire_bytes = 0;
        self.last_flush = Instant::now();

        self.total_wire_bytes
            .fetch_add(wire_total as u64, Ordering::Relaxed);
        self.total_flushes.fetch_add(1, Ordering::Relaxed);

        Some(BatchOutput {
            payload: buf.freeze(),
            n_frames,
            n_events: n_events_total as usize,
            raw_bytes: raw_total,
            wire_bytes: wire_total,
            compression_ratio: raw_total as f32 / wire_total.max(1) as f32,
        })
    }

    // -- Flush if any trigger is satisfied --------------------
    pub fn flush_if_ready(&mut self) -> Option<BatchOutput> {
        if self.should_flush() {
            self.flush()
        } else {
            None
        }
    }

    // -- Three flush triggers ----------------------------------
    #[inline(always)]
    fn should_flush(&self) -> bool {
        self.wire_bytes  >= MAX_BATCH_BYTES       // size trigger
        || self.queue.len() >= MAX_FRAME_COUNT    // count trigger
        || self.last_flush.elapsed() >= FLUSH_INTERVAL // time trigger
    }

    // -- Adaptive level selection -----------------------------
    // CPU remaining < 30% → level 1 (fastest, ~0.2 µs/KB)
    // BW remaining  < 15% → level 9 (max ratio, ~4.0 µs/KB)
    // BW remaining  < 40% → level 6 (balanced, ~1.2 µs/KB)
    // otherwise           → level 3 (default,  ~0.5 µs/KB)
    fn select_level(&self, budget: &BudgetSnapshot) -> i32 {
        let cpu_remaining = budget.remaining[CPU] / budget.total[CPU].max(1.0);
        let bw_remaining = budget.remaining[BW] / budget.total[BW].max(1.0);

        if cpu_remaining < 0.30 {
            return LEVEL_FAST; // CPU starved — compress fast
        }
        if bw_remaining < 0.15 {
            return LEVEL_MAX; // BW critical — maximum compression
        }
        if bw_remaining < 0.40 {
            return LEVEL_BALANCED; // BW tight — trade CPU for ratio
        }
        LEVEL_DEFAULT
    }

    pub fn stats(&self) -> BatcherStats {
        BatcherStats {
            queue_depth: self.queue.len(),
            queue_cap: self.queue_cap,
            raw_bytes_pending: self.raw_bytes,
            wire_bytes_pending: self.wire_bytes,
            compression_ratio: self.raw_bytes as f32 / self.wire_bytes.max(1) as f32,
            total_frames_in: self.total_frames_in.load(Ordering::Relaxed),
            total_frames_out: self.total_frames_out.load(Ordering::Relaxed),
            total_flushes: self.total_flushes.load(Ordering::Relaxed),
            total_dropped: self.total_dropped.load(Ordering::Relaxed),
        }
    }
}

// -- DictCompressor — zstd compressor with domain dictionary --
// The dictionary is loaded once at startup and reused.
// Reusing the same Compressor across frames avoids re-initialising
// the zstd context (which allocates ~100KB of internal state).
struct DictCompressor {
    inner: Compressor<'static>,
    level: i32,
    dict_id: u32, // embedded in zstd frame — backend uses this to
                  // select the matching decompressor dictionary
}

impl DictCompressor {
    fn new(level: i32) -> Self {
        // If OLOPA_DICT is empty (test mode), fall back to no dictionary
        if OLOPA_DICT.is_empty() {
            let c = Compressor::new(level).expect("zstd compressor init");
            return Self {
                inner: c,
                level,
                dict_id: 0,
            };
        }

        let compressor =
            Compressor::with_dictionary(level, OLOPA_DICT).expect("zstd dict compressor init");

        // The runtime currently does not ship with a trained dictionary artifact.
        // Keep dict_id at 0 until dictionary plumbing is enabled end-to-end.
        Self {
            inner: compressor,
            level,
            dict_id: 0,
        }
    }

    fn compress(&mut self, src: &[u8]) -> io::Result<Vec<u8>> {
        self.inner.compress(src)
    }

    fn set_level(&mut self, level: i32) {
        // Recreate the compressor with the new level.
        // This re-initialises the zstd context (~1µs) — only done
        // when the level changes, which is at most once per 5s window.
        if OLOPA_DICT.is_empty() {
            self.inner = Compressor::new(level).expect("zstd level change");
        } else {
            self.inner =
                Compressor::with_dictionary(level, OLOPA_DICT).expect("zstd dict level change");
        }
        self.level = level;
    }
}

// -- BatchOutput — what the gRPC sender receives --------------
pub struct BatchOutput {
    pub payload: Bytes, // ready-to-send wire bytes (header + frames)
    pub n_frames: usize,
    pub n_events: usize,
    pub raw_bytes: usize,
    pub wire_bytes: usize,
    pub compression_ratio: f32, // raw/wire — e.g. 4.2x = 76% reduction
}

// -- Decompressor — used by backend and tests ------------------
// Symmetric to DictCompressor. Backend must load identical dict bytes.
pub struct DictDecompressor {
    inner: Decompressor<'static>,
}

impl DictDecompressor {
    pub fn new() -> Self {
        if OLOPA_DICT.is_empty() {
            return Self {
                inner: Decompressor::new().expect("zstd decompressor init"),
            };
        }
        Self {
            inner: Decompressor::with_dictionary(OLOPA_DICT).expect("zstd dict decompressor init"),
        }
    }

    pub fn decompress(&mut self, src: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
        self.inner.decompress(src, capacity)
    }
}

// -- BatchParser — parse a BatchOutput on the backend ---------
// Reads the BatchHeader then iterates over [len][frame] pairs.
pub struct BatchParser<'a> {
    data: &'a [u8],
    cursor: usize,
    pub header: BatchHeader,
}

impl<'a> BatchParser<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ParseError> {
        let hdr_size = std::mem::size_of::<BatchHeader>();
        if data.len() < hdr_size {
            return Err(ParseError::TooShort);
        }

        // SAFETY: we checked length, BatchHeader is repr(C) with no padding issues
        let header: BatchHeader =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const BatchHeader) };

        if &header.magic != b"OLOP" {
            return Err(ParseError::BadMagic);
        }

        Ok(Self {
            data,
            cursor: hdr_size,
            header,
        })
    }

    // Iterate over compressed frame payloads
    pub fn next_frame(&mut self) -> Option<&'a [u8]> {
        if self.cursor + 4 > self.data.len() {
            return None;
        }

        let len =
            u32::from_be_bytes(self.data[self.cursor..self.cursor + 4].try_into().ok()?) as usize;
        self.cursor += 4;

        if self.cursor + len > self.data.len() {
            return None;
        }
        let frame = &self.data[self.cursor..self.cursor + len];
        self.cursor += len;
        Some(frame)
    }
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    BadMagic,
}

// -- PushResult — returned by Batcher::push() -----------------
#[derive(Debug, PartialEq)]
pub enum PushResult {
    Ok,          // enqueued, no flush needed yet
    FlushNeeded, // a trigger fired — caller should call flush()
    QueueFull,   // backpressure — frame was dropped
}

// -- Budget type alias (from mdkp_scheduler.rs) ---------------
// Repeated here to keep this file self-contained.
pub use crate::data::mdkp_scheduler::{BudgetSnapshot, BW, CPU};

#[derive(Debug)]
pub struct BatcherStats {
    pub queue_depth: usize,
    pub queue_cap: usize,
    pub raw_bytes_pending: usize,
    pub wire_bytes_pending: usize,
    pub compression_ratio: f32,
    pub total_frames_in: u64,
    pub total_frames_out: u64,
    pub total_flushes: u64,
    pub total_dropped: u64,
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// -- Tests
#[cfg(test)]
mod tests {
    use super::*;

    fn incompressible_bytes(len: usize, mut seed: u64) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for b in &mut out {
            // xorshift64* for deterministic pseudo-random test data.
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            seed = seed.wrapping_mul(0x2545_F491_4F6C_DD1D);
            *b = (seed & 0xFF) as u8;
        }
        out
    }

    fn default_budget() -> BudgetSnapshot {
        BudgetSnapshot::default_budgets()
    }

    fn tight_bw_budget() -> BudgetSnapshot {
        let mut b = BudgetSnapshot::default_budgets();
        // BW 10% remaining → should select level 9
        b.remaining[BW] = b.total[BW] * 0.10;
        b
    }

    fn tight_cpu_budget() -> BudgetSnapshot {
        let mut b = BudgetSnapshot::default_budgets();
        // CPU 20% remaining → should select level 1
        b.remaining[CPU] = b.total[CPU] * 0.20;
        b
    }

    #[test]
    fn batch_header_size() {
        assert_eq!(std::mem::size_of::<BatchHeader>(), 40);
    }

    #[test]
    fn push_and_flush_roundtrip() {
        let mut batcher = Batcher::new(42, 1024);
        let payload = b"test telemetry event bytes for compression test";

        let result = batcher.push(payload, &default_budget());
        assert_ne!(result, PushResult::QueueFull);

        // Force flush regardless of triggers
        let output = batcher.flush().expect("should produce output");
        assert_eq!(output.n_frames, 1);
        assert_eq!(output.raw_bytes, payload.len());
        assert!(output.wire_bytes > 0);
        assert!(output.wire_bytes <= output.raw_bytes + 100); // header overhead
    }

    #[test]
    fn header_magic_is_correct() {
        let mut batcher = Batcher::new(1, 1024);
        batcher.push(b"hello", &default_budget());
        let output = batcher.flush().unwrap();

        // First 4 bytes of payload should be magic "OLOP"
        assert_eq!(&output.payload[..4], b"OLOP");
    }

    #[test]
    fn frame_count_trigger() {
        let mut batcher = Batcher::new(1, MAX_FRAME_COUNT + 10);
        let payload = b"small frame";

        // Push exactly MAX_FRAME_COUNT frames
        let mut flush_signalled = false;
        for i in 0..MAX_FRAME_COUNT {
            let r = batcher.push(payload, &default_budget());
            if r == PushResult::FlushNeeded {
                flush_signalled = true;
                break;
            }
        }
        assert!(
            flush_signalled,
            "count trigger should fire at MAX_FRAME_COUNT"
        );
    }

    #[test]
    fn size_trigger_fires_on_large_payload() {
        let mut batcher = Batcher::new(1, 1024);
        // Push incompressible chunks until compressed bytes cross threshold.
        let mut flush_signalled = false;
        for i in 0..512u64 {
            let chunk = incompressible_bytes(32 * 1024, i + 1);
            let r = batcher.push(&chunk, &default_budget());
            if r == PushResult::FlushNeeded {
                flush_signalled = true;
                break;
            }
        }
        assert!(flush_signalled, "size trigger should fire");
    }

    #[test]
    fn level_selection_by_budget() {
        let batcher = Batcher::new(1, 1024);

        // CPU starved → level 1
        assert_eq!(batcher.select_level(&tight_cpu_budget()), LEVEL_FAST);

        // BW critical → level 9
        assert_eq!(batcher.select_level(&tight_bw_budget()), LEVEL_MAX);

        // Normal → level 3
        assert_eq!(batcher.select_level(&default_budget()), LEVEL_DEFAULT);
    }

    #[test]
    fn queue_full_drops_frames() {
        let mut batcher = Batcher::new(1, 2); // cap of 2
        let payload = b"event";

        batcher.push(payload, &default_budget());
        batcher.push(payload, &default_budget());

        // Third push should be dropped
        let r = batcher.push(payload, &default_budget());
        assert_eq!(r, PushResult::QueueFull);
        assert_eq!(batcher.total_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn empty_flush_returns_none() {
        let mut batcher = Batcher::new(1, 1024);
        assert!(batcher.flush().is_none());
    }

    #[test]
    fn batch_parser_reads_frames() {
        let mut batcher = Batcher::new(99, 1024);
        let payload1 = b"frame one payload data";
        let payload2 = b"frame two payload data";

        batcher.push(payload1, &default_budget());
        batcher.push(payload2, &default_budget());

        let output = batcher.flush().unwrap();
        assert_eq!(output.n_frames, 2);

        // Parse the batch back
        let mut parser = BatchParser::new(&output.payload).unwrap();
        assert_eq!(parser.header.frame_count, 2);
        assert_eq!(parser.header.agent_id, 99);
        assert_eq!(&parser.header.magic, b"OLOP");

        let f1 = parser.next_frame().expect("frame 1");
        let f2 = parser.next_frame().expect("frame 2");
        assert!(f1.len() > 0);
        assert!(f2.len() > 0);
        assert!(parser.next_frame().is_none()); // no more frames
    }

    #[test]
    fn stats_track_correctly() {
        let mut batcher = Batcher::new(1, 1024);
        let payload = b"some event data";

        batcher.push(payload, &default_budget());
        batcher.push(payload, &default_budget());
        let _ = batcher.flush();

        let s = batcher.stats();
        assert_eq!(s.total_flushes, 1);
        assert_eq!(s.queue_depth, 0); // cleared after flush
        assert_eq!(s.raw_bytes_pending, 0);
    }
}
