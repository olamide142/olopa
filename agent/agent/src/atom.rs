//! Shared "atom" event type that rule evaluation consumes.
//!
//! Why this exists:
//! - `HotEvent` in event_store is intentionally tiny for scan speed.
//! - Rules often need more context than hot store carries.
//! - `OlopaEvent` is the richer canonical packet for rule engines.
//!
//! ABI note:
//! - This struct may cross dynamic boundaries (e.g. compiled rule modules).
//! - `#[repr(C)]` keeps field layout deterministic.

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OlopaEvent {
    // --- Hot-path fields ---
    // Keep first 16 bytes aligned with HotEvent layout for easy projection.
    pub ts_ns:        u64,   // 8
    pub pid:          u32,   // 4
    pub risk_score:   f32,   // 4
    // --- Rule context fields ---
    // Parent process vertex id (or parent-like lineage id in current bootstrap).
    pub ppid:         u32,   // 4 — parent PID vertex_id
    // Effective user id observed at event emission.
    pub uid:          u32,   // 4 — effective UID
    // Process name represented as integer symbol id.
    pub comm_id:      u32,   // 4 — process name as integer
    // Source vertex in graph model (process/file/net node id space).
    pub vertex_id:    u32,   // 4 — pre-tagged by XDP: O(1) graph lookup
    // Event family discriminator (Exec/Net/File/Tool/etc).
    pub event_type:   u8,    // 1 — Exec/Net/File/Tool
    // Explicit padding to keep layout stable and avoid compiler-inserted padding surprises.
    pub _pad:         [u8;3],// 3
}
