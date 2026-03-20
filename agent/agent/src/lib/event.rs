mod ulib;


// ── OlopaEvent — the full event passed to rules ──────────────
// Superset of HotEvent. Contains everything a rule might need.
// repr(C) so layout is stable across the .so boundary.
// Rules receive a *reference* — zero copy.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OlopaEvent {
    // ── hot fields (match HotEvent layout exactly) ───────────
    pub ts_ns:        u64,   // 8
    pub pid:          u32,   // 4
    pub risk_score:   f32,   // 4
    // ── additional context for rule evaluation ───────────────
    pub ppid:         u32,   // 4 — parent PID vertex_id
    pub uid:          u32,   // 4 — effective UID
    pub comm_id:      u32,   // 4 — process name as integer
    pub vertex_id:    u32,   // 4 — pre-tagged by XDP: O(1) graph lookup
    pub event_type:   u8,    // 1 — Exec/Net/File/Tool
    pub _pad:         [u8;3],// 3
}