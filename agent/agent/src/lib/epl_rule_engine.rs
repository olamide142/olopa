// ============================================================
// OLOPA — EPL Compiled Rule Engine
// ============================================================
// Security rules are compiled to native .so files at deploy time.
// At runtime the engine dlopen()s each .so and calls the exported
// function pointer directly — no query parsing, no interpreter,
// no allocations on the hot path.
//
// Pipeline:
//   Rule DSL (YAML) → rustc → .so → dlopen → fn ptr in RuleEngine
//   Hot path: rule_fn(&event, &graph_snapshot) → Option<Alert>
//   Cost per rule: ~15 ns  (2 array reads + branch)
//   Output buffer: ArrayVec<Alert, 8>  (stack-allocated, zero heap)
//
// Each .so exports exactly one symbol:
//   #[no_mangle] pub extern "C" fn evaluate(
//       event: &OlopaEvent,
//       graph: &CsrSnapshot,
//   ) -> u8    // 0 = no alert, 1 = alert written to out_ptr
//
// The engine calls all loaded rules in a tight loop.
// First match wins and short-circuits (configurable).
// ============================================================

use std::path::{Path, PathBuf};
use std::sync::Arc;
use arrayvec::ArrayVec;
use libloading::{Library, Symbol};
use ulib::OlopaEvent;

// Re-use types from the other modules
use crate::csr_graph::{CsrSnapshot, NodeLabel, EdgeKind};
use crate::event_store::HotEvent;


// Total: 36 bytes — fits one cache line.
const _: () = assert!(std::mem::size_of::<OlopaEvent>() == 36);

// ── Alert — output of a fired rule ──────────────────────────
// repr(C): written by rule .so, read by engine. ABI must match.
// 48 bytes — fits in one cache line with a few bytes spare.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Alert {
    pub ts_ns:      u64,       // 8 — when the alert fired
    pub confidence: f32,       // 4 — 0.0–1.0
    pub risk_score: f32,       // 4 — composite risk
    pub pid:        u32,       // 4 — offending process
    pub vertex_id:  u32,       // 4 — graph node of offending process
    pub rule_id:    u32,       // 4 — which rule fired
    pub severity:   Severity,  // 1
    pub attack_cls: AttackClass, // 1
    pub _pad:       [u8; 2],   // 2
    pub ttp:        [u8; 8],   // 8 — "T1059\0\0\0" fixed-width ASCII
    pub engines:    EngineFlags, // 1 — which detection engines fired
    pub _pad2:      [u8; 7],   // 7 — bring to 48 bytes
}
const _: () = assert!(std::mem::size_of::<Alert>() == 48);

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Severity {
    Low      = 0,
    Medium   = 1,
    High     = 2,
    Critical = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AttackClass {
    Unknown          = 0,
    Webshell         = 1,
    LateralMovement  = 2,
    SecretExfil      = 3,
    PrivEscalation   = 4,
    DnsTunneling     = 5,
    AgenticExfil     = 6,
    DataExfil        = 7,
    PromptInjection  = 8,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub struct EngineFlags(pub u8);
impl EngineFlags {
    pub const CYPHER:      u8 = 0b0001;
    pub const GNN:         u8 = 0b0010;
    pub const CLICKHOUSE:  u8 = 0b0100;
    pub const EPL:         u8 = 0b1000;
}

// ── The rule function pointer type ──────────────────────────
// This is the ABI contract between engine and every .so.
// Rule returns 1 if an alert was written to `out`, 0 otherwise.
// Using *mut Alert (raw pointer) keeps the ABI C-compatible
// across the dlopen boundary.
type RuleFn = unsafe extern "C" fn(
    event: *const OlopaEvent,
    graph: *const CsrSnapshot,
    out:   *mut   Alert,
) -> u8;

// ── LoadedRule — one dlopen'd .so ───────────────────────────
struct LoadedRule {
    _lib:    Library,       // keeps the .so mapped — must outlive fn ptr
    func:    RuleFn,
    rule_id: u32,
    name:    String,        // for logging only
    path:    PathBuf,
}

// ── RuleEngine — owns all loaded rules ──────────────────────
// Constructed once at startup, rules can be hot-reloaded.
// The evaluate() method is the only hot-path entry point.
pub struct RuleEngine {
    rules: Vec<LoadedRule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::with_capacity(32) }
    }

    // ── Load a compiled rule .so ─────────────────────────────
    // Called at startup for each .so in the rules directory,
    // and again when a new rule is deployed (hot-reload).
    pub fn load(&mut self, path: &Path, rule_id: u32) -> Result<(), RuleError> {
        // SAFETY: We are loading a .so that was compiled by our own
        // build pipeline. The RuleFn ABI is enforced by the shared
        // type definitions in this crate (OlopaEvent, Alert are repr(C)).
        // A malformed .so would be a supply-chain attack — mitigated by
        // signed rule packages verified before loading (see security model).
        let lib: Library = unsafe { Library::new(path)? };

        // Look up the single exported symbol "evaluate"
        let func: RuleFn = unsafe {
            let sym: Symbol<RuleFn> = lib.get(b"evaluate\0")?;
            *sym  // copy the fn pointer out so it is 'static relative to lib
        };

        self.rules.push(LoadedRule {
            _lib:    lib,
            func,
            rule_id,
            name:    path.file_stem()
                         .unwrap_or_default()
                         .to_string_lossy()
                         .into_owned(),
            path:    path.to_path_buf(),
        });

        Ok(())
    }

    // ── Unload a rule by rule_id (for hot-swap) ──────────────
    pub fn unload(&mut self, rule_id: u32) {
        self.rules.retain(|r| r.rule_id != rule_id);
        // LoadedRule::drop() will dlclose() the library automatically
    }

    // ── HOT PATH: evaluate all rules against one event ───────
    // Cost: ~15 ns per rule (2 array reads + branch, no alloc).
    // Output buffer is an ArrayVec<Alert, 8> on the caller's stack.
    // Capacity of 8: in practice ≤2 rules fire per event.
    // If somehow 8+ fire, further alerts are silently dropped —
    // the first match is highest confidence anyway.
    //
    // `mode` controls short-circuit behaviour:
    //   FirstMatch  — return after first firing rule (default, fastest)
    //   AllMatches  — collect all firing rules (audit / investigation mode)
    #[inline(always)]
    pub fn evaluate(
        &self,
        event:    &OlopaEvent,
        graph:    &CsrSnapshot,
        out:      &mut ArrayVec<Alert, 8>,
        mode:     EvalMode,
    ) {
        for rule in &self.rules {
            // Stack-allocate a zeroed Alert for the rule to write into.
            // If the rule returns 0 (no alert), we discard it.
            // If it returns 1, we push it into the ArrayVec.
            // No heap allocation in either path.
            let mut alert = std::mem::zeroed::<Alert>();

            // SAFETY: rule was loaded from a trusted signed .so.
            // event and graph are valid for the duration of this call.
            let fired = unsafe {
                (rule.func)(
                    event as *const _,
                    graph as *const _,
                    &mut alert as *mut _,
                )
            };

            if fired == 1 {
                alert.rule_id  = rule.rule_id;
                alert.engines  = EngineFlags(EngineFlags::EPL);
                if out.try_push(alert).is_err() {
                    // ArrayVec is full (8 alerts). This should never happen
                    // in normal operation. Log and break.
                    break;
                }
                if mode == EvalMode::FirstMatch {
                    return;
                }
            }
        }
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }

    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name.as_str()).collect()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum EvalMode {
    FirstMatch, // default: fastest, short-circuits on first alert
    AllMatches, // audit mode: collects every firing rule
}

// ── Error type ───────────────────────────────────────────────
#[derive(Debug)]
pub enum RuleError {
    Load(libloading::Error),
    SymbolNotFound(libloading::Error),
}
impl From<libloading::Error> for RuleError {
    fn from(e: libloading::Error) -> Self { RuleError::Load(e) }
}
impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::Load(e)            => write!(f, "dlopen failed: {e}"),
            RuleError::SymbolNotFound(e)  => write!(f, "symbol 'evaluate' not found: {e}"),
        }
    }
}

// ============================================================
// COMPILED RULES — each lives in its own .so
// The examples below show what the compiler emits from the DSL.
// In production these are separate crates built with:
//   cargo build --release --lib  →  target/release/libwebshell_detect.so
// ============================================================

// ── Rule: webshell reverse shell (T1059) ─────────────────────
// Fires when: current process is a shell AND its parent (in the
// graph) is a web server AND there is an external neighbor.
// Cost: 2 graph array reads + 2 set lookups = ~15 ns.
//
// In a real .so this is the only function in the file.
// Shown inline here for documentation purposes.
pub mod rule_webshell {
    use super::*;

    // Known comm_ids for web servers and shells.
    // These integer IDs are assigned by the eBPF global_id_map at
    // agent startup from the /etc/olopa/comm_ids.toml config file.
    // Using static sets means the check is a single integer compare,
    // not a string comparison.
    const WEBSERVER_IDS: &[u32] = &[1, 2, 3, 4, 5, 6]; // nginx,apache,httpd,gunicorn,uvicorn,caddy
    const SHELL_IDS:     &[u32] = &[10, 11, 12, 13, 14, 15]; // bash,sh,zsh,python3,perl,ruby

    // This function IS the .so export in production.
    // ABI: C-compatible, no_mangle, no panics, no allocations.
    // The compiler can inline and optimize this aggressively because
    // there are no virtual calls and all data is in registers/cache.
    #[no_mangle]
    pub unsafe extern "C" fn evaluate(
        event: *const OlopaEvent,
        graph: *const CsrSnapshot,
        out:   *mut   Alert,
    ) -> u8 {
        let event = &*event;
        let graph = &*graph;

        // ── Gate 1: is this a shell process? (~1 ns) ─────────
        // Linear scan over a small static slice — likely in L1.
        if !SHELL_IDS.contains(&event.comm_id) {
            return 0; // fast exit — not a shell, nothing to check
        }

        // ── Gate 2: is the parent a web server? (~4 ns) ──────
        // graph.node(ppid_vertex) = one array index read.
        let parent = graph.node(event.ppid);
        if !WEBSERVER_IDS.contains(&parent.comm_id()) {
            return 0;
        }

        // ── Gate 3: does this process have an external neighbor? (~10 ns)
        // neighbors() = two array reads (offsets) + slice construction.
        // external check = iterate neighbor node_props, check is_internal flag.
        let has_external = graph.neighbors(event.vertex_id)
            .iter()
            .any(|&n| {
                let p = graph.node(n);
                p.label == NodeLabel::NetworkEndpoint && !p.is_internal
            });

        if !has_external {
            return 0;
        }

        // ── All gates passed — write alert ───────────────────
        let alert = &mut *out;
        alert.ts_ns      = event.ts_ns;
        alert.confidence = 0.92;
        alert.risk_score = event.risk_score.max(0.85); // at least 0.85
        alert.pid        = event.pid;
        alert.vertex_id  = event.vertex_id;
        alert.severity   = Severity::Critical;
        alert.attack_cls = AttackClass::Webshell;
        // "T1059\0\0\0" packed into 8 bytes
        alert.ttp = *b"T1059\0\0\0";
        1 // fired
    }
}

// ── Rule: privilege escalation + network (T1548) ─────────────
// Fires when: uid == 0 AND parent uid > 1000 (non-root parent)
// AND there is an external neighbor (post-escalation egress).
pub mod rule_priv_esc {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn evaluate(
        event: *const OlopaEvent,
        graph: *const CsrSnapshot,
        out:   *mut   Alert,
    ) -> u8 {
        let event = &*event;
        let graph = &*graph;

        // ── Gate 1: running as root? ──────────────────────────
        if event.uid != 0 { return 0; }

        // ── Gate 2: parent was non-root? ─────────────────────
        let parent = graph.node(event.ppid);
        if parent.uid() <= 1000 { return 0; } // parent was root or system

        // ── Gate 3: external neighbor within 30s ─────────────
        let has_recent_external = graph.neighbors(event.vertex_id)
            .iter()
            .zip(graph.neighbor_props(event.vertex_id).iter())
            .any(|(&n, props)| {
                let node = graph.node(n);
                node.label == NodeLabel::NetworkEndpoint
                    && !node.is_internal
                    && props.ts_ns > event.ts_ns.saturating_sub(30_000_000_000) // 30s
            });

        if !has_recent_external { return 0; }

        let alert = &mut *out;
        alert.ts_ns      = event.ts_ns;
        alert.confidence = 0.88;
        alert.risk_score = 0.9;
        alert.pid        = event.pid;
        alert.vertex_id  = event.vertex_id;
        alert.severity   = Severity::High;
        alert.attack_cls = AttackClass::PrivEscalation;
        alert.ttp        = *b"T1548\0\0\0";
        1
    }
}

// ── Rule: canary node access ──────────────────────────────────
// Zero false positives. Any edge to a canary node = attacker.
// No gates needed — one array lookup.
pub mod rule_canary {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn evaluate(
        event: *const OlopaEvent,
        graph: *const CsrSnapshot,
        out:   *mut   Alert,
    ) -> u8 {
        let event = &*event;
        let graph = &*graph;

        // Check all neighbors of this process for canary nodes
        let touched_canary = graph.neighbors(event.vertex_id)
            .iter()
            .any(|&n| graph.is_canary(n));

        if !touched_canary { return 0; }

        let alert = &mut *out;
        alert.ts_ns      = event.ts_ns;
        alert.confidence = 1.0; // zero false positives by definition
        alert.risk_score = 1.0;
        alert.pid        = event.pid;
        alert.vertex_id  = event.vertex_id;
        alert.severity   = Severity::Critical;
        alert.attack_cls = AttackClass::Unknown; // canary fires before class known
        alert.ttp        = *b"CANARY\0\0";
        1
    }
}

// ── Rule: data exfiltration chain (T1567) ────────────────────
// Fires when: process has read a sensitive file AND connected
// to an external endpoint in the same session window.
// Uses edge timestamps to enforce ordering: read BEFORE connect.
pub mod rule_data_exfil {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn evaluate(
        event: *const OlopaEvent,
        graph: *const CsrSnapshot,
        out:   *mut   Alert,
    ) -> u8 {
        let event = &*event;
        let graph = &*graph;

        // Only care about network connect events
        if event.event_type != 3 { return 0; } // 3 = Net event

        let neighbors  = graph.neighbors(event.vertex_id);
        let edge_props = graph.neighbor_props(event.vertex_id);

        let mut read_sensitive_ts: Option<u64> = None;
        let mut has_external_connect            = false;
        let mut external_risk                   = 0.0f32;

        for (i, &n) in neighbors.iter().enumerate() {
            let node = graph.node(n);
            let prop = &edge_props[i];

            match node.label {
                NodeLabel::File | NodeLabel::Secret => {
                    if prop.kind == EdgeKind::ReadFile || prop.kind == EdgeKind::AccessedSecret {
                        if node.sensitivity() > 0 {
                            // Track earliest sensitive read timestamp
                            read_sensitive_ts = Some(match read_sensitive_ts {
                                Some(t) => t.min(prop.ts_ns),
                                None    => prop.ts_ns,
                            });
                        }
                    }
                }
                NodeLabel::NetworkEndpoint => {
                    if !node.is_internal && prop.kind == EdgeKind::ConnectedTo {
                        has_external_connect = true;
                        external_risk = node.risk_score;
                    }
                }
                _ => {}
            }
        }

        // Only fire if: read sensitive data BEFORE connecting externally
        let read_before_connect = match read_sensitive_ts {
            Some(read_ts) => {
                // Find external connect timestamp from current event ts_ns
                // (this is the connect event triggering the rule)
                read_ts < event.ts_ns
            }
            None => false,
        };

        if !has_external_connect || !read_before_connect { return 0; }

        let confidence = 0.75 + (external_risk * 0.20); // higher threat intel → higher conf
        let alert = &mut *out;
        alert.ts_ns      = event.ts_ns;
        alert.confidence = confidence.min(0.99);
        alert.risk_score = (event.risk_score + external_risk) / 2.0;
        alert.pid        = event.pid;
        alert.vertex_id  = event.vertex_id;
        alert.severity   = if confidence > 0.85 { Severity::Critical } else { Severity::High };
        alert.attack_cls = AttackClass::DataExfil;
        alert.ttp        = *b"T1567\0\0\0";
        1
    }
}

// ── Tests ─────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pid: u32, ppid: u32, uid: u32, comm_id: u32, vertex_id: u32) -> OlopaEvent {
        OlopaEvent {
            ts_ns: 1_000_000_000,
            pid, ppid: ppid, uid, comm_id, vertex_id,
            risk_score: 0.5,
            event_type: 0,
            _pad: [0; 3],
        }
    }

    #[test]
    fn alert_size_is_correct() {
        assert_eq!(std::mem::size_of::<Alert>(), 48);
    }

    #[test]
    fn event_size_is_correct() {
        assert_eq!(std::mem::size_of::<OlopaEvent>(), 36);
    }

    #[test]
    fn arrayvec_is_stack_allocated() {
        // ArrayVec<Alert, 8> must not heap-allocate.
        // 8 × 48 bytes = 384 bytes on the stack — well within limits.
        let buf: ArrayVec<Alert, 8> = ArrayVec::new();
        assert_eq!(buf.capacity(), 8);
        assert_eq!(std::mem::size_of::<ArrayVec<Alert, 8>>(),
                   8 * std::mem::size_of::<Alert>() + std::mem::size_of::<usize>());
    }

    #[test]
    fn webshell_rule_fires_on_shell_child_of_webserver() {
        // Build a minimal CsrSnapshot: nginx(0) → bash(1) → ext_ip(2)
        // nginx comm_id=1 (WEBSERVER_IDS[0]), bash comm_id=10 (SHELL_IDS[0])
        use crate::csr_graph::*;

        let node_props = vec![
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.1, page_rank:0.0,
                label:NodeLabel::Process, is_internal:true, is_canary:false,
                community_id:0, _pad:[0;4] }, // 0 nginx
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.8, page_rank:0.0,
                label:NodeLabel::Process, is_internal:true, is_canary:false,
                community_id:0, _pad:[0;4] }, // 1 bash
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.9, page_rank:0.0,
                label:NodeLabel::NetworkEndpoint, is_internal:false, is_canary:false,
                community_id:0, _pad:[0;4] }, // 2 ext_ip
        ];
        let offsets    = vec![0u32, 0, 1, 1]; // nginx: no out-edges; bash→ext_ip
        let adjacency  = vec![2u32];
        let edge_props = vec![EdgeProps {
            ts_ns:1000, kind:EdgeKind::ConnectedTo, causal:true,
            risk_weight:80, _pad:0, bytes:0,
        }];
        let graph = CsrSnapshot {
            offsets, adjacency, edge_props, node_props,
            num_nodes:3, num_edges:1,
        };

        // bash (comm_id=10) with parent nginx (vertex 0, comm_id=1)
        let event = make_event(4821, 0, 33, 10, 1); // vertex_id=1 = bash

        let mut out = std::mem::zeroed::<Alert>();
        let fired = unsafe {
            rule_webshell::evaluate(&event as *const _, &graph as *const _, &mut out)
        };
        assert_eq!(fired, 1, "webshell rule should fire");
        assert_eq!(out.attack_cls, AttackClass::Webshell);
        assert_eq!(out.severity,   Severity::Critical);
        assert_eq!(&out.ttp, b"T1059\0\0\0");
    }

    #[test]
    fn webshell_rule_silent_for_benign_worker() {
        use crate::csr_graph::*;

        // nginx → worker (comm_id=99, not in SHELL_IDS) → internal CDN
        let node_props = vec![
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.0, page_rank:0.0,
                label:NodeLabel::Process, is_internal:true, is_canary:false,
                community_id:0, _pad:[0;4] }, // 0 nginx
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.0, page_rank:0.0,
                label:NodeLabel::Process, is_internal:true, is_canary:false,
                community_id:0, _pad:[0;4] }, // 1 worker
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.0, page_rank:0.0,
                label:NodeLabel::NetworkEndpoint, is_internal:true, is_canary:false, // INTERNAL cdn
                community_id:0, _pad:[0;4] }, // 2 cdn
        ];
        let offsets    = vec![0u32, 0, 1, 1];
        let adjacency  = vec![2u32];
        let edge_props = vec![EdgeProps {
            ts_ns:1000, kind:EdgeKind::ConnectedTo, causal:true,
            risk_weight:0, _pad:0, bytes:0,
        }];
        let graph = CsrSnapshot {
            offsets, adjacency, edge_props, node_props,
            num_nodes:3, num_edges:1,
        };

        let event = make_event(9999, 0, 33, 99, 1); // comm_id=99 not a shell
        let mut out = std::mem::zeroed::<Alert>();
        let fired = unsafe {
            rule_webshell::evaluate(&event as *const _, &graph as *const _, &mut out)
        };
        assert_eq!(fired, 0, "benign worker should not fire webshell rule");
    }

    #[test]
    fn canary_rule_always_fires_at_full_confidence() {
        use crate::csr_graph::*;

        let node_props = vec![
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.0, page_rank:0.0,
                label:NodeLabel::Process, is_internal:true, is_canary:false,
                community_id:0, _pad:[0;4] }, // 0 attacker process
            NodeProps { first_seen_ns:0, last_seen_ns:0, risk_score:0.0, page_rank:0.0,
                label:NodeLabel::Secret, is_internal:true, is_canary:true, // CANARY
                community_id:0, _pad:[0;4] }, // 1 canary secret
        ];
        let offsets    = vec![0u32, 1, 1];
        let adjacency  = vec![1u32]; // process → canary secret
        let edge_props = vec![EdgeProps {
            ts_ns:1000, kind:EdgeKind::AccessedSecret, causal:true,
            risk_weight:100, _pad:0, bytes:0,
        }];
        let graph = CsrSnapshot {
            offsets, adjacency, edge_props, node_props,
            num_nodes:2, num_edges:1,
        };

        let event = make_event(666, 1, 0, 10, 0); // attacker at vertex 0
        let mut out = std::mem::zeroed::<Alert>();
        let fired = unsafe {
            rule_canary::evaluate(&event as *const _, &graph as *const _, &mut out)
        };
        assert_eq!(fired, 1);
        assert!((out.confidence - 1.0).abs() < f32::EPSILON);
        assert!((out.risk_score  - 1.0).abs() < f32::EPSILON);
    }
}