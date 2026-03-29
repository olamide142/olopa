// ============================================================
// OLOPA — CsrGraph (Compressed Sparse Row)
// ============================================================
// Three contiguous flat arrays. No pointers. No heap per node.
// Hardware prefetcher reads ahead automatically.
// ~10 ns/hop vs ~100 ns/hop for pointer-chasing graph DBs.
//
// Layout recap:
//   offsets[v]   ..offsets[v+1]  = range into adjacency[] for node v
//   adjacency[k]                 = neighbor node ID at position k
//   edge_props[k]                = edge metadata at position k (parallel to adjacency)
//   node_props[v]                = node metadata at index v
//
// All four arrays are indexed by the same integer IDs that XDP
// pre-tags onto every packet. Graph lookup = one array read. O(1).
// ============================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use crossbeam_utils::CachePadded;
use log::warn;

// -- Compile-time size guards 
const _: () = assert!(std::mem::size_of::<NodeProps>()  == 32);
const _: () = assert!(std::mem::size_of::<EdgeProps>()  == 16);

// -- Node types (matches graph data model)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NodeLabel {
    Process         = 0,
    File            = 1,
    NetworkEndpoint = 2,
    User            = 3,
    Host            = 4,
    Secret          = 5,
    AgentSession    = 6,
    ToolCall        = 7,
    Container       = 8,
    DomainName      = 9,
}

// -- Edge types 
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EdgeKind {
    Spawned         = 0,
    ReadFile        = 1,
    WroteFile       = 2,
    ConnectedTo     = 3,
    AccessedSecret  = 4,
    LateralMove     = 5,
    RanAs           = 6,
    DataFlow        = 7,
    CalledTool      = 8,
    ResolvedDns     = 9,
    ExecIn          = 10,
    HasProcess      = 11,
}

// -- NodeProps — 32 bytes, one per node
// Packed: largest fields first, no wasted padding.
// Fits in half a cache line; two nodes per cache line.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NodeProps {
    pub first_seen_ns:    u64,   // 8 — when this node was first observed
    pub last_seen_ns:     u64,   // 8 — most recent event touching this node
    pub risk_score:       f32,   // 4 — updated by graph sync service
    pub page_rank:        f32,   // 4 — updated by scheduled GDS/MAGE run
    pub label:            NodeLabel, // 1 — Process / File / NetworkEndpoint / …
    pub is_internal:      bool,  // 1 — false = external IP/domain
    pub is_canary:        bool,  // 1 — true = zero-FP honeypot node
    pub community_id:     u8,   // 1 — Louvain community (8-bit bucket)
    pub _pad:             [u8; 4], // explicit — brings total to 32 bytes
}

// -- EdgeProps — 16 bytes, one per directed edge 
// Parallel to adjacency[]. adjacency[k] = dst node, edge_props[k] = metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EdgeProps {
    pub ts_ns:       u64,   // 8 — nanosecond timestamp of this edge write
    pub kind:        EdgeKind, // 1 — SPAWNED / CONNECTED_TO / …
    pub causal:      bool,  // 1 — true = direct syscall causation (provenance)
    pub risk_weight: u8,    // 1 — 0–255 scaled edge risk for Dijkstra
    pub _pad:        u8,    // 1 — align to 8
    pub bytes:       u32,   // 4 — bytes transferred (net/file edges)
}
// Total: 16 bytes. Adjacency + EdgeProps fit in 8 bytes + 16 bytes = 24 bytes
// per edge. Dense graphs stay comfortably in L3.

// -- The immutable CSR snapshot 
// Built once from accumulated deltas, then swapped in atomically.
// Readers hold an Arc<CsrSnapshot> — they are never blocked.
// The writer builds a new snapshot, swaps the Arc, and the old
// one is dropped when the last reader releases it (RCU pattern).
pub struct CsrSnapshot {
    // Core CSR arrays — never mutated after construction
    pub offsets:    Vec<u32>,       // len = num_nodes + 1
    pub adjacency:  Vec<u32>,       // len = num_edges
    pub edge_props: Vec<EdgeProps>, // len = num_edges (parallel to adjacency)
    pub node_props: Vec<NodeProps>, // len = num_nodes
    pub num_nodes:  u32,
    pub num_edges:  u32,
}

impl CsrSnapshot {
    // -- Core access: neighbors of node v 
    // Returns a slice of neighbor node IDs.
    // Cost: two array reads (offsets) + one slice construction.
    // All data is contiguous — hardware prefetcher reads ahead.
    #[inline(always)]
    pub fn neighbors(&self, v: u32) -> &[u32] {
        let v: usize = v as usize;
        debug_assert!(v < self.num_nodes as usize);
        let start: usize = self.offsets[v]     as usize;
        let end: usize   = self.offsets[v + 1] as usize;
        &self.adjacency[start..end]
    }

    // -- Edge props for neighbors of node v 
    // Parallel slice to neighbors(). Same start/end offsets.
    #[inline(always)]
    pub fn neighbor_props(&self, v: u32) -> &[EdgeProps] {
        let v: usize = v as usize;
        let start: usize = self.offsets[v]     as usize;
        let end: usize   = self.offsets[v + 1] as usize;
        &self.edge_props[start..end]
    }

    // -- Node props for a single node 
    // Direct array index — O(1), no search.
    // XDP pre-tags each packet with vertex_id so this is always
    // a known index, never a lookup.
    #[inline(always)]
    pub fn node(&self, v: u32) -> &NodeProps {
        debug_assert!((v as usize) < self.node_props.len());
        &self.node_props[v as usize]
    }

    // -- Degree of node v
    #[inline(always)]
    pub fn degree(&self, v: u32) -> u32 {
        let v = v as usize;
        self.offsets[v + 1] - self.offsets[v]
    }

    // -- Find a specific edge (src → dst)
    // Linear scan over adjacency slice for src — typically small.
    // For hot-path use, prefer maintaining a reverse index map.
    pub fn find_edge(&self, src: u32, dst: u32) -> Option<&EdgeProps> {
        let neighbors  = self.neighbors(src);
        let props      = self.neighbor_props(src);
        neighbors.iter().position(|&n| n == dst)
                 .map(|i| &props[i])
    }

    // -- BFS from a start node (bounded depth) 
    // Used by subgraph extractor for GNN inference.
    // Returns (node_id, depth) pairs within max_depth hops.
    // Pre-allocated buffers — no Vec::new() on the hot path.
    pub fn bfs(&self, start: u32, max_depth: u8) -> Vec<(u32, u8)> {
        let mut visited = vec![false; self.num_nodes as usize];
        let mut queue   = std::collections::VecDeque::with_capacity(256);
        let mut result  = Vec::with_capacity(256);

        visited[start as usize] = true;
        queue.push_back((start, 0u8));

        while let Some((v, depth)) = queue.pop_front() {
            result.push((v, depth));
            if depth >= max_depth { continue; }
            for &neighbor in self.neighbors(v) {
                if !visited[neighbor as usize] {
                    visited[neighbor as usize] = true;
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
        result
    }

    // -- k-hop subgraph extraction 
    // Used by GNN inference service: pull k-hop neighborhood
    // around a trigger node and convert to PyG Data object.
    // Returns (nodes, edges) as parallel vecs.
    pub fn k_hop_subgraph(
        &self,
        trigger: u32,
        k: u8,
    ) -> (Vec<u32>, Vec<(u32, u32, EdgeProps)>) {
        let reachable = self.bfs(trigger, k);
        let node_set: std::collections::HashSet<u32> =
            reachable.iter().map(|(v, _)| *v).collect();

        let nodes: Vec<u32> = reachable.into_iter().map(|(v, _)| v).collect();

        let mut edges = Vec::new();
        for &src in &nodes {
            for (i, &dst) in self.neighbors(src).iter().enumerate() {
                if node_set.contains(&dst) {
                    edges.push((src, dst, self.neighbor_props(src)[i]));
                }
            }
        }
        (nodes, edges)
    }

    // -- Canary check 
    // Any edge written to a canary node = zero-FP CRITICAL alert.
    // Called by event-driven trigger on every graph write.
    #[inline(always)]
    pub fn is_canary(&self, v: u32) -> bool {
        self.node_props
            .get(v as usize)
            .map_or(false, |n| n.is_canary)
    }

    // -- Find external neighbors 
    // Returns node IDs of NetworkEndpoint neighbors that are external.
    // Used by kill-chain detection: process connected to external IP?
    pub fn external_neighbors(&self, v: u32) -> Vec<u32> {
        self.neighbors(v)
            .iter()
            .copied()
            .filter(|&n| {
                let props = self.node(n);
                props.label == NodeLabel::NetworkEndpoint && !props.is_internal
            })
            .collect()
    }
}

// -- Delta buffer — one per ingest worker thread 
// Hot path writes here. Never touches the shared CsrSnapshot.
// No locking. No contention. One writer per core.
// Drained every 10ms by the merge task.
#[derive(Default)]
pub struct DeltaBuffer {
    pub new_nodes: Vec<(u32, NodeProps)>,            // (vertex_id, props)
    pub new_edges: Vec<(u32, u32, EdgeProps)>,        // (src, dst, props)
    pub risk_updates: Vec<(u32, f32)>,                // (vertex_id, new_risk)
}

impl DeltaBuffer {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            new_nodes:    Vec::with_capacity(n),
            new_edges:    Vec::with_capacity(n * 2),
            risk_updates: Vec::with_capacity(n),
        }
    }

    // -- Hot-path write — called ~15M times/sec per core 
    #[inline(always)]
    pub fn add_edge(&mut self, src: u32, dst: u32, props: EdgeProps) {
        self.new_edges.push((src, dst, props));
    }

    #[inline(always)]
    pub fn add_node(&mut self, id: u32, props: NodeProps) {
        self.new_nodes.push((id, props));
    }

    #[inline(always)]
    pub fn update_risk(&mut self, id: u32, risk: f32) {
        self.risk_updates.push((id, risk));
    }

    pub fn drain(&mut self) -> DeltaBuffer {
        let mut out = DeltaBuffer::with_capacity(self.new_edges.len());
        std::mem::swap(self, &mut out);
        out
    }
}

// -- CsrGraph — the live graph, RCU-protected
// Writers build a new CsrSnapshot from accumulated deltas,
// then atomically swap the Arc pointer.
// Readers call `snapshot()` to get an Arc — they hold it for
// the duration of their traversal. The old snapshot is dropped
// when all readers release their Arc. Zero blocking.
pub struct CsrGraph {
    // Current live snapshot - read by detection workers constantly
    current: Arc<parking_lot::RwLock<Arc<CsrSnapshot>>>,

    // Per-thread delta buffers — written by ingest workers, never shared
    // In production: thread_local! or indexed by core ID
    delta:   parking_lot::Mutex<DeltaBuffer>,

    // Metrics
    merge_count:    CachePadded<AtomicU64>,
    edge_count:     CachePadded<AtomicU64>,
    node_count:     CachePadded<AtomicU64>,
}

impl CsrGraph {
    pub fn new(initial_capacity_nodes: usize, initial_capacity_edges: usize) -> Self {
        let empty = Arc::new(CsrSnapshot {
            offsets:    vec![0u32; initial_capacity_nodes + 1],
            adjacency:  Vec::with_capacity(initial_capacity_edges),
            edge_props: Vec::with_capacity(initial_capacity_edges),
            node_props: vec![
                NodeProps {
                    first_seen_ns: 0, last_seen_ns: 0,
                    risk_score: 0.0, page_rank: 0.0,
                    label: NodeLabel::Process,
                    is_internal: true, is_canary: false,
                    community_id: 0, _pad: [0; 4],
                };
                initial_capacity_nodes
            ],
            num_nodes: initial_capacity_nodes as u32,
            num_edges: 0,
        });

        Self {
            current:     Arc::new(parking_lot::RwLock::new(empty)),
            delta:       parking_lot::Mutex::new(
                             DeltaBuffer::with_capacity(65_536)),
            merge_count: CachePadded::new(AtomicU64::new(0)),
            edge_count:  CachePadded::new(AtomicU64::new(0)),
            node_count:  CachePadded::new(AtomicU64::new(0)),
        }
    }

    // -- Reader: get current snapshot (Arc clone, ~5ns) 
    // Readers hold this Arc for the duration of their traversal.
    // No blocking. No locking on the traversal itself.
    #[inline(always)]
    pub fn snapshot(&self) -> Arc<CsrSnapshot> {
        self.current.read().clone()
    }

    // -- Writer: queue an edge from ingest worker
    // Hot path. Writes to delta buffer only — no shared state.
    // In production, each ingest worker has its own DeltaBuffer
    // (thread_local!). The Mutex here is for illustration.
    #[inline]
    pub fn write_edge(&self, src: u32, dst: u32, props: EdgeProps) {
        self.delta.lock().add_edge(src, dst, props);
        self.edge_count.fetch_add(1, Ordering::Relaxed);
    }

    // -- Merge task: runs every 10ms on a background thread ---
    // Drains all delta buffers, rebuilds CSR arrays, swaps pointer.
    // Readers are never blocked — they hold the old Arc until done.
    pub fn merge_deltas(&self) {
        let delta: DeltaBuffer = self.delta.lock().drain();

        // Get the current snapshot as our base
        let current: Arc<CsrSnapshot> = self.snapshot();

        // Rebuild CSR from current + delta
        // In production: sort edges by src, compute offsets[], fill adjacency[].
        // Simplified here for clarity — production uses radix sort for speed.
        let new_snapshot: Arc<CsrSnapshot> = Arc::new(rebuild_csr(&current, delta));

        // Atomic swap — O(1), no reader is blocked
        *self.current.write() = new_snapshot;
        self.merge_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> CsrStats {
        let snap: Arc<CsrSnapshot> = self.snapshot();
        CsrStats {
            num_nodes:   snap.num_nodes,
            num_edges:   snap.num_edges,
            merge_count: self.merge_count.load(Ordering::Relaxed),
        }
    }
}

// -- CSR rebuild from base + delta
// Production implementation uses a radix sort on (src, dst) pairs.
// The sort brings all edges for the same source together,
// making offsets[] trivial to compute in one linear pass.
fn rebuild_csr(base: &CsrSnapshot, delta: DeltaBuffer) -> CsrSnapshot {
    let num_nodes = base.num_nodes as usize;
    let DeltaBuffer {
        new_nodes,
        new_edges,
        risk_updates,
    } = delta;

    // Merge base edges + delta edges into one sorted edge list
    let mut all_edges: Vec<(u32, u32, EdgeProps)> = Vec::with_capacity(
        base.adjacency.len() + new_edges.len(),
    );
    for src in 0..base.num_nodes {
        let neighbors = base.neighbors(src);
        let props = base.neighbor_props(src);
        for (i, &dst) in neighbors.iter().enumerate() {
            all_edges.push((src, dst, props[i]));
        }
    }
    all_edges.extend(new_edges);

    // Sort by src so all edges from the same source are contiguous
    // Radix sort is O(n) for u32 keys — faster than comparison sort
    all_edges.sort_unstable_by_key(|(src, dst, _)| (*src, *dst));

    // Build offsets[] in one linear pass
    let mut offsets    = vec![0u32; num_nodes + 1];
    let mut adjacency  = Vec::with_capacity(all_edges.len());
    let mut edge_props = Vec::with_capacity(all_edges.len());
    let mut dropped_oob_edges = 0u64;

    for (src, dst, props) in &all_edges {
        let src_idx = *src as usize;
        let dst_idx = *dst as usize;
        if src_idx >= num_nodes || dst_idx >= num_nodes {
            dropped_oob_edges = dropped_oob_edges.saturating_add(1);
            continue;
        }

        offsets[src_idx + 1] += 1;
        adjacency.push(*dst);
        edge_props.push(*props);
    }

    if dropped_oob_edges > 0 {
        warn!(
            "csr_graph: dropped {} out-of-range edges (num_nodes={})",
            dropped_oob_edges, num_nodes
        );
    }
    // Prefix-sum to convert counts → cumulative offsets
    for i in 1..=num_nodes {
        offsets[i] += offsets[i - 1];
    }

    // Apply risk updates to node_props
    let mut node_props = base.node_props.clone();
    for (id, risk) in risk_updates {
        if let Some(n) = node_props.get_mut(id as usize) {
            n.risk_score = risk;
            n.last_seen_ns = 0; // would be set from event ts_ns in production
        }
    }
    // Merge new nodes
    for (id, props) in new_nodes {
        if let Some(n) = node_props.get_mut(id as usize) {
            *n = props;
        }
    }

    CsrSnapshot {
        num_nodes: num_nodes as u32,
        // Authoritative edge count is what actually made it into adjacency[].
        num_edges: adjacency.len() as u32,
        offsets,
        adjacency,
        edge_props,
        node_props,
    }
}

#[derive(Debug)]
pub struct CsrStats {
    pub num_nodes:   u32,
    pub num_edges:   u32,
    pub merge_count: u64,
}

// -- Tests 
#[cfg(test)]
mod tests {
    use super::*;

    fn make_props(kind: EdgeKind, ts: u64) -> EdgeProps {
        EdgeProps { ts_ns: ts, kind, causal: true, risk_weight: 50, _pad: 0, bytes: 0 }
    }

    fn make_node(label: NodeLabel, risk: f32, internal: bool) -> NodeProps {
        NodeProps {
            first_seen_ns: 0, last_seen_ns: 0,
            risk_score: risk, page_rank: 0.0,
            label, is_internal: internal,
            is_canary: false, community_id: 0, _pad: [0;4],
        }
    }

    fn small_snapshot() -> CsrSnapshot {
        // 5 nodes: 0=nginx, 1=bash, 2=ext_ip, 3=secret, 4=host
        // Edges: 0→1 (SPAWNED), 1→2 (CONNECTED_TO), 1→3 (ACCESSED_SECRET)
        let node_props = vec![
            make_node(NodeLabel::Process,         0.1, true),  // 0 nginx
            make_node(NodeLabel::Process,         0.85, true), // 1 bash
            make_node(NodeLabel::NetworkEndpoint, 0.9, false), // 2 ext ip
            make_node(NodeLabel::Secret,          1.0, true),  // 3 /etc/secret
            make_node(NodeLabel::Host,            0.1, true),  // 4 host
        ];
        // offsets: node 0 has 1 edge (→1), node 1 has 2 edges (→2,→3)
        let offsets    = vec![0, 1, 3, 3, 3, 3];
        let adjacency  = vec![1, 2, 3];
        let edge_props = vec![
            make_props(EdgeKind::Spawned,        1_000),
            make_props(EdgeKind::ConnectedTo,    2_000),
            make_props(EdgeKind::AccessedSecret, 3_000),
        ];
        CsrSnapshot {
            offsets, adjacency, edge_props, node_props,
            num_nodes: 5, num_edges: 3,
        }
    }

    #[test]
    fn neighbors_correct() {
        let g = small_snapshot();
        assert_eq!(g.neighbors(0), &[1]);          // nginx → bash
        assert_eq!(g.neighbors(1), &[2, 3]);       // bash → ext_ip, secret
        assert_eq!(g.neighbors(2), &[] as &[u32]); // ext_ip has no outgoing
    }

    #[test]
    fn external_neighbors_detected() {
        let g = small_snapshot();
        // bash (node 1) connects to ext_ip (node 2, is_internal=false)
        let ext = g.external_neighbors(1);
        assert_eq!(ext, vec![2]);
        // nginx has no external neighbors
        assert!(g.external_neighbors(0).is_empty());
    }

    #[test]
    fn bfs_depth_limited() {
        let g = small_snapshot();
        // BFS from nginx (0) with depth=1: should reach bash (1)
        let reachable: Vec<u32> = g.bfs(0, 1).into_iter().map(|(v,_)| v).collect();
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        // ext_ip (2) is 2 hops away — should NOT be in depth=1 BFS
        assert!(!reachable.contains(&2));
    }

    #[test]
    fn k_hop_subgraph_includes_edges() {
        let g = small_snapshot();
        let (nodes, edges) = g.k_hop_subgraph(0, 2);
        // All 4 reachable nodes should be included
        assert!(nodes.contains(&0)); // nginx
        assert!(nodes.contains(&1)); // bash
        assert!(nodes.contains(&2)); // ext_ip
        assert!(nodes.contains(&3)); // secret
        // Edges within the subgraph
        assert!(edges.iter().any(|(s,d,_)| *s==0 && *d==1)); // SPAWNED
        assert!(edges.iter().any(|(s,d,_)| *s==1 && *d==2)); // CONNECTED_TO
    }

    #[test]
    fn struct_sizes_are_correct() {
        assert_eq!(std::mem::size_of::<NodeProps>(), 32);
        assert_eq!(std::mem::size_of::<EdgeProps>(), 16);
        // Two NodeProps fit in a 64-byte cache line
        assert_eq!(64 / std::mem::size_of::<NodeProps>(), 2);
        // Four EdgeProps fit in a 64-byte cache line
        assert_eq!(64 / std::mem::size_of::<EdgeProps>(), 4);
    }

    #[test]
    fn find_edge_returns_correct_props() {
        let g = small_snapshot();
        let ep = g.find_edge(0, 1).expect("edge 0→1 should exist");
        assert_eq!(ep.kind, EdgeKind::Spawned);
        assert_eq!(ep.ts_ns, 1_000);
        assert!(g.find_edge(0, 2).is_none()); // no direct edge 0→2
    }

    #[test]
    fn merge_preserves_existing_edges_and_adds_new_delta_edges() {
        let g = CsrGraph::new(8, 16);

        g.write_edge(1, 2, make_props(EdgeKind::ConnectedTo, 1_000));
        g.merge_deltas();
        let first = g.snapshot();
        assert_eq!(first.neighbors(1), &[2]);
        assert_eq!(first.num_edges, 1);

        g.write_edge(1, 3, make_props(EdgeKind::ReadFile, 2_000));
        g.merge_deltas();
        let second = g.snapshot();
        assert_eq!(second.neighbors(1), &[2, 3]);
        assert_eq!(second.num_edges, 2);
    }
}
