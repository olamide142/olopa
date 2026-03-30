//! Data-plane modules.
//!
//! This namespace contains performance-sensitive pipeline components
//! used by `agent.run(...)` orchestration:
//! - event store
//! - relevance scorer
//! - scheduler
//! - batch/compress
//! - graph
//! - rule engine
//! - metric aggregator
//!
//! In the current bootstrap branch, only selected pieces are wired
//! directly in `main.rs` via simple adapters while full integration
//! is completed.

pub mod batcher_compressor;
pub mod csr_graph;
pub mod event_store;
pub mod mdkp_scheduler;
pub mod metric_aggregator;
pub mod relevance_scorer;
