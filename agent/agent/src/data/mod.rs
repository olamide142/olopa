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

pub mod event_store;
