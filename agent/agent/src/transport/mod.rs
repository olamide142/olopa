//! Transport adapters used by the userspace agent runtime.
//!
//! `http_sender` is the currently active sender path.
//! `grpc_sender_spool` exists in-tree for future integration work but is
//! intentionally not re-exported here yet.

mod durable_spool;
pub mod http_sender;
