use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error};

use crate::config::IngestConfig;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IngestBatchRequest {
    pub tenant_id: String,
    pub host_id: String,
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub process_exec_events: Vec<ProcessExecEvent>,
    #[serde(default)]
    pub file_events: Vec<FileEvent>,
    #[serde(default)]
    pub net_events: Vec<NetEvent>,
    #[serde(default)]
    pub agent_heartbeats: Vec<AgentHeartbeat>,
}

impl IngestBatchRequest {
    fn row_count(&self) -> usize {
        self.process_exec_events.len()
            + self.file_events.len()
            + self.net_events.len()
            + self.agent_heartbeats.len()
    }
}

fn default_schema_version() -> u16 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub tgid: u32,
    #[serde(default)]
    pub ppid: u32,
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    pub comm: String,
    pub filename: String,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    pub comm: String,
    pub operation: String,
    pub path: String,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    pub comm: String,
    pub direction: String,
    pub protocol: String,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentHeartbeat {
    pub agent_version: String,
    pub kernel_version: String,
    pub events_read_total: u64,
    pub events_dropped_total: u64,
    pub queue_depth: u32,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AckResponse {
    pub accepted: bool,
    pub rejected: u32,
    pub retry_after_ms: u32,
    pub suggested_batch_bytes: u32,
    pub throttle_ratio: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IngestStatsResponse {
    pub queued: usize,
    pub max_queue: usize,
    pub accepted_total: u64,
    pub rejected_total: u64,
    pub flushed_total: u64,
    pub failed_flush_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_flush_at_unix_ms: Option<u64>,
}

struct QueuedBatch {
    rows: usize,
    payload: IngestBatchRequest,
}

pub struct IngestRuntime {
    cfg: IngestConfig,
    tx: mpsc::Sender<QueuedBatch>,
    rx: Mutex<Option<mpsc::Receiver<QueuedBatch>>>,
    worker_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    shutdown_tx: watch::Sender<bool>,

    queued: AtomicUsize,
    accepted_total: AtomicU64,
    rejected_total: AtomicU64,
    flushed_total: AtomicU64,
    failed_flush_total: AtomicU64,
    last_flush_at_unix_ms: AtomicU64,
}

impl IngestRuntime {
    pub fn new(cfg: IngestConfig) -> Self {
        let (tx, rx) = mpsc::channel(cfg.queue_maxsize);
        let (shutdown_tx, _) = watch::channel(false);

        Self {
            cfg,
            tx,
            rx: Mutex::new(Some(rx)),
            worker_handle: Mutex::new(None),
            shutdown_tx,
            queued: AtomicUsize::new(0),
            accepted_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            flushed_total: AtomicU64::new(0),
            failed_flush_total: AtomicU64::new(0),
            last_flush_at_unix_ms: AtomicU64::new(0),
        }
    }

    pub async fn start_worker(self: &Arc<Self>) {
        let mut rx_guard = self.rx.lock().await;
        let Some(mut rx) = rx_guard.take() else {
            return;
        };

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut pending_rows = 0usize;
            let mut pending_batches = Vec::<QueuedBatch>::new();
            let mut flush_tick =
                tokio::time::interval(Duration::from_millis(this.cfg.flush_interval_ms));
            flush_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = flush_tick.tick() => {
                        if !pending_batches.is_empty() {
                            this.flush_pending(&mut pending_batches, &mut pending_rows).await;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    recv = rx.recv() => {
                        match recv {
                            Some(batch) => {
                                this.queued.fetch_sub(1, Ordering::Relaxed);
                                pending_rows += batch.rows;
                                pending_batches.push(batch);
                                if pending_rows >= this.cfg.flush_max_rows {
                                    this.flush_pending(&mut pending_batches, &mut pending_rows).await;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            if !pending_batches.is_empty() {
                this.flush_pending(&mut pending_batches, &mut pending_rows)
                    .await;
            }
        });

        *self.worker_handle.lock().await = Some(handle);
    }

    async fn flush_pending(
        &self,
        pending_batches: &mut Vec<QueuedBatch>,
        pending_rows: &mut usize,
    ) {
        if pending_batches.is_empty() {
            return;
        }

        let batch_count = pending_batches.len() as u64;
        let row_count = *pending_rows as u64;

        // Placeholder persistence hook:
        // Replace with ClickHouse/Kafka write path.
        let result = self.persist_placeholder(pending_batches).await;
        match result {
            Ok(inserted_rows) => {
                self.flushed_total
                    .fetch_add(inserted_rows as u64, Ordering::Relaxed);
                self.last_flush_at_unix_ms
                    .store(now_unix_ms(), Ordering::Relaxed);
                debug!(
                    batches = batch_count,
                    rows = row_count,
                    inserted_rows = inserted_rows,
                    "ingest flush complete"
                );
            }
            Err(err) => {
                self.failed_flush_total
                    .fetch_add(batch_count, Ordering::Relaxed);
                error!(error = %err, batches = batch_count, rows = row_count, "ingest flush failed");
            }
        }

        pending_batches.clear();
        *pending_rows = 0;
    }

    async fn persist_placeholder(
        &self,
        pending_batches: &[QueuedBatch],
    ) -> Result<usize, &'static str> {
        // Simulate lightweight persistence work to keep plumbing realistic.
        let mut rows = 0usize;
        for batch in pending_batches {
            rows += batch.rows;
            let _tenant = &batch.payload.tenant_id;
            let _host = &batch.payload.host_id;
            let _schema = batch.payload.schema_version;
            let _batch_id = &batch.payload.batch_id;
        }
        Ok(rows)
    }

    pub fn ack_batch(&self, batch: IngestBatchRequest) -> AckResponse {
        let rows = batch.row_count();
        if rows == 0 {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return AckResponse {
                accepted: false,
                rejected: 1,
                retry_after_ms: self.cfg.default_retry_after_ms,
                suggested_batch_bytes: self.cfg.suggested_batch_bytes,
                throttle_ratio: 0.0,
                message: Some("empty batch".to_string()),
            };
        }

        let queued_batch = QueuedBatch {
            rows,
            payload: batch,
        };
        match self.tx.try_send(queued_batch) {
            Ok(()) => {
                self.accepted_total.fetch_add(1, Ordering::Relaxed);
                let queued = self.queued.fetch_add(1, Ordering::Relaxed) + 1;
                AckResponse {
                    accepted: true,
                    rejected: 0,
                    retry_after_ms: 0,
                    suggested_batch_bytes: self.cfg.suggested_batch_bytes,
                    throttle_ratio: throttle_ratio(queued, self.cfg.queue_maxsize),
                    message: None,
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                let queued = self.queued.load(Ordering::Relaxed);
                AckResponse {
                    accepted: false,
                    rejected: 1,
                    retry_after_ms: self.cfg.default_retry_after_ms,
                    suggested_batch_bytes: (self.cfg.suggested_batch_bytes / 2).max(500_000),
                    throttle_ratio: throttle_ratio(queued, self.cfg.queue_maxsize),
                    message: Some("queue saturated".to_string()),
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                AckResponse {
                    accepted: false,
                    rejected: 1,
                    retry_after_ms: self.cfg.default_retry_after_ms,
                    suggested_batch_bytes: 0,
                    throttle_ratio: 1.0,
                    message: Some("ingest runtime unavailable".to_string()),
                }
            }
        }
    }

    pub fn stats(&self) -> IngestStatsResponse {
        let last = self.last_flush_at_unix_ms.load(Ordering::Relaxed);
        IngestStatsResponse {
            queued: self.queued.load(Ordering::Relaxed),
            max_queue: self.cfg.queue_maxsize,
            accepted_total: self.accepted_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            flushed_total: self.flushed_total.load(Ordering::Relaxed),
            failed_flush_total: self.failed_flush_total.load(Ordering::Relaxed),
            last_flush_at_unix_ms: if last == 0 { None } else { Some(last) },
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.worker_handle.lock().await.take() {
            let _ = handle.await;
        }
    }
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_millis() as u64,
        Err(_) => 0,
    }
}

fn throttle_ratio(queued: usize, max: usize) -> f32 {
    if max == 0 {
        return 1.0;
    }
    (queued as f32 / max as f32).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_batch() -> IngestBatchRequest {
        IngestBatchRequest {
            tenant_id: "acme".to_string(),
            host_id: "host-01".to_string(),
            schema_version: 1,
            batch_id: Some("test-batch".to_string()),
            process_exec_events: vec![ProcessExecEvent {
                pid: 123,
                tgid: 123,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm: "bash".to_string(),
                filename: "/usr/bin/bash".to_string(),
                attrs: HashMap::new(),
            }],
            file_events: Vec::new(),
            net_events: Vec::new(),
            agent_heartbeats: Vec::new(),
        }
    }

    #[tokio::test]
    async fn ack_accepts_and_tracks_queue_depth() {
        let cfg = IngestConfig {
            queue_maxsize: 4,
            flush_interval_ms: 2000,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
        };

        let runtime = Arc::new(IngestRuntime::new(cfg));
        let ack = runtime.ack_batch(test_batch());
        assert!(ack.accepted);
        assert_eq!(runtime.stats().queued, 1);
    }

    #[tokio::test]
    async fn ack_rejects_when_full() {
        let cfg = IngestConfig {
            queue_maxsize: 1,
            flush_interval_ms: 2000,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));

        let first = runtime.ack_batch(test_batch());
        assert!(first.accepted);

        let second = runtime.ack_batch(test_batch());
        assert!(!second.accepted);
        assert_eq!(second.rejected, 1);
    }

    #[tokio::test]
    async fn worker_flushes_pending_batches() {
        let cfg = IngestConfig {
            queue_maxsize: 8,
            flush_interval_ms: 30,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;

        let ack = runtime.ack_batch(test_batch());
        assert!(ack.accepted);

        tokio::time::sleep(Duration::from_millis(90)).await;
        let stats = runtime.stats();
        assert_eq!(stats.queued, 0);
        assert!(stats.flushed_total >= 1);

        runtime.shutdown().await;
    }
}
