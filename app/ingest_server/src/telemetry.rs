//! Ingest runtime and wire schema for telemetry ingestion.
//!
//! Design overview:
//! - API handlers enqueue validated batches via `ack_batch`.
//! - A background worker drains queue entries into in-memory pending buffers.
//! - Flush is triggered by time and/or row count thresholds.
//! - Flushed rows are persisted to ClickHouse (optional) with JSONL fallback.
//! - Operational counters expose queue depth and flush health.

use std::collections::{hash_map::DefaultHasher, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::fs::{create_dir_all, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error};

use super::config::IngestConfig;
use super::durability::{AcceptOutcome, DurableAcceptance};

/// Versioned ingest request envelope sent by agents.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IngestBatchRequest {
    /// Tenant scope for multi-tenant ingestion.
    pub tenant_id: String,
    /// Stable host identity for source attribution.
    pub host_id: String,
    /// Wire/schema version of this request format.
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    /// Optional sender-generated idempotency token.
    #[serde(default)]
    pub batch_id: Option<String>,
    /// Process execution events.
    #[serde(default)]
    pub process_exec_events: Vec<ProcessExecEvent>,
    /// File system telemetry events.
    #[serde(default)]
    pub file_events: Vec<FileEvent>,
    /// Network telemetry events.
    #[serde(default)]
    pub net_events: Vec<NetEvent>,
    /// Database query events derived from SQL client uprobes.
    ///
    /// Added in schema version 2; absent from version 1 senders.
    #[serde(default)]
    pub db_query_events: Vec<DbQueryEvent>,
    /// Agent heartbeat/health events.
    #[serde(default)]
    pub agent_heartbeats: Vec<AgentHeartbeat>,
}

impl IngestBatchRequest {
    /// Count all event rows in this batch across all event families.
    fn row_count(&self) -> usize {
        self.process_exec_events.len()
            + self.file_events.len()
            + self.net_events.len()
            + self.db_query_events.len()
            + self.agent_heartbeats.len()
    }
}

/// Default schema version for backwards-compatible deserialization.
fn default_schema_version() -> u16 {
    1
}

/// Process execution event emitted by agent/runtime.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessExecEvent {
    /// Process id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// Parent process id when available.
    #[serde(default)]
    pub ppid: u32,
    /// User id.
    pub uid: u32,
    /// Group id.
    #[serde(default)]
    pub gid: u32,
    /// Process command/executable short name.
    pub comm: String,
    /// Executable path.
    pub filename: String,
    /// Arbitrary key/value attributes.
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

/// File event emitted by agent/runtime.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileEvent {
    /// Process id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// User id.
    pub uid: u32,
    /// Group id.
    #[serde(default)]
    pub gid: u32,
    /// Process command/executable short name.
    pub comm: String,
    /// File operation name (read/write/open/etc).
    pub operation: String,
    /// File path.
    pub path: String,
    /// Arbitrary key/value attributes.
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

/// Network event emitted by agent/runtime.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetEvent {
    /// Process id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// User id.
    pub uid: u32,
    /// Group id.
    #[serde(default)]
    pub gid: u32,
    /// Process command/executable short name.
    pub comm: String,
    /// Direction label (`inbound`/`outbound`).
    pub direction: String,
    /// Protocol label (`tcp`/`udp`/etc).
    pub protocol: String,
    /// Optional source IP.
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Optional destination IP.
    #[serde(default)]
    pub dst_ip: Option<String>,
    /// Optional source port.
    #[serde(default)]
    pub src_port: Option<u16>,
    /// Optional destination port.
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// Arbitrary key/value attributes.
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

/// Database query event emitted by agent SQL uprobes.
///
/// Normalized shape so a query is attributable to a process without the caller
/// having to understand engine-specific wire protocols. `database` and `tables`
/// stay optional: the agent resolves them from redacted statement text, and a
/// statement it cannot parse confidently omits them rather than guessing. They
/// are also absent from senders predating statement capture.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DbQueryEvent {
    /// Process id issuing the query.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// User id.
    pub uid: u32,
    /// Group id.
    #[serde(default)]
    pub gid: u32,
    /// Process command/executable short name.
    pub comm: String,
    /// Engine label (`postgresql`/`mysql`/`unknown`).
    pub db_engine: String,
    /// Database endpoint as `host:port` when known.
    #[serde(default)]
    pub db_server: Option<String>,
    /// Target database/schema name when resolvable.
    #[serde(default)]
    pub database: Option<String>,
    /// Normalized operation (`select`/`dml`/`ddl`/`admin`/`other`).
    pub operation: String,
    /// Tables referenced by the statement when resolvable.
    #[serde(default)]
    pub tables: Vec<String>,
    /// Stable statement hash; never contains literal values.
    pub statement_fingerprint: String,
    /// Arbitrary key/value attributes.
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

/// Agent health/heartbeat payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentHeartbeat {
    /// Agent software version.
    pub agent_version: String,
    /// Kernel version seen by agent.
    pub kernel_version: String,
    /// Total events read by source agent.
    pub events_read_total: u64,
    /// Total events dropped by source agent.
    pub events_dropped_total: u64,
    /// Sender queue depth observed on agent side.
    pub queue_depth: u32,
    /// Arbitrary key/value attributes.
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

/// Ack contract returned to ingest senders.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AckResponse {
    /// Whether batch was accepted into server queue.
    pub accepted: bool,
    /// True when an already-accepted batch id was acknowledged without enqueueing it again.
    #[serde(default)]
    pub duplicate: bool,
    /// Number of rejected rows/batches for this request.
    pub rejected: u32,
    /// Backoff hint when rejected/throttled.
    pub retry_after_ms: u32,
    /// Recommended payload size for sender next batch.
    pub suggested_batch_bytes: u32,
    /// Queue pressure ratio in range `[0, 1]`.
    pub throttle_ratio: f32,
    /// Optional informational error/detail string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Operational stats for runtime queue and flushing.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IngestStatsResponse {
    /// Current queue depth.
    pub queued: usize,
    /// Configured queue capacity.
    pub max_queue: usize,
    /// Total accepted batches.
    pub accepted_total: u64,
    /// Total retry batches acknowledged without enqueueing duplicate rows.
    pub duplicate_total: u64,
    /// Total rejected batches.
    pub rejected_total: u64,
    /// Total rows flushed successfully.
    pub flushed_total: u64,
    /// Total failed flush attempts.
    pub failed_flush_total: u64,
    /// Uncommitted acceptance records currently retained in the WAL.
    pub wal_pending: usize,
    /// WAL batches replayed during this process start.
    pub replayed_total: u64,
    /// Active partitioned flush workers.
    pub flush_workers: usize,
    /// Retried remote sink requests.
    pub sink_retry_total: u64,
    /// Payloads written to the dead-letter file.
    pub dead_letter_total: u64,
    /// Number of times either remote sink circuit opened.
    pub circuit_open_total: u64,
    /// Wall-clock timestamp of last successful flush.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_flush_at_unix_ms: Option<u64>,
}

/// One recently ingested event row retained in memory for API inspection.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecentIngestRow {
    /// Tenant scope for this row.
    pub tenant_id: String,
    /// Source host id.
    pub host_id: String,
    /// Original batch id if provided by sender.
    pub batch_id: Option<String>,
    /// Event family label (`process_exec`, `file`, `net`, `db_query`,
    /// `agent_heartbeat`).
    pub event_kind: String,
    /// Ingest timestamp generated during flush.
    pub ingested_at_unix_ms: u64,
    /// Raw event payload body.
    pub event: serde_json::Value,
}

/// Response for `recent ingested rows` endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecentIngestResponse {
    /// Total number of rows currently retained in memory.
    pub total_available: usize,
    /// Number of rows returned in this response.
    pub returned: usize,
    /// Most-recent-first row list.
    pub rows: Vec<RecentIngestRow>,
}

/// Aggregated counters computed from flushed rows since process start.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IngestDataSummaryResponse {
    /// Total number of rows recorded by this process.
    pub total_rows: u64,
    /// Rows grouped by event kind.
    pub by_kind: HashMap<String, u64>,
    /// Rows grouped by tenant id.
    pub by_tenant: HashMap<String, u64>,
    /// Rows grouped by host id.
    pub by_host: HashMap<String, u64>,
}

/// Internal flattened row representation used for persistence + indexing.
#[derive(Clone, Debug)]
struct PersistRow {
    /// JSONEachRow / JSONL serialized representation.
    line: String,
    /// Parsed row data retained in memory.
    recent: RecentIngestRow,
}

/// In-memory data index updated on successful flush.
#[derive(Default)]
struct IngestInMemoryState {
    /// Fixed-size ring buffer of recently flushed rows.
    recent_rows: VecDeque<RecentIngestRow>,
    /// Aggregated counters by event kind.
    by_kind: HashMap<String, u64>,
    /// Aggregated counters by event kind per tenant.
    by_kind_by_tenant: HashMap<String, HashMap<String, u64>>,
    /// Aggregated counters by tenant.
    by_tenant: HashMap<String, u64>,
    /// Aggregated counters by host.
    by_host: HashMap<String, u64>,
    /// Aggregated counters by host per tenant.
    by_host_by_tenant: HashMap<String, HashMap<String, u64>>,
    /// Total rows tracked since process start.
    total_rows: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReadinessResponse {
    pub ready: bool,
    pub queue_healthy: bool,
    pub wal_healthy: bool,
    pub workers_healthy: bool,
    pub local_sink_healthy: bool,
    pub surreal_circuit_open: bool,
    pub clickhouse_circuit_open: bool,
    pub queued: usize,
    pub wal_pending: usize,
}

#[derive(Debug)]
struct SinkError {
    message: String,
    permanent: bool,
}

impl SinkError {
    fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
        }
    }

    fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: true,
        }
    }

    fn status(status: reqwest::StatusCode, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: status.is_client_error()
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

#[derive(Debug)]
struct RemoteFailure {
    message: String,
    permanent: bool,
}

impl std::fmt::Display for RemoteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[derive(Default)]
struct CircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    fn is_open(&self) -> bool {
        self.open_until.is_some_and(|until| until > Instant::now())
    }

    fn allow(&mut self) -> bool {
        match self.open_until {
            Some(until) if until > Instant::now() => false,
            Some(_) => {
                self.open_until = None;
                true
            }
            None => true,
        }
    }

    fn success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn failure(&mut self, threshold: u32, open_for: Duration) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= threshold.max(1) {
            self.open_until = Some(Instant::now() + open_for);
            self.consecutive_failures = 0;
            true
        } else {
            false
        }
    }
}

/// Internal queue item (batch plus precomputed row count).
struct QueuedBatch {
    /// Durable WAL sequence used to commit this acceptance after persistence.
    sequence: u64,
    /// Number of rows in payload for quick threshold accounting.
    rows: usize,
    /// Original request payload.
    payload: IngestBatchRequest,
}

/// Ingest runtime owning queue, flush worker, persistence hooks, and metrics.
pub struct IngestRuntime {
    /// Runtime config snapshot.
    cfg: IngestConfig,
    /// Optional prebuilt SurrealDB HTTP client.
    surreal_client: Option<reqwest::Client>,
    /// Optional prebuilt ClickHouse HTTP client.
    clickhouse_client: Option<reqwest::Client>,
    /// Sender side of bounded ingest queue.
    tx: Vec<mpsc::Sender<QueuedBatch>>,
    /// Partition receivers moved into background workers at startup.
    rx: Mutex<Vec<mpsc::Receiver<QueuedBatch>>>,
    /// Join handles for background workers.
    worker_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Cooperative shutdown flag for worker.
    shutdown_tx: watch::Sender<bool>,

    /// Approximate queue depth.
    queued: AtomicUsize,
    /// Accepted batch counter.
    accepted_total: AtomicU64,
    /// Duplicate retry counter.
    duplicate_total: AtomicU64,
    /// Rejected batch counter.
    rejected_total: AtomicU64,
    /// Flushed row counter.
    flushed_total: AtomicU64,
    /// Failed flush counter.
    failed_flush_total: AtomicU64,
    /// Last successful flush timestamp.
    last_flush_at_unix_ms: AtomicU64,
    /// Batches recovered from the acceptance WAL during this process start.
    replayed_total: AtomicU64,
    /// Number of active partition workers.
    workers_started: AtomicUsize,
    sink_retry_total: AtomicU64,
    dead_letter_total: AtomicU64,
    circuit_open_total: AtomicU64,
    flush_duration_buckets: [AtomicU64; 7],
    flush_duration_count: AtomicU64,
    flush_duration_sum_micros: AtomicU64,
    /// In-memory recent rows + aggregates exposed by inspection APIs.
    state: Mutex<IngestInMemoryState>,
    /// Fsynced acceptance log and persistent idempotency state.
    durable: Arc<DurableAcceptance>,
    surreal_breaker: StdMutex<CircuitBreaker>,
    clickhouse_breaker: StdMutex<CircuitBreaker>,
    /// Serialize multi-write JSONL records across partition workers.
    jsonl_lock: Mutex<()>,
    /// Serialize dead-letter records across partition workers.
    dead_letter_lock: Mutex<()>,
}

impl IngestRuntime {
    /// Construct a new ingest runtime with bounded queue and counters reset.
    #[cfg(test)]
    pub fn new(cfg: IngestConfig) -> Self {
        Self::try_new(cfg).expect("initialize durable ingest runtime")
    }

    /// Construct a runtime, failing startup if durable acceptance cannot open.
    pub fn try_new(cfg: IngestConfig) -> Result<Self, String> {
        let worker_count = cfg.flush_workers.max(1);
        let partition_capacity = cfg.queue_maxsize.div_ceil(worker_count).max(1);
        let mut tx = Vec::with_capacity(worker_count);
        let mut rx = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (partition_tx, partition_rx) = mpsc::channel(partition_capacity);
            tx.push(partition_tx);
            rx.push(partition_rx);
        }
        let (shutdown_tx, _) = watch::channel(false);
        let durable = Arc::new(DurableAcceptance::open(
            &cfg.wal_path,
            &cfg.dedupe_path,
            cfg.dedupe_max_entries,
            cfg.wal_compact_after_commits,
        )?);
        let surreal_client = cfg.surreal_url.as_ref().and_then(|_| {
            reqwest::Client::builder()
                .timeout(Duration::from_millis(cfg.surreal_timeout_ms))
                .build()
                .map_err(|err| {
                    error!(error = %err, "failed to build surrealdb HTTP client; disabling SurrealDB sink");
                    err
                })
                .ok()
        });
        let clickhouse_client = cfg.clickhouse_url.as_ref().and_then(|_| {
            reqwest::Client::builder()
                .timeout(Duration::from_millis(cfg.clickhouse_timeout_ms))
                .build()
                .map_err(|err| {
                    error!(error = %err, "failed to build clickhouse HTTP client; disabling ClickHouse sink");
                    err
                })
                .ok()
        });

        Ok(Self {
            cfg,
            surreal_client,
            clickhouse_client,
            tx,
            rx: Mutex::new(rx),
            worker_handles: Mutex::new(Vec::new()),
            shutdown_tx,
            queued: AtomicUsize::new(0),
            accepted_total: AtomicU64::new(0),
            duplicate_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            flushed_total: AtomicU64::new(0),
            failed_flush_total: AtomicU64::new(0),
            last_flush_at_unix_ms: AtomicU64::new(0),
            replayed_total: AtomicU64::new(0),
            workers_started: AtomicUsize::new(0),
            sink_retry_total: AtomicU64::new(0),
            dead_letter_total: AtomicU64::new(0),
            circuit_open_total: AtomicU64::new(0),
            flush_duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            flush_duration_count: AtomicU64::new(0),
            flush_duration_sum_micros: AtomicU64::new(0),
            state: Mutex::new(IngestInMemoryState::default()),
            durable,
            surreal_breaker: StdMutex::new(CircuitBreaker::default()),
            clickhouse_breaker: StdMutex::new(CircuitBreaker::default()),
            jsonl_lock: Mutex::new(()),
            dead_letter_lock: Mutex::new(()),
        })
    }

    /// Start partitioned background flush workers and replay uncommitted WAL entries.
    ///
    /// Idempotent: calling this more than once is a no-op after the receiver has
    /// already been moved into a worker.
    pub async fn start_worker(self: &Arc<Self>) {
        let mut rx_guard = self.rx.lock().await;
        if rx_guard.is_empty() {
            return;
        }

        let receivers = std::mem::take(&mut *rx_guard);
        drop(rx_guard);
        let mut handles = Vec::with_capacity(receivers.len());
        for mut rx in receivers {
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let this = Arc::clone(self);
            handles.push(tokio::spawn(async move {
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
            }));
        }
        self.workers_started.store(handles.len(), Ordering::Release);
        *self.worker_handles.lock().await = handles;

        let recovered = self.durable.recovered();
        for (sequence, payload) in recovered {
            let rows = payload.row_count();
            let partition = self.partition_for(&payload);
            self.queued.fetch_add(1, Ordering::Relaxed);
            if self.tx[partition]
                .send(QueuedBatch {
                    sequence,
                    rows,
                    payload,
                })
                .await
                .is_err()
            {
                self.queued.fetch_sub(1, Ordering::Relaxed);
                break;
            }
            self.replayed_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn flush_pending(
        &self,
        pending_batches: &mut Vec<QueuedBatch>,
        pending_rows: &mut usize,
    ) {
        // Nothing to flush.
        if pending_batches.is_empty() {
            return;
        }

        let batch_count = pending_batches.len() as u64;
        let row_count = *pending_rows as u64;

        let started = Instant::now();
        let result = match self.persist_batches(pending_batches).await {
            Ok(inserted) => {
                let sequences = pending_batches
                    .iter()
                    .map(|batch| batch.sequence)
                    .collect::<Vec<_>>();
                let durable = Arc::clone(&self.durable);
                match tokio::task::spawn_blocking(move || durable.commit(&sequences)).await {
                    Ok(Ok(())) => Ok(inserted),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("WAL commit worker failed: {err}")),
                }
            }
            Err(err) => Err(err),
        };
        self.observe_flush_duration(started.elapsed());
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
                pending_batches.clear();
                *pending_rows = 0;
            }
            Err(err) => {
                self.failed_flush_total
                    .fetch_add(batch_count, Ordering::Relaxed);
                error!(error = %err, batches = batch_count, rows = row_count, "ingest flush failed");
            }
        }
    }

    /// Persist pending batches and return number of rows durably written.
    ///
    /// Strategy:
    /// - flatten all event families into JSON rows,
    /// - try SurrealDB when configured,
    /// - then try ClickHouse when configured,
    /// - always fall back to local JSONL on sink failures.
    async fn persist_batches(&self, pending_batches: &[QueuedBatch]) -> Result<usize, String> {
        let rows = build_persist_rows(pending_batches)
            .map_err(|err| format!("serialize rows failed: {err}"))?;
        if rows.is_empty() {
            return Ok(0);
        }

        if self.cfg.surreal_url.is_some() {
            match self.persist_surreal_resilient(&rows).await {
                Ok(()) => {}
                Err(surreal_err) => {
                    error!(
                        error = %surreal_err,
                        "surrealdb insert failed; trying clickhouse/jsonl fallback path"
                    );
                    if self.cfg.clickhouse_url.is_some() {
                        match self.persist_clickhouse_resilient(&rows).await {
                            Ok(()) => {}
                            Err(clickhouse_err) => {
                                error!(
                                    error = %clickhouse_err,
                                    "clickhouse fallback insert failed; falling back to JSONL persistence"
                                );
                                if surreal_err.permanent || clickhouse_err.permanent {
                                    let reason = format!(
                                        "permanent remote failure: surreal={surreal_err}; clickhouse={clickhouse_err}"
                                    );
                                    self.persist_dead_letter(&rows, &reason).await?;
                                } else if let Err(io_err) = self.persist_jsonl(&rows).await {
                                    let reason = format!("surreal={surreal_err}; clickhouse={clickhouse_err}; jsonl={io_err}");
                                    self.persist_dead_letter(&rows, &reason).await?;
                                }
                            }
                        }
                    } else {
                        if surreal_err.permanent {
                            let reason = format!("permanent surreal failure: {surreal_err}");
                            self.persist_dead_letter(&rows, &reason).await?;
                        } else if let Err(io_err) = self.persist_jsonl(&rows).await {
                            let reason = format!("surreal={surreal_err}; jsonl={io_err}");
                            self.persist_dead_letter(&rows, &reason).await?;
                        }
                    }
                }
            }
        } else {
            if self.cfg.clickhouse_url.is_some() {
                match self.persist_clickhouse_resilient(&rows).await {
                    Ok(()) => {}
                    Err(err) => {
                        error!(
                            error = %err,
                            "clickhouse insert failed; falling back to JSONL persistence"
                        );
                        if err.permanent {
                            let reason = format!("permanent clickhouse failure: {err}");
                            self.persist_dead_letter(&rows, &reason).await?;
                        } else if let Err(io_err) = self.persist_jsonl(&rows).await {
                            let reason = format!("clickhouse={err}; jsonl={io_err}");
                            self.persist_dead_letter(&rows, &reason).await?;
                        }
                    }
                }
            } else {
                self.persist_jsonl(&rows)
                    .await
                    .map_err(|io_err| format!("jsonl persistence failed: {io_err}"))?;
            }
        }

        self.record_rows(&rows).await;
        Ok(rows.len())
    }

    /// Try inserting flattened rows into SurrealDB over HTTP SQL endpoint.
    async fn persist_surreal_once(&self, rows: &[PersistRow]) -> Result<(), SinkError> {
        let Some(url_base) = self.cfg.surreal_url.as_ref() else {
            return Err(SinkError::transient("surrealdb URL not configured"));
        };
        let Some(client) = self.surreal_client.as_ref() else {
            return Err(SinkError::transient("surrealdb client unavailable"));
        };
        if !is_valid_surreal_identifier(&self.cfg.surreal_table) {
            return Err(SinkError::permanent(format!(
                "invalid surreal table name '{}': only [A-Za-z0-9_] allowed",
                self.cfg.surreal_table
            )));
        }

        let sql = build_surreal_insert_sql(rows, &self.cfg.surreal_table);
        let mut req = client
            .post(url_base)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .header("NS", &self.cfg.surreal_namespace)
            .header("DB", &self.cfg.surreal_database)
            .body(sql);

        if let Some(token) = self.cfg.surreal_token.as_ref() {
            req = req.bearer_auth(token);
        } else if let Some(user) = self.cfg.surreal_user.as_ref() {
            req = req.basic_auth(user, self.cfg.surreal_password.as_ref());
        }

        let resp = req
            .send()
            .await
            .map_err(|err| SinkError::transient(format!("surrealdb HTTP request failed: {err}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(SinkError::status(
                status,
                format!(
                    "surrealdb insert failed (status={}): {}",
                    status,
                    truncate_for_log(&body, 512)
                ),
            ));
        }

        if let Some(err_message) = extract_surreal_error(&body) {
            return Err(SinkError::transient(format!(
                "surrealdb insert returned error: {err_message}"
            )));
        }

        Ok(())
    }

    /// Try inserting flattened rows into ClickHouse over HTTP.
    ///
    /// Uses `query=<INSERT ... FORMAT JSONEachRow>` style endpoint.
    async fn persist_clickhouse_once(&self, rows: &[PersistRow]) -> Result<(), SinkError> {
        let Some(url_base) = self.cfg.clickhouse_url.as_ref() else {
            return Err(SinkError::transient("clickhouse URL not configured"));
        };
        let Some(client) = self.clickhouse_client.as_ref() else {
            return Err(SinkError::transient("clickhouse client unavailable"));
        };

        let mut url = reqwest::Url::parse(url_base).map_err(|err| {
            SinkError::transient(format!("invalid clickhouse URL '{url_base}': {err}"))
        })?;
        url.query_pairs_mut()
            .append_pair("query", &self.cfg.clickhouse_insert_sql);

        let mut req = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                rows.iter()
                    .map(|r| r.line.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            );

        if let Some(user) = self.cfg.clickhouse_user.as_ref() {
            req = req.basic_auth(user, self.cfg.clickhouse_password.as_ref());
        }

        let resp = req.send().await.map_err(|err| {
            SinkError::transient(format!("clickhouse HTTP request failed: {err}"))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SinkError::status(
                status,
                format!(
                    "clickhouse insert failed (status={}): {}",
                    status,
                    truncate_for_log(&body, 512)
                ),
            ));
        }

        Ok(())
    }

    /// Append flattened rows to local JSONL fallback file.
    async fn persist_jsonl(&self, rows: &[PersistRow]) -> std::io::Result<()> {
        let _write_guard = self.jsonl_lock.lock().await;
        let path = std::path::Path::new(&self.cfg.persist_jsonl_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_all(parent).await?;
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        for row in rows {
            file.write_all(row.line.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
        file.flush().await?;
        file.sync_data().await
    }

    async fn persist_surreal_resilient(&self, rows: &[PersistRow]) -> Result<(), RemoteFailure> {
        self.persist_remote_with_retry(rows, true).await
    }

    async fn persist_clickhouse_resilient(&self, rows: &[PersistRow]) -> Result<(), RemoteFailure> {
        self.persist_remote_with_retry(rows, false).await
    }

    async fn persist_remote_with_retry(
        &self,
        rows: &[PersistRow],
        surreal: bool,
    ) -> Result<(), RemoteFailure> {
        let breaker = if surreal {
            &self.surreal_breaker
        } else {
            &self.clickhouse_breaker
        };
        if !breaker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allow()
        {
            return Err(RemoteFailure {
                message: "sink circuit is open".to_string(),
                permanent: false,
            });
        }

        let attempts = self.cfg.sink_retry_max_attempts.max(1);
        let mut delay = self.cfg.sink_retry_initial_ms.max(1);
        let mut last_error = String::new();
        let mut permanent = false;
        for attempt in 0..attempts {
            let result = if surreal {
                self.persist_surreal_once(rows).await
            } else {
                self.persist_clickhouse_once(rows).await
            };
            match result {
                Ok(()) => {
                    breaker
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .success();
                    return Ok(());
                }
                Err(err) => {
                    last_error = err.message;
                    permanent = err.permanent;
                    if err.permanent || attempt + 1 == attempts {
                        let opened = breaker
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .failure(
                                self.cfg.circuit_failure_threshold,
                                Duration::from_millis(self.cfg.circuit_open_ms),
                            );
                        if opened {
                            self.circuit_open_total.fetch_add(1, Ordering::Relaxed);
                        }
                        break;
                    }
                    self.sink_retry_total.fetch_add(1, Ordering::Relaxed);
                    let jitter = retry_jitter_ms(attempt, delay);
                    tokio::time::sleep(Duration::from_millis(delay.saturating_add(jitter))).await;
                    delay = delay
                        .saturating_mul(2)
                        .min(self.cfg.sink_retry_max_ms.max(1));
                }
            }
        }
        Err(RemoteFailure {
            message: last_error,
            permanent,
        })
    }

    async fn persist_dead_letter(&self, rows: &[PersistRow], reason: &str) -> Result<(), String> {
        let _write_guard = self.dead_letter_lock.lock().await;
        let path = std::path::Path::new(&self.cfg.dead_letter_path);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            create_dir_all(parent)
                .await
                .map_err(|err| format!("create dead-letter directory: {err}"))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|err| format!("open dead-letter file: {err}"))?;
        for row in rows {
            let record = json!({
                "failed_at_unix_ms": now_unix_ms(),
                "reason": reason,
                "row": serde_json::from_str::<serde_json::Value>(&row.line).unwrap_or_default(),
            });
            let line = serde_json::to_vec(&record)
                .map_err(|err| format!("serialize dead-letter record: {err}"))?;
            file.write_all(&line)
                .await
                .map_err(|err| format!("write dead-letter record: {err}"))?;
            file.write_all(b"\n")
                .await
                .map_err(|err| format!("write dead-letter delimiter: {err}"))?;
        }
        file.sync_data()
            .await
            .map_err(|err| format!("fsync dead-letter file: {err}"))?;
        self.dead_letter_total
            .fetch_add(rows.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Update in-memory recent rows and aggregate counters after successful flush.
    async fn record_rows(&self, rows: &[PersistRow]) {
        let mut state = self.state.lock().await;
        for row in rows {
            let tenant_id = row.recent.tenant_id.clone();
            let host_id = row.recent.host_id.clone();
            let event_kind = row.recent.event_kind.clone();

            state.total_rows = state.total_rows.saturating_add(1);
            *state.by_kind.entry(event_kind.clone()).or_insert(0) += 1;
            *state.by_tenant.entry(tenant_id.clone()).or_insert(0) += 1;
            *state.by_host.entry(host_id.clone()).or_insert(0) += 1;
            *state
                .by_kind_by_tenant
                .entry(tenant_id.clone())
                .or_default()
                .entry(event_kind)
                .or_insert(0) += 1;
            *state
                .by_host_by_tenant
                .entry(tenant_id)
                .or_default()
                .entry(host_id)
                .or_insert(0) += 1;

            state.recent_rows.push_back(row.recent.clone());
            while state.recent_rows.len() > self.cfg.recent_events_max {
                state.recent_rows.pop_front();
            }
        }
    }

    /// Queue a batch for async processing and return immediate ack/backpressure hints.
    pub fn ack_batch(&self, batch: IngestBatchRequest) -> AckResponse {
        let rows = batch.row_count();
        if !(1..=2).contains(&batch.schema_version) {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return AckResponse {
                accepted: false,
                duplicate: false,
                rejected: 1,
                retry_after_ms: 0,
                suggested_batch_bytes: self.cfg.suggested_batch_bytes,
                throttle_ratio: throttle_ratio(
                    self.queued.load(Ordering::Relaxed),
                    self.cfg.queue_maxsize,
                ),
                message: Some(format!(
                    "unsupported schema_version {}; supported versions are 1 and 2",
                    batch.schema_version
                )),
            };
        }
        if rows == 0 {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return AckResponse {
                accepted: false,
                duplicate: false,
                rejected: 1,
                retry_after_ms: self.cfg.default_retry_after_ms,
                suggested_batch_bytes: self.cfg.suggested_batch_bytes,
                throttle_ratio: 0.0,
                message: Some("empty batch".to_string()),
            };
        }

        let partition = self.partition_for(&batch);
        let sender = &self.tx[partition];
        let acceptance = self.durable.accept(batch, |sequence, payload| {
            let previous = self.queued.fetch_add(1, Ordering::Relaxed);
            if previous >= self.cfg.queue_maxsize {
                self.queued.fetch_sub(1, Ordering::Relaxed);
                return Err(false);
            }
            match sender.try_send(QueuedBatch {
                sequence,
                rows,
                payload,
            }) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.queued.fetch_sub(1, Ordering::Relaxed);
                    Err(false)
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.queued.fetch_sub(1, Ordering::Relaxed);
                    Err(true)
                }
            }
        });
        match acceptance {
            Ok(AcceptOutcome::Accepted(sequence)) => {
                let _accepted_wal_sequence = sequence;
                self.accepted_total.fetch_add(1, Ordering::Relaxed);
                let queued = self.queued.load(Ordering::Relaxed);
                AckResponse {
                    accepted: true,
                    duplicate: false,
                    rejected: 0,
                    retry_after_ms: 0,
                    suggested_batch_bytes: self.cfg.suggested_batch_bytes,
                    throttle_ratio: throttle_ratio(queued, self.cfg.queue_maxsize),
                    message: None,
                }
            }
            Ok(AcceptOutcome::Duplicate) => {
                self.duplicate_total.fetch_add(1, Ordering::Relaxed);
                let queued = self.queued.load(Ordering::Relaxed);
                AckResponse {
                    accepted: true,
                    duplicate: true,
                    rejected: 0,
                    retry_after_ms: 0,
                    suggested_batch_bytes: self.cfg.suggested_batch_bytes,
                    throttle_ratio: throttle_ratio(queued, self.cfg.queue_maxsize),
                    message: Some("duplicate batch_id already accepted".to_string()),
                }
            }
            Ok(AcceptOutcome::QueueFull) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                let queued = self.queued.load(Ordering::Relaxed);
                AckResponse {
                    accepted: false,
                    duplicate: false,
                    rejected: 1,
                    retry_after_ms: self.cfg.default_retry_after_ms,
                    suggested_batch_bytes: (self.cfg.suggested_batch_bytes / 2).max(500_000),
                    throttle_ratio: throttle_ratio(queued, self.cfg.queue_maxsize),
                    message: Some("queue saturated".to_string()),
                }
            }
            Ok(AcceptOutcome::QueueClosed) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                AckResponse {
                    accepted: false,
                    duplicate: false,
                    rejected: 1,
                    retry_after_ms: self.cfg.default_retry_after_ms,
                    suggested_batch_bytes: 0,
                    throttle_ratio: 1.0,
                    message: Some("ingest runtime unavailable".to_string()),
                }
            }
            Err(err) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                AckResponse {
                    accepted: false,
                    duplicate: false,
                    rejected: 1,
                    retry_after_ms: self.cfg.default_retry_after_ms,
                    suggested_batch_bytes: 0,
                    throttle_ratio: 1.0,
                    message: Some(format!("durable acceptance failed: {err}")),
                }
            }
        }
    }

    fn partition_for(&self, batch: &IngestBatchRequest) -> usize {
        let mut hasher = DefaultHasher::new();
        batch.tenant_id.hash(&mut hasher);
        batch.host_id.hash(&mut hasher);
        (hasher.finish() as usize) % self.tx.len()
    }

    /// Snapshot current ingest runtime counters.
    pub fn stats(&self) -> IngestStatsResponse {
        let last = self.last_flush_at_unix_ms.load(Ordering::Relaxed);
        IngestStatsResponse {
            queued: self.queued.load(Ordering::Relaxed),
            max_queue: self.cfg.queue_maxsize,
            accepted_total: self.accepted_total.load(Ordering::Relaxed),
            duplicate_total: self.duplicate_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            flushed_total: self.flushed_total.load(Ordering::Relaxed),
            failed_flush_total: self.failed_flush_total.load(Ordering::Relaxed),
            wal_pending: self.durable.pending_count(),
            replayed_total: self.replayed_total.load(Ordering::Relaxed),
            flush_workers: self.workers_started.load(Ordering::Acquire),
            sink_retry_total: self.sink_retry_total.load(Ordering::Relaxed),
            dead_letter_total: self.dead_letter_total.load(Ordering::Relaxed),
            circuit_open_total: self.circuit_open_total.load(Ordering::Relaxed),
            last_flush_at_unix_ms: if last == 0 { None } else { Some(last) },
        }
    }

    /// Readiness is intentionally stricter than liveness: it checks acceptance,
    /// worker availability, queue pressure, local persistence, and sink circuits.
    pub async fn readiness(&self) -> ReadinessResponse {
        let queued = self.queued.load(Ordering::Relaxed);
        let queue_healthy = queued < self.cfg.queue_maxsize;
        let wal_healthy = self.durable.is_healthy();
        let workers_healthy = self.workers_started.load(Ordering::Acquire) == self.tx.len();
        let local_sink_healthy = probe_append_path(&self.cfg.persist_jsonl_path).await;
        let surreal_circuit_open = self
            .surreal_breaker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_open();
        let clickhouse_circuit_open = self
            .clickhouse_breaker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_open();
        let remote_healthy = (self.cfg.surreal_url.is_none() || !surreal_circuit_open)
            && (self.cfg.clickhouse_url.is_none() || !clickhouse_circuit_open);
        ReadinessResponse {
            ready: queue_healthy
                && wal_healthy
                && workers_healthy
                && local_sink_healthy
                && remote_healthy,
            queue_healthy,
            wal_healthy,
            workers_healthy,
            local_sink_healthy,
            surreal_circuit_open,
            clickhouse_circuit_open,
            queued,
            wal_pending: self.durable.pending_count(),
        }
    }

    /// Render Prometheus exposition text without a global recorder dependency.
    pub fn prometheus_metrics(&self) -> String {
        let stats = self.stats();
        let mut out = String::new();
        metric(
            &mut out,
            "olopa_ingest_accepted_batches_total",
            stats.accepted_total,
        );
        metric(
            &mut out,
            "olopa_ingest_duplicate_batches_total",
            stats.duplicate_total,
        );
        metric(
            &mut out,
            "olopa_ingest_rejected_batches_total",
            stats.rejected_total,
        );
        metric(
            &mut out,
            "olopa_ingest_flushed_rows_total",
            stats.flushed_total,
        );
        metric(
            &mut out,
            "olopa_ingest_failed_flushes_total",
            stats.failed_flush_total,
        );
        metric(
            &mut out,
            "olopa_ingest_sink_retries_total",
            stats.sink_retry_total,
        );
        metric(
            &mut out,
            "olopa_ingest_dead_letter_rows_total",
            stats.dead_letter_total,
        );
        metric(
            &mut out,
            "olopa_ingest_circuit_opens_total",
            stats.circuit_open_total,
        );
        gauge(&mut out, "olopa_ingest_queue_depth", stats.queued);
        gauge(&mut out, "olopa_ingest_wal_pending", stats.wal_pending);
        gauge(&mut out, "olopa_ingest_flush_workers", stats.flush_workers);

        const BOUNDS_MS: [u64; 7] = [5, 10, 25, 50, 100, 500, u64::MAX];
        let mut cumulative = 0u64;
        for (index, bound) in BOUNDS_MS.iter().enumerate() {
            cumulative = cumulative
                .saturating_add(self.flush_duration_buckets[index].load(Ordering::Relaxed));
            let label = if *bound == u64::MAX {
                "+Inf".to_string()
            } else {
                format!("{:.3}", *bound as f64 / 1_000.0)
            };
            out.push_str(&format!(
                "olopa_ingest_flush_duration_seconds_bucket{{le=\"{label}\"}} {cumulative}\n"
            ));
        }
        out.push_str(&format!(
            "olopa_ingest_flush_duration_seconds_sum {:.6}\n",
            self.flush_duration_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
        ));
        out.push_str(&format!(
            "olopa_ingest_flush_duration_seconds_count {}\n",
            self.flush_duration_count.load(Ordering::Relaxed)
        ));
        out
    }

    fn observe_flush_duration(&self, elapsed: Duration) {
        let millis = elapsed.as_millis().try_into().unwrap_or(u64::MAX);
        let micros = elapsed.as_micros().try_into().unwrap_or(u64::MAX);
        let index = [5u64, 10, 25, 50, 100, 500, u64::MAX]
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(6);
        self.flush_duration_buckets[index].fetch_add(1, Ordering::Relaxed);
        self.flush_duration_count.fetch_add(1, Ordering::Relaxed);
        self.flush_duration_sum_micros
            .fetch_add(micros, Ordering::Relaxed);
    }

    /// Return most recent flushed rows (newest first), capped by `limit`.
    pub async fn recent_rows(&self, limit: usize) -> RecentIngestResponse {
        let state = self.state.lock().await;
        let total_available = state.recent_rows.len();
        let requested = limit.max(1).min(self.cfg.recent_events_max.max(1));
        let rows = state
            .recent_rows
            .iter()
            .rev()
            .take(requested)
            .cloned()
            .collect::<Vec<_>>();

        RecentIngestResponse {
            total_available,
            returned: rows.len(),
            rows,
        }
    }

    /// Return recent rows for a single tenant (newest first), capped by `limit`.
    pub async fn recent_rows_for_tenant(
        &self,
        limit: usize,
        tenant_id: &str,
    ) -> RecentIngestResponse {
        let state = self.state.lock().await;
        let requested = limit.max(1).min(self.cfg.recent_events_max.max(1));
        let rows = state
            .recent_rows
            .iter()
            .rev()
            .filter(|row| row.tenant_id == tenant_id)
            .take(requested)
            .cloned()
            .collect::<Vec<_>>();
        let total_available = state
            .recent_rows
            .iter()
            .filter(|row| row.tenant_id == tenant_id)
            .count();

        RecentIngestResponse {
            total_available,
            returned: rows.len(),
            rows,
        }
    }

    /// Return aggregate counters built from all successfully flushed rows.
    pub async fn data_summary(&self) -> IngestDataSummaryResponse {
        let state = self.state.lock().await;
        IngestDataSummaryResponse {
            total_rows: state.total_rows,
            by_kind: state.by_kind.clone(),
            by_tenant: state.by_tenant.clone(),
            by_host: state.by_host.clone(),
        }
    }

    /// Return aggregate counters for one tenant only.
    pub async fn data_summary_for_tenant(&self, tenant_id: &str) -> IngestDataSummaryResponse {
        let state = self.state.lock().await;
        let total_rows = state.by_tenant.get(tenant_id).copied().unwrap_or(0);
        let by_kind = state
            .by_kind_by_tenant
            .get(tenant_id)
            .cloned()
            .unwrap_or_default();
        let by_host = state
            .by_host_by_tenant
            .get(tenant_id)
            .cloned()
            .unwrap_or_default();
        let mut by_tenant = HashMap::new();
        if total_rows > 0 {
            by_tenant.insert(tenant_id.to_string(), total_rows);
        }

        IngestDataSummaryResponse {
            total_rows,
            by_kind,
            by_tenant,
            by_host,
        }
    }

    /// Gracefully stop worker and wait for completion.
    ///
    /// Any pending batches already buffered by the worker are flushed before exit.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        for handle in self.worker_handles.lock().await.drain(..) {
            let _ = handle.await;
        }
        self.workers_started.store(0, Ordering::Release);
        let durable = Arc::clone(&self.durable);
        match tokio::task::spawn_blocking(move || durable.compact()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(error = %err, "final ingest WAL compaction failed"),
            Err(err) => error!(error = %err, "final ingest WAL compaction worker failed"),
        }
    }
}

/// Current wall-clock UNIX timestamp in milliseconds.
fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_millis() as u64,
        Err(_) => 0,
    }
}

fn retry_jitter_ms(attempt: u32, delay: u64) -> u64 {
    if delay <= 1 {
        return 0;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or(0);
    (nanos ^ attempt as u64).wrapping_mul(0x9E37_79B9) % (delay / 4).max(1)
}

async fn probe_append_path(path: &str) -> bool {
    let path = std::path::Path::new(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if create_dir_all(parent).await.is_err() {
            return false;
        }
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .is_ok()
}

fn metric(out: &mut String, name: &str, value: u64) {
    out.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
}

fn gauge(out: &mut String, name: &str, value: usize) {
    out.push_str(&format!("# TYPE {name} gauge\n{name} {value}\n"));
}

/// Convert queue occupancy to normalized pressure ratio `[0, 1]`.
fn throttle_ratio(queued: usize, max: usize) -> f32 {
    if max == 0 {
        return 1.0;
    }
    (queued as f32 / max as f32).clamp(0.0, 1.0)
}

/// Flatten queued batches into JSONEachRow-compatible event rows.
///
/// Each output row contains shared envelope metadata (`tenant_id`, `host_id`,
/// `schema_version`, `batch_id`, ingest timestamp) and one concrete event body.
fn build_persist_rows(
    pending_batches: &[QueuedBatch],
) -> Result<Vec<PersistRow>, serde_json::Error> {
    let mut rows = Vec::new();
    let ingested_at_unix_ms = now_unix_ms();

    for batch in pending_batches {
        let tenant_id = &batch.payload.tenant_id;
        let host_id = &batch.payload.host_id;
        let schema_version = batch.payload.schema_version;
        let batch_id = batch.payload.batch_id.as_deref();

        for event in &batch.payload.process_exec_events {
            let event_json = serde_json::to_value(event)?;
            let line = serde_json::to_string(&json!({
                "tenant_id": tenant_id,
                "host_id": host_id,
                "schema_version": schema_version,
                "batch_id": batch_id,
                "ingested_at_unix_ms": ingested_at_unix_ms,
                "event_kind": "process_exec",
                "event": event,
            }))?;
            rows.push(PersistRow {
                line,
                recent: RecentIngestRow {
                    tenant_id: tenant_id.to_string(),
                    host_id: host_id.to_string(),
                    batch_id: batch.payload.batch_id.clone(),
                    event_kind: "process_exec".to_string(),
                    ingested_at_unix_ms,
                    event: event_json,
                },
            });
        }

        for event in &batch.payload.file_events {
            let event_json = serde_json::to_value(event)?;
            let line = serde_json::to_string(&json!({
                "tenant_id": tenant_id,
                "host_id": host_id,
                "schema_version": schema_version,
                "batch_id": batch_id,
                "ingested_at_unix_ms": ingested_at_unix_ms,
                "event_kind": "file",
                "event": event,
            }))?;
            rows.push(PersistRow {
                line,
                recent: RecentIngestRow {
                    tenant_id: tenant_id.to_string(),
                    host_id: host_id.to_string(),
                    batch_id: batch.payload.batch_id.clone(),
                    event_kind: "file".to_string(),
                    ingested_at_unix_ms,
                    event: event_json,
                },
            });
        }

        for event in &batch.payload.net_events {
            let event_json = serde_json::to_value(event)?;
            let line = serde_json::to_string(&json!({
                "tenant_id": tenant_id,
                "host_id": host_id,
                "schema_version": schema_version,
                "batch_id": batch_id,
                "ingested_at_unix_ms": ingested_at_unix_ms,
                "event_kind": "net",
                "event": event,
            }))?;
            rows.push(PersistRow {
                line,
                recent: RecentIngestRow {
                    tenant_id: tenant_id.to_string(),
                    host_id: host_id.to_string(),
                    batch_id: batch.payload.batch_id.clone(),
                    event_kind: "net".to_string(),
                    ingested_at_unix_ms,
                    event: event_json,
                },
            });
        }

        for event in &batch.payload.db_query_events {
            let event_json = serde_json::to_value(event)?;
            let line = serde_json::to_string(&json!({
                "tenant_id": tenant_id,
                "host_id": host_id,
                "schema_version": schema_version,
                "batch_id": batch_id,
                "ingested_at_unix_ms": ingested_at_unix_ms,
                "event_kind": "db_query",
                "event": event,
            }))?;
            rows.push(PersistRow {
                line,
                recent: RecentIngestRow {
                    tenant_id: tenant_id.to_string(),
                    host_id: host_id.to_string(),
                    batch_id: batch.payload.batch_id.clone(),
                    event_kind: "db_query".to_string(),
                    ingested_at_unix_ms,
                    event: event_json,
                },
            });
        }

        for event in &batch.payload.agent_heartbeats {
            let event_json = serde_json::to_value(event)?;
            let line = serde_json::to_string(&json!({
                "tenant_id": tenant_id,
                "host_id": host_id,
                "schema_version": schema_version,
                "batch_id": batch_id,
                "ingested_at_unix_ms": ingested_at_unix_ms,
                "event_kind": "agent_heartbeat",
                "event": event,
            }))?;
            rows.push(PersistRow {
                line,
                recent: RecentIngestRow {
                    tenant_id: tenant_id.to_string(),
                    host_id: host_id.to_string(),
                    batch_id: batch.payload.batch_id.clone(),
                    event_kind: "agent_heartbeat".to_string(),
                    ingested_at_unix_ms,
                    event: event_json,
                },
            });
        }
    }

    Ok(rows)
}

/// Truncate long error bodies for logs while preserving UTF-8 boundaries.
fn truncate_for_log(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }
    if max_len == 0 {
        return "...".to_string();
    }

    let mut end = max_len.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &input[..end])
}

fn is_valid_surreal_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn build_surreal_insert_sql(rows: &[PersistRow], table: &str) -> String {
    rows.iter()
        .map(|row| format!("INSERT INTO {table} CONTENT {};", row.line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_surreal_error(body: &str) -> Option<String> {
    if body.trim().is_empty() {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let entries = parsed.as_array()?;
    for entry in entries {
        if entry.get("status").and_then(|v| v.as_str()) == Some("ERR") {
            let message = entry
                .get("result")
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_else(|| "unknown surrealdb error".to_string());
            return Some(truncate_for_log(&message, 512));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static TEST_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);

    fn test_config() -> IngestConfig {
        let id = TEST_RUNTIME_ID.fetch_add(1, AtomicOrdering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "olopa-ingest-runtime-{}-{id}-{nonce}",
            std::process::id()
        ));
        IngestConfig {
            flush_workers: 1,
            wal_path: base.with_extension("wal").to_string_lossy().into_owned(),
            dedupe_path: base.with_extension("dedupe").to_string_lossy().into_owned(),
            persist_jsonl_path: base.with_extension("jsonl").to_string_lossy().into_owned(),
            dead_letter_path: base.with_extension("dlq").to_string_lossy().into_owned(),
            ..IngestConfig::default()
        }
    }

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
            db_query_events: Vec::new(),
            agent_heartbeats: Vec::new(),
        }
    }

    async fn wait_for_flush(runtime: &IngestRuntime, minimum_rows: u64) {
        for _ in 0..200 {
            if runtime.stats().flushed_total >= minimum_rows {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("flush did not complete: stats={:?}", runtime.stats());
    }

    #[tokio::test]
    async fn ack_accepts_and_tracks_queue_depth() {
        let cfg = IngestConfig {
            queue_maxsize: 4,
            flush_interval_ms: 2000,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
            recent_events_max: 100,
            ..test_config()
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
            recent_events_max: 100,
            ..test_config()
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));

        let first = runtime.ack_batch(test_batch());
        assert!(first.accepted);

        let mut second_batch = test_batch();
        second_batch.batch_id = Some("test-batch-2".to_string());
        let second = runtime.ack_batch(second_batch);
        assert!(!second.accepted);
        assert_eq!(second.rejected, 1);
    }

    #[test]
    fn duplicate_batch_id_is_acknowledged_without_requeueing() {
        let runtime = IngestRuntime::new(IngestConfig {
            queue_maxsize: 4,
            dedupe_max_entries: 16,
            ..test_config()
        });

        let first = runtime.ack_batch(test_batch());
        let duplicate = runtime.ack_batch(test_batch());

        assert!(first.accepted);
        assert!(!first.duplicate);
        assert!(duplicate.accepted);
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.rejected, 0);
        let stats = runtime.stats();
        assert_eq!(stats.queued, 1);
        assert_eq!(stats.accepted_total, 1);
        assert_eq!(stats.duplicate_total, 1);
    }

    #[test]
    fn batch_id_scope_includes_tenant_and_host() {
        let runtime = IngestRuntime::new(IngestConfig {
            queue_maxsize: 4,
            dedupe_max_entries: 16,
            ..test_config()
        });
        let first = test_batch();
        let mut other_host = test_batch();
        other_host.host_id = "host-02".to_string();

        assert!(!runtime.ack_batch(first).duplicate);
        assert!(!runtime.ack_batch(other_host).duplicate);
        assert_eq!(runtime.stats().queued, 2);
    }

    #[test]
    fn dedupe_index_is_bounded_and_evicts_oldest_key() {
        let runtime = IngestRuntime::new(IngestConfig {
            queue_maxsize: 4,
            dedupe_max_entries: 1,
            ..test_config()
        });
        let first = test_batch();
        let mut second = test_batch();
        second.batch_id = Some("test-batch-2".to_string());

        assert!(!runtime.ack_batch(first.clone()).duplicate);
        assert!(!runtime.ack_batch(second).duplicate);
        assert!(
            !runtime.ack_batch(first).duplicate,
            "oldest key should be accepted again after bounded eviction"
        );
        assert_eq!(runtime.stats().queued, 3);
    }

    #[test]
    fn concurrent_retries_enqueue_exactly_once() {
        use std::sync::Barrier;
        use std::thread;

        const RETRIES: usize = 8;
        let runtime = Arc::new(IngestRuntime::new(IngestConfig {
            queue_maxsize: RETRIES + 1,
            dedupe_max_entries: 16,
            ..test_config()
        }));
        let barrier = Arc::new(Barrier::new(RETRIES));
        let handles = (0..RETRIES)
            .map(|_| {
                let runtime = Arc::clone(&runtime);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    runtime.ack_batch(test_batch())
                })
            })
            .collect::<Vec<_>>();
        let acknowledgements = handles
            .into_iter()
            .map(|handle| handle.join().expect("retry thread"))
            .collect::<Vec<_>>();

        assert_eq!(
            acknowledgements.iter().filter(|ack| !ack.duplicate).count(),
            1
        );
        assert!(acknowledgements.iter().all(|ack| ack.accepted));
        assert_eq!(runtime.stats().queued, 1);
        assert_eq!(runtime.stats().duplicate_total, (RETRIES - 1) as u64);
    }

    #[tokio::test]
    async fn worker_flushes_pending_batches() {
        let cfg = IngestConfig {
            queue_maxsize: 8,
            flush_interval_ms: 30,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
            recent_events_max: 100,
            ..test_config()
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;

        let ack = runtime.ack_batch(test_batch());
        assert!(ack.accepted);

        wait_for_flush(&runtime, 1).await;
        let stats = runtime.stats();
        assert_eq!(stats.queued, 0);
        assert!(stats.flushed_total >= 1);

        runtime.shutdown().await;
    }

    #[test]
    fn build_persist_rows_flattens_all_event_families() {
        let mut batch = test_batch();
        batch.file_events.push(FileEvent {
            pid: 1,
            tgid: 1,
            uid: 0,
            gid: 0,
            comm: "touch".to_string(),
            operation: "write".to_string(),
            path: "/tmp/a".to_string(),
            attrs: HashMap::new(),
        });
        batch.net_events.push(NetEvent {
            pid: 2,
            tgid: 2,
            uid: 0,
            gid: 0,
            comm: "curl".to_string(),
            direction: "outbound".to_string(),
            protocol: "tcp".to_string(),
            src_ip: None,
            dst_ip: Some("1.1.1.1".to_string()),
            src_port: None,
            dst_port: Some(443),
            attrs: HashMap::new(),
        });
        batch.db_query_events.push(sample_db_query_event());
        batch.agent_heartbeats.push(AgentHeartbeat {
            agent_version: "v1".to_string(),
            kernel_version: "k".to_string(),
            events_read_total: 1,
            events_dropped_total: 0,
            queue_depth: 0,
            attrs: HashMap::new(),
        });

        let queued = vec![QueuedBatch {
            sequence: 1,
            rows: batch.row_count(),
            payload: batch,
        }];

        let rows = build_persist_rows(&queued).expect("rows");
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].recent.event_kind, "process_exec");
        assert_eq!(rows[1].recent.event_kind, "file");
        assert_eq!(rows[2].recent.event_kind, "net");
        assert_eq!(rows[3].recent.event_kind, "db_query");
        assert_eq!(rows[4].recent.event_kind, "agent_heartbeat");

        let db_row = &rows[3].recent.event;
        assert_eq!(db_row["db_engine"], "postgresql");
        assert_eq!(db_row["operation"], "select");
        assert_eq!(db_row["statement_fingerprint"], "deadbeef");
    }

    fn sample_db_query_event() -> DbQueryEvent {
        DbQueryEvent {
            pid: 900,
            tgid: 900,
            uid: 1000,
            gid: 1000,
            comm: "psql".to_string(),
            db_engine: "postgresql".to_string(),
            db_server: Some("unknown:5432".to_string()),
            database: None,
            operation: "select".to_string(),
            tables: Vec::new(),
            statement_fingerprint: "deadbeef".to_string(),
            attrs: HashMap::new(),
        }
    }

    #[test]
    fn db_query_events_are_optional_for_v1_senders() {
        // A schema-version-1 payload has no `db_query_events` key at all.
        let body = r#"{
            "tenant_id": "acme",
            "host_id": "host-01",
            "schema_version": 1,
            "process_exec_events": [
                {"pid":1,"tgid":1,"uid":0,"comm":"bash","filename":"/bin/bash"}
            ]
        }"#;
        let parsed: IngestBatchRequest = serde_json::from_str(body).expect("parse v1 batch");
        assert!(parsed.db_query_events.is_empty());
        assert_eq!(parsed.row_count(), 1);
    }

    #[tokio::test]
    async fn db_query_rows_reach_recent_and_summary_apis() {
        let cfg = IngestConfig {
            queue_maxsize: 8,
            flush_interval_ms: 30,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
            recent_events_max: 16,
            ..test_config()
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;

        let mut batch = test_batch();
        batch.process_exec_events.clear();
        batch.db_query_events.push(sample_db_query_event());
        assert!(runtime.ack_batch(batch).accepted);

        wait_for_flush(&runtime, 1).await;

        let recent = runtime.recent_rows(10).await;
        assert_eq!(recent.returned, 1);
        assert_eq!(recent.rows[0].event_kind, "db_query");
        assert_eq!(recent.rows[0].event["comm"], "psql");

        let summary = runtime.data_summary().await;
        assert_eq!(summary.by_kind.get("db_query").copied(), Some(1));

        runtime.shutdown().await;
    }

    #[test]
    fn surreal_insert_sql_contains_insert_per_row() {
        let queued = vec![QueuedBatch {
            sequence: 1,
            rows: test_batch().row_count(),
            payload: test_batch(),
        }];
        let rows = build_persist_rows(&queued).expect("rows");
        let sql = build_surreal_insert_sql(&rows, "events_raw");
        assert!(sql.contains("INSERT INTO events_raw CONTENT"));
        assert_eq!(
            sql.matches("INSERT INTO events_raw CONTENT").count(),
            rows.len()
        );
    }

    #[test]
    fn surreal_error_parser_detects_err_status() {
        let body = r#"[{"status":"OK","result":[]},{"status":"ERR","result":"bad query"}]"#;
        let err = extract_surreal_error(body);
        assert_eq!(err.as_deref(), Some("bad query"));
    }

    #[tokio::test]
    async fn recent_rows_and_summary_are_populated_after_flush() {
        let cfg = IngestConfig {
            queue_maxsize: 8,
            flush_interval_ms: 30,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
            recent_events_max: 16,
            ..test_config()
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;

        let ack = runtime.ack_batch(test_batch());
        assert!(ack.accepted);

        wait_for_flush(&runtime, 1).await;

        let recent = runtime.recent_rows(10).await;
        assert!(recent.returned >= 1);
        assert_eq!(recent.rows[0].event_kind, "process_exec");
        assert_eq!(recent.rows[0].tenant_id, "acme");

        let summary = runtime.data_summary().await;
        assert!(summary.total_rows >= 1);
        assert!(summary.by_kind.get("process_exec").copied().unwrap_or(0) >= 1);
        assert!(summary.by_tenant.get("acme").copied().unwrap_or(0) >= 1);

        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn tenant_scoped_recent_and_summary_filter_rows() {
        let cfg = IngestConfig {
            queue_maxsize: 8,
            flush_interval_ms: 30,
            flush_max_rows: 1000,
            default_retry_after_ms: 500,
            suggested_batch_bytes: 4_000_000,
            recent_events_max: 16,
            ..test_config()
        };
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;

        let first = test_batch();
        assert!(runtime.ack_batch(first).accepted);

        let mut second = test_batch();
        second.tenant_id = "globex".to_string();
        second.host_id = "host-02".to_string();
        second.process_exec_events[0].pid = 777;
        assert!(runtime.ack_batch(second).accepted);

        wait_for_flush(&runtime, 2).await;

        let recent_acme = runtime.recent_rows_for_tenant(10, "acme").await;
        assert!(recent_acme.returned >= 1);
        assert!(recent_acme.rows.iter().all(|r| r.tenant_id == "acme"));

        let recent_globex = runtime.recent_rows_for_tenant(10, "globex").await;
        assert!(recent_globex.returned >= 1);
        assert!(recent_globex.rows.iter().all(|r| r.tenant_id == "globex"));

        let summary_acme = runtime.data_summary_for_tenant("acme").await;
        assert_eq!(summary_acme.total_rows, 1);
        assert_eq!(summary_acme.by_tenant.get("acme").copied(), Some(1));
        assert!(!summary_acme.by_tenant.contains_key("globex"));

        let summary_globex = runtime.data_summary_for_tenant("globex").await;
        assert_eq!(summary_globex.total_rows, 1);
        assert_eq!(summary_globex.by_tenant.get("globex").copied(), Some(1));
        assert!(!summary_globex.by_tenant.contains_key("acme"));

        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn uncommitted_wal_batch_replays_after_runtime_restart() {
        let mut cfg = test_config();
        cfg.flush_interval_ms = 20;
        cfg.wal_compact_after_commits = 1;

        let first = IngestRuntime::new(cfg.clone());
        let accepted = first.ack_batch(test_batch());
        assert!(accepted.accepted);
        assert_eq!(first.stats().wal_pending, 1);
        drop(first);

        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;
        wait_for_flush(&runtime, 1).await;
        assert_eq!(runtime.stats().replayed_total, 1);
        assert_eq!(runtime.stats().wal_pending, 0);
        assert!(runtime.ack_batch(test_batch()).duplicate);
        runtime.shutdown().await;
    }

    #[test]
    fn global_queue_bound_holds_across_worker_partitions() {
        let runtime = IngestRuntime::new(IngestConfig {
            queue_maxsize: 2,
            flush_workers: 4,
            ..test_config()
        });
        for index in 0..2 {
            let mut batch = test_batch();
            batch.host_id = format!("host-{index}");
            batch.batch_id = Some(format!("batch-{index}"));
            assert!(runtime.ack_batch(batch).accepted);
        }
        let mut overflow = test_batch();
        overflow.host_id = "host-overflow".to_string();
        overflow.batch_id = Some("batch-overflow".to_string());
        assert!(!runtime.ack_batch(overflow).accepted);
        assert_eq!(runtime.stats().queued, 2);
    }

    #[tokio::test]
    async fn configured_partition_workers_start_and_report_ready() {
        let runtime = Arc::new(IngestRuntime::new(IngestConfig {
            flush_workers: 3,
            queue_maxsize: 30,
            ..test_config()
        }));
        runtime.start_worker().await;
        assert_eq!(runtime.stats().flush_workers, 3);
        let ready = runtime.readiness().await;
        assert!(ready.ready, "readiness detail: {ready:?}");
        assert!(runtime
            .prometheus_metrics()
            .contains("olopa_ingest_flush_duration_seconds_bucket"));
        runtime.shutdown().await;
    }

    #[test]
    fn rejects_unsupported_schema_versions_and_malformed_payloads() {
        let runtime = IngestRuntime::new(test_config());
        let mut future = test_batch();
        future.schema_version = 99;
        let ack = runtime.ack_batch(future);
        assert!(!ack.accepted);
        assert!(ack.message.unwrap_or_default().contains("unsupported"));

        let malformed = r#"{"tenant_id":"acme","host_id":7,"process_exec_events":[]}"#;
        assert!(serde_json::from_str::<IngestBatchRequest>(malformed).is_err());
    }

    #[test]
    fn circuit_breaker_opens_and_allows_a_half_open_probe() {
        let mut breaker = CircuitBreaker::default();
        assert!(breaker.allow());
        assert!(breaker.failure(1, Duration::from_millis(10)));
        assert!(breaker.is_open());
        assert!(!breaker.allow());
        std::thread::sleep(Duration::from_millis(15));
        assert!(breaker.allow());
        breaker.success();
        assert!(!breaker.is_open());
    }

    #[tokio::test]
    async fn transient_sink_failures_retry_open_circuit_and_use_jsonl_fallback() {
        let mut cfg = test_config();
        cfg.clickhouse_url = Some("://invalid".to_string());
        cfg.sink_retry_max_attempts = 3;
        cfg.sink_retry_initial_ms = 1;
        cfg.sink_retry_max_ms = 2;
        cfg.circuit_failure_threshold = 1;
        cfg.flush_interval_ms = 10;
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;
        assert!(runtime.ack_batch(test_batch()).accepted);
        wait_for_flush(&runtime, 1).await;
        assert_eq!(runtime.stats().sink_retry_total, 2);
        assert_eq!(runtime.stats().circuit_open_total, 1);
        assert!(runtime.readiness().await.clickhouse_circuit_open);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn permanent_sink_failures_are_dead_lettered() {
        let mut cfg = test_config();
        cfg.surreal_url = Some("http://unused.invalid/sql".to_string());
        cfg.surreal_table = "invalid-table-name".to_string();
        cfg.flush_interval_ms = 10;
        let dead_letter_path = cfg.dead_letter_path.clone();
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;
        assert!(runtime.ack_batch(test_batch()).accepted);
        wait_for_flush(&runtime, 1).await;
        assert_eq!(runtime.stats().dead_letter_total, 1);
        let contents = std::fs::read_to_string(dead_letter_path).expect("dead letter contents");
        assert!(contents.contains("permanent surreal failure"));
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn partitioned_workers_flush_sustained_load_without_corrupting_jsonl() {
        const BATCHES: u64 = 24;
        let mut cfg = test_config();
        cfg.flush_workers = 4;
        cfg.queue_maxsize = 128;
        cfg.flush_max_rows = 8;
        cfg.flush_interval_ms = 10;
        let jsonl_path = cfg.persist_jsonl_path.clone();
        let runtime = Arc::new(IngestRuntime::new(cfg));
        runtime.start_worker().await;
        for index in 0..BATCHES {
            let mut batch = test_batch();
            batch.host_id = format!("host-{}", index % 16);
            batch.batch_id = Some(format!("load-{index}"));
            batch.process_exec_events[0].pid = index as u32 + 1;
            assert!(runtime.ack_batch(batch).accepted);
        }
        wait_for_flush(&runtime, BATCHES).await;
        runtime.shutdown().await;

        let contents = std::fs::read_to_string(jsonl_path).expect("load-test JSONL");
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), BATCHES as usize);
        assert!(lines
            .iter()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()));
    }
}
