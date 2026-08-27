use anyhow::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use crate::agent::{SenderLike, SenderStats, TelemetryWireEvent};
use crate::data::batcher_compressor::{BatchParser, DictDecompressor};
use crate::transport::durable_spool::DurableSpool;

const ALERT_MAGIC: &[u8; 4] = b"OLRT";
/// Oldest alert wire version this sender still decodes.
const ALERT_WIRE_VERSION_MIN: u16 = 1;
/// Alert wire version that carries the SQL/TLS/DNS extension block.
const ALERT_WIRE_VERSION_EXT: u16 = 2;
/// Alert wire version that carries stable kernel cgroup identity.
const ALERT_WIRE_VERSION_CGROUP: u16 = 3;

/// Ring-buffer event type discriminants shared with `agent::IngestEvent`.
const EVENT_TYPE_FILE: u8 = 2;
const EVENT_TYPE_NET: u8 = 3;
const EVENT_TYPE_SQL: u8 = 4;
const EVENT_TYPE_SSL: u8 = 5;
const EVENT_TYPE_DNS: u8 = 6;
const EVENT_TYPE_TC: u8 = 7;

#[derive(Clone, Debug)]
struct HttpSenderConfig {
    ingest_url: String,
    tenant_id: String,
    host_id: String,
    auth: Option<HttpSenderAuth>,
    spool_path: PathBuf,
    spool_max_bytes: u64,
    queue_capacity: usize,
    retry_min: Duration,
    retry_max: Duration,
}

#[derive(Clone, Debug)]
enum HttpSenderAuth {
    BearerToken(String),
    ApiKey(String),
}

impl HttpSenderConfig {
    fn from_env() -> Self {
        let auth = env_non_empty("OLOPA_INGEST_API_TOKEN")
            .map(HttpSenderAuth::BearerToken)
            .or_else(|| env_non_empty("OLOPA_INGEST_API_KEY").map(HttpSenderAuth::ApiKey));
        Self {
            ingest_url: std::env::var("OLOPA_INGEST_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8000/api/v1/ingest/batches".to_string()),
            tenant_id: std::env::var("OLOPA_INGEST_TENANT_ID")
                .unwrap_or_else(|_| "default".to_string()),
            host_id: std::env::var("OLOPA_INGEST_HOST_ID")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "agent-local".to_string()),
            auth,
            spool_path: env_non_empty("OLOPA_HTTP_SPOOL_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/olopa/http-spool.bin")),
            spool_max_bytes: env_parse_or("OLOPA_HTTP_SPOOL_MAX_BYTES", 2 * 1024 * 1024 * 1024),
            queue_capacity: env_parse_or("OLOPA_HTTP_QUEUE_CAPACITY", 256usize).max(1),
            retry_min: Duration::from_millis(
                env_parse_or("OLOPA_HTTP_RETRY_MIN_MS", 250u64).max(1),
            ),
            retry_max: Duration::from_millis(
                env_parse_or("OLOPA_HTTP_RETRY_MAX_MS", 60_000u64).max(1),
            ),
        }
    }

    #[cfg(test)]
    fn for_mapping(tenant_id: &str, host_id: &str) -> Self {
        Self {
            ingest_url: "http://127.0.0.1:8000/api/v1/ingest/batches".to_string(),
            tenant_id: tenant_id.to_string(),
            host_id: host_id.to_string(),
            auth: None,
            spool_path: PathBuf::from("unused-in-mapping-tests"),
            spool_max_bytes: 1024 * 1024,
            queue_capacity: 8,
            retry_min: Duration::from_millis(10),
            retry_max: Duration::from_secs(1),
        }
    }
}

#[derive(Default)]
struct SharedSenderState {
    spool_pending_bytes: AtomicU64,
    spooling: AtomicBool,
    backend_reachable: AtomicBool,
    backend_reachability_known: AtomicBool,
    backend_rtt_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
struct IngestBatchRequest {
    tenant_id: String,
    host_id: String,
    schema_version: u16,
    batch_id: Option<String>,
    process_exec_events: Vec<ProcessExecEvent>,
    file_events: Vec<FileEvent>,
    net_events: Vec<NetEvent>,
    db_query_events: Vec<DbQueryEvent>,
    agent_heartbeats: Vec<AgentHeartbeat>,
}

impl IngestBatchRequest {
    fn new(cfg: &HttpSenderConfig, batch_id: String) -> Self {
        Self {
            tenant_id: cfg.tenant_id.clone(),
            host_id: cfg.host_id.clone(),
            schema_version: 2,
            batch_id: Some(batch_id),
            process_exec_events: Vec::new(),
            file_events: Vec::new(),
            net_events: Vec::new(),
            db_query_events: Vec::new(),
            agent_heartbeats: Vec::new(),
        }
    }

    fn row_count(&self) -> usize {
        self.process_exec_events.len()
            + self.file_events.len()
            + self.net_events.len()
            + self.db_query_events.len()
            + self.agent_heartbeats.len()
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProcessExecEvent {
    pid: u32,
    tgid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
    attrs: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct FileEvent {
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    operation: String,
    path: String,
    attrs: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct NetEvent {
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    direction: String,
    protocol: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    attrs: HashMap<String, String>,
}

/// Normalized database query event derived from SQL client uprobes.
/// Statement text is redacted before this boundary; only its fingerprint and
/// derived database/table names are serialized.
#[derive(Debug, Clone, Serialize)]
struct DbQueryEvent {
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    /// `postgresql` / `mysql` / `unknown`, inferred from the observed port.
    db_engine: String,
    /// `host:port` of the database endpoint when the port is known.
    db_server: Option<String>,
    database: Option<String>,
    /// `select` / `dml` / `ddl` / `admin` / `other`.
    operation: String,
    tables: Vec<String>,
    /// Stable hash of the statement text, hex-encoded.
    statement_fingerprint: String,
    attrs: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentHeartbeat {
    agent_version: String,
    kernel_version: String,
    events_read_total: u64,
    events_dropped_total: u64,
    queue_depth: u32,
    attrs: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AckResponse {
    accepted: bool,
    #[serde(default)]
    retry_after_ms: u32,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct DecodedAlert {
    event_type: u8,
    sql_policy_verdict: u8,
    ts_ns: u64,
    pid: u32,
    uid: u32,
    vertex_id: u32,
    dst_vertex_id: u32,
    comm_id: u32,
    risk_score: f32,
    rule_id: String,
    rule_name: String,
    cgroup_id: u64,
    /// Present only for v2+ payloads; `None` for legacy v1 senders.
    ext: Option<AlertExt>,
}

/// Per-family detail carried by the v2 alert extension block.
#[derive(Debug, Clone, Default)]
struct AlertExt {
    comm: String,
    sql_query_hash: u32,
    sql_query_class: u8,
    sql_db_port: u16,
    ssl_data_len: u32,
    ssl_operation: u8,
    dns_query_hash: u32,
    dns_query: String,
    /// Fingerprint over the redacted statement, so the same statement shape
    /// with different literals groups together.
    sql_norm_hash: u32,
    /// Comma-separated table names derived from the redacted statement.
    sql_tables: String,
}

impl DecodedAlert {
    /// Real process name when the sender got a v2 payload, else the legacy
    /// `comm_id_<hash>` placeholder.
    fn comm_label(&self) -> String {
        match self.ext.as_ref() {
            Some(ext) if !ext.comm.is_empty() => ext.comm.clone(),
            _ => format!("comm_id_{}", self.comm_id),
        }
    }
}

#[derive(Debug)]
struct SpoolPayload {
    batch_id: String,
    payload: Vec<u8>,
}

pub struct HttpIngestSender {
    wake_tx: mpsc::Sender<()>,
    spool: Arc<Mutex<DurableSpool>>,
    batch_sequence: u64,
    shared: Arc<SharedSenderState>,
}

impl HttpIngestSender {
    pub fn from_env() -> Result<Self> {
        let cfg = HttpSenderConfig::from_env();
        let spool = Arc::new(Mutex::new(DurableSpool::open(
            &cfg.spool_path,
            cfg.spool_max_bytes,
        )?));
        let (wake_tx, wake_rx) = mpsc::channel(cfg.queue_capacity);
        let shared = Arc::new(SharedSenderState::default());
        let auth_mode = match &cfg.auth {
            Some(HttpSenderAuth::BearerToken(_)) => "bearer",
            Some(HttpSenderAuth::ApiKey(_)) => "x-api-key",
            None => "none",
        };

        info!(
            "sender: http ingest enabled url={} tenant={} host={} auth={} spool={} spool_max_bytes={}",
            cfg.ingest_url,
            cfg.tenant_id,
            cfg.host_id,
            auth_mode,
            cfg.spool_path.display(),
            cfg.spool_max_bytes,
        );

        update_shared_state(&shared, &spool);
        tokio::spawn(sender_worker(
            wake_rx,
            cfg,
            Arc::clone(&shared),
            Arc::clone(&spool),
        ));
        let _ = wake_tx.try_send(());

        Ok(Self {
            wake_tx,
            spool,
            batch_sequence: 0,
            shared,
        })
    }
}

/// Cloneable emitter for subsystems that ship telemetry outside the sensor
/// hot loop (currently Secure Connect).
///
/// It shares the durable spool with the owning sender, so subsystem events
/// survive restarts and backpressure exactly like sensor events do. Its own
/// batch sequence keeps ids unique without touching the sensor's counter.
#[derive(Clone)]
pub struct SenderHandle {
    wake_tx: mpsc::Sender<()>,
    spool: Arc<Mutex<DurableSpool>>,
    shared: Arc<SharedSenderState>,
    batch_sequence: Arc<AtomicU64>,
}

impl SenderHandle {
    /// Spool one payload and wake the sender worker.
    pub fn emit(&self, payload: Vec<u8>) -> Result<()> {
        let mut seq = self.batch_sequence.fetch_add(1, Ordering::Relaxed);
        let record = SpoolPayload {
            batch_id: next_batch_id(&mut seq),
            payload,
        };
        let encoded = encode_spool_payload(&record)?;
        self.spool
            .lock()
            .map_err(|_| anyhow::anyhow!("HTTP spool lock poisoned"))?
            .append(&encoded)?;
        update_shared_state(&self.shared, &self.spool);
        let _ = self.wake_tx.try_send(());
        Ok(())
    }
}

impl HttpIngestSender {
    /// Hand out an emitter for subsystems that run beside the sensor loop.
    pub fn handle(&self) -> SenderHandle {
        SenderHandle {
            wake_tx: self.wake_tx.clone(),
            spool: self.spool.clone(),
            shared: self.shared.clone(),
            batch_sequence: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl SenderLike for HttpIngestSender {
    fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()> {
        let record = SpoolPayload {
            batch_id: next_batch_id(&mut self.batch_sequence),
            payload,
        };
        let encoded = encode_spool_payload(&record)?;
        self.spool
            .lock()
            .map_err(|_| anyhow::anyhow!("HTTP spool lock poisoned"))?
            .append(&encoded)?;
        update_shared_state(&self.shared, &self.spool);
        // A full notification channel is fine: it already contains a wakeup.
        let _ = self.wake_tx.try_send(());
        Ok(())
    }

    fn stats(&self) -> SenderStats {
        let pending = self.shared.spool_pending_bytes.load(Ordering::Relaxed);
        let spooling = pending > 0 || self.shared.spooling.load(Ordering::Relaxed);
        let reachability_known = self
            .shared
            .backend_reachability_known
            .load(Ordering::Relaxed);
        let backend_reachable = if reachability_known {
            Some(self.shared.backend_reachable.load(Ordering::Relaxed))
        } else {
            None
        };
        let rtt_ms = self.shared.backend_rtt_ms.load(Ordering::Relaxed);
        let backend_rtt_ms = (rtt_ms > 0).then_some(rtt_ms);
        SenderStats {
            spool_pending_bytes: pending,
            spooling,
            backend_reachable,
            backend_rtt_ms,
        }
    }

    fn drain_spool(&mut self, deadline: Instant) -> Result<usize> {
        if Instant::now() < deadline {
            let _ = self.wake_tx.try_send(());
        }
        Ok(0)
    }
}

async fn sender_worker(
    mut wake_rx: mpsc::Receiver<()>,
    cfg: HttpSenderConfig,
    shared: Arc<SharedSenderState>,
    spool: Arc<Mutex<DurableSpool>>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build();

    let client = match client {
        Ok(c) => c,
        Err(err) => {
            warn!("sender: failed to build HTTP client: {}", err);
            shared.spooling.store(true, Ordering::Relaxed);
            return;
        }
    };

    let mut dec = DictDecompressor::new();
    let mut retry_delay = cfg.retry_min.min(cfg.retry_max);
    let mut next_attempt = Some(Instant::now());

    loop {
        tokio::select! {
            wake = wake_rx.recv() => if wake.is_none() { break; },
            _ = async {
                match next_attempt {
                    Some(deadline) => {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {},
        }

        if next_attempt.is_some_and(|deadline| Instant::now() < deadline) {
            continue;
        }
        loop {
            let encoded = match spool.lock() {
                Ok(mut guard) => match guard.peek() {
                    Ok(value) => value,
                    Err(err) => {
                        warn!("sender: failed reading durable spool: {}", err);
                        None
                    }
                },
                Err(_) => {
                    warn!("sender: durable spool lock poisoned");
                    None
                }
            };
            let Some(encoded) = encoded else {
                break;
            };
            let record = match decode_spool_payload(&encoded) {
                Ok(record) => record,
                Err(err) => {
                    warn!("sender: corrupt durable spool record: {}", err);
                    break;
                }
            };
            let mut batches =
                payload_to_batches_with_id(&record.payload, &cfg, &mut dec, &record.batch_id);
            let Some(batch) = batches.pop() else {
                warn!("sender: spool record produced no ingest batch");
                break;
            };
            let started = Instant::now();
            match post_batch(&client, &cfg, &batch).await {
                Ok(()) => {
                    shared
                        .backend_reachability_known
                        .store(true, Ordering::Relaxed);
                    shared.backend_reachable.store(true, Ordering::Relaxed);
                    let rtt_ms = started.elapsed().as_millis() as u64;
                    shared
                        .backend_rtt_ms
                        .store(rtt_ms.max(1), Ordering::Relaxed);
                    match spool.lock() {
                        Ok(mut guard) => {
                            if let Err(err) = guard.acknowledge() {
                                warn!("sender: failed persisting spool acknowledgement: {}", err);
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                    retry_delay = cfg.retry_min.min(cfg.retry_max);
                    next_attempt = Some(Instant::now());
                }
                Err(err) => {
                    shared
                        .backend_reachability_known
                        .store(true, Ordering::Relaxed);
                    shared.backend_reachable.store(false, Ordering::Relaxed);
                    debug!("sender: backlog send paused: {}", err);
                    let server_delay = err.retry_after.unwrap_or_default();
                    let delay = retry_delay.max(server_delay).min(cfg.retry_max);
                    next_attempt = Some(Instant::now() + delay);
                    retry_delay = retry_delay.saturating_mul(2).min(cfg.retry_max);
                    break;
                }
            }
            update_shared_state(&shared, &spool);
        }
        if spool
            .lock()
            .map(|guard| guard.pending_bytes() == 0)
            .unwrap_or(false)
        {
            next_attempt = None;
        }
        update_shared_state(&shared, &spool);
    }
    update_shared_state(&shared, &spool);
}

fn update_shared_state(shared: &SharedSenderState, spool: &Arc<Mutex<DurableSpool>>) {
    let pending = spool
        .lock()
        .map(|guard| guard.pending_bytes())
        .unwrap_or(u64::MAX);
    shared.spool_pending_bytes.store(pending, Ordering::Relaxed);
    shared.spooling.store(pending != 0, Ordering::Relaxed);
}

#[derive(Debug)]
struct PostBatchError {
    message: String,
    retry_after: Option<Duration>,
}

impl std::fmt::Display for PostBatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

async fn post_batch(
    client: &reqwest::Client,
    cfg: &HttpSenderConfig,
    batch: &IngestBatchRequest,
) -> std::result::Result<(), PostBatchError> {
    let mut req = client.post(&cfg.ingest_url).json(batch);
    if let Some(auth) = cfg.auth.as_ref() {
        req = match auth {
            HttpSenderAuth::BearerToken(token) => req.bearer_auth(token),
            HttpSenderAuth::ApiKey(api_key) => req.header("x-api-key", api_key),
        };
    }

    let resp = req.send().await.map_err(|err| PostBatchError {
        message: err.to_string(),
        retry_after: None,
    })?;
    let status = resp.status();
    let header_retry = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs);
    let body = resp.text().await.unwrap_or_default();
    let ack = serde_json::from_str::<AckResponse>(&body).unwrap_or(AckResponse {
        accepted: status.is_success(),
        retry_after_ms: 0,
        message: None,
    });
    let retry_after = (ack.retry_after_ms != 0)
        .then(|| Duration::from_millis(u64::from(ack.retry_after_ms)))
        .or(header_retry);
    if !status.is_success() {
        return Err(PostBatchError {
            message: format!(
                "http status {} body={}",
                status,
                truncate_for_log(&body, 256)
            ),
            retry_after,
        });
    }

    if !ack.accepted {
        return Err(PostBatchError {
            message: format!(
                "server rejected batch retry_after_ms={} message={:?}",
                ack.retry_after_ms, ack.message
            ),
            retry_after,
        });
    }

    Ok(())
}

fn env_parse_or<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    env_non_empty(key)
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn encode_spool_payload(record: &SpoolPayload) -> Result<Vec<u8>> {
    let id = record.batch_id.as_bytes();
    let id_len = u16::try_from(id.len())
        .map_err(|_| anyhow::anyhow!("batch id is too long for spool record"))?;
    let mut encoded = Vec::with_capacity(3 + id.len() + record.payload.len());
    encoded.push(1);
    encoded.extend_from_slice(&id_len.to_be_bytes());
    encoded.extend_from_slice(id);
    encoded.extend_from_slice(&record.payload);
    Ok(encoded)
}

fn decode_spool_payload(encoded: &[u8]) -> Result<SpoolPayload> {
    if encoded.first().copied() != Some(1) || encoded.len() < 3 {
        anyhow::bail!("unsupported or truncated HTTP spool record");
    }
    let id_len = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
    let id_end = 3usize
        .checked_add(id_len)
        .filter(|end| *end <= encoded.len())
        .ok_or_else(|| anyhow::anyhow!("truncated batch id in HTTP spool record"))?;
    let batch_id = std::str::from_utf8(&encoded[3..id_end])?.to_string();
    if batch_id.is_empty() {
        anyhow::bail!("empty batch id in HTTP spool record");
    }
    Ok(SpoolPayload {
        batch_id,
        payload: encoded[id_end..].to_vec(),
    })
}

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

fn payload_to_batches(
    payload: &[u8],
    cfg: &HttpSenderConfig,
    dec: &mut DictDecompressor,
    seq: &mut u64,
) -> Vec<IngestBatchRequest> {
    let batch_id = next_batch_id(seq);
    payload_to_batches_with_id(payload, cfg, dec, &batch_id)
}

fn payload_to_batches_with_id(
    payload: &[u8],
    cfg: &HttpSenderConfig,
    dec: &mut DictDecompressor,
    batch_id: &str,
) -> Vec<IngestBatchRequest> {
    if let Some(alert) = decode_alert_payload(payload) {
        let mut batch = IngestBatchRequest::new(cfg, batch_id.to_string());
        append_alert_to_batch(&mut batch, &alert);
        return vec![batch];
    }

    if let Ok(mut parser) = BatchParser::new(payload) {
        let mut batch = IngestBatchRequest::new(cfg, batch_id.to_string());
        let default_cap = (parser.header.raw_bytes as usize).max(2048);

        while let Some(frame) = parser.next_frame() {
            if let Some(raw) = try_decompress_frame(dec, frame, default_cap) {
                let line = String::from_utf8_lossy(&raw);
                append_line_to_batch(&mut batch, line.trim());
            } else {
                append_unknown_payload_heartbeat(
                    &mut batch,
                    "batch_frame_decode_error",
                    frame.len(),
                );
            }
        }

        if batch.row_count() == 0 {
            append_unknown_payload_heartbeat(&mut batch, "empty_batch_payload", payload.len());
        }
        return vec![batch];
    }

    if let Ok(text) = std::str::from_utf8(payload) {
        let mut batch = IngestBatchRequest::new(cfg, batch_id.to_string());
        append_line_to_batch(&mut batch, text.trim());
        if batch.row_count() == 0 {
            append_unknown_payload_heartbeat(&mut batch, "text_payload_no_rows", payload.len());
        }
        return vec![batch];
    }

    let mut batch = IngestBatchRequest::new(cfg, batch_id.to_string());
    append_unknown_payload_heartbeat(&mut batch, "binary_payload", payload.len());
    vec![batch]
}

#[cfg(test)]
pub(crate) fn payload_to_batches_for_tests(
    payload: &[u8],
    tenant_id: &str,
    host_id: &str,
) -> Vec<serde_json::Value> {
    // Reuse the real sender mapping logic so e2e tests validate the exact
    // wire shape that would be posted to ingest in production.
    let cfg = HttpSenderConfig::for_mapping(tenant_id, host_id);
    let mut dec = DictDecompressor::new();
    let mut seq = 0u64;
    payload_to_batches(payload, &cfg, &mut dec, &mut seq)
        .into_iter()
        .map(|batch| serde_json::to_value(batch).expect("serialize batch payload"))
        .collect()
}

fn try_decompress_frame(
    dec: &mut DictDecompressor,
    frame: &[u8],
    initial: usize,
) -> Option<Vec<u8>> {
    let mut cap = initial.max(1024);
    for _ in 0..5 {
        match dec.decompress(frame, cap) {
            Ok(raw) => return Some(raw),
            Err(_) => cap = cap.saturating_mul(2),
        }
    }
    None
}

fn append_line_to_batch(batch: &mut IngestBatchRequest, line: &str) {
    if line.is_empty() {
        return;
    }

    if let Some(encoded) = line.strip_prefix("event_v2 ") {
        match serde_json::from_str::<TelemetryWireEvent>(encoded) {
            Ok(event) if (2..=3).contains(&event.wire_version) => {
                append_telemetry_event(batch, &event)
            }
            Ok(event) => append_unknown_payload_heartbeat(
                batch,
                &format!("unsupported_event_wire_v{}", event.wire_version),
                line.len(),
            ),
            Err(_) => append_unknown_payload_heartbeat(batch, "invalid_event_v2", line.len()),
        }
        return;
    }

    if line.starts_with("evt ") {
        append_evt_line(batch, line);
        return;
    }

    if line.starts_with("metric ") {
        append_metric_line(batch, line);
        return;
    }

    if line.starts_with("sc_event ") {
        append_secure_connect_line(batch, line);
        return;
    }

    let mut attrs = HashMap::new();
    attrs.insert("kind".to_string(), "line".to_string());
    attrs.insert("raw".to_string(), line.to_string());
    batch.agent_heartbeats.push(AgentHeartbeat {
        agent_version: "olopa".to_string(),
        kernel_version: "unknown".to_string(),
        events_read_total: 0,
        events_dropped_total: 0,
        queue_depth: 0,
        attrs,
    });
}

fn append_telemetry_event(batch: &mut IngestBatchRequest, event: &TelemetryWireEvent) {
    let mut attrs = HashMap::new();
    attrs.insert("ts_ns".to_string(), event.ts_ns.to_string());
    attrs.insert("risk_score".to_string(), format!("{:.6}", event.risk_score));
    attrs.insert("vertex_id".to_string(), event.vertex_id.to_string());
    attrs.insert("dst_vertex_id".to_string(), event.dst_vertex_id.to_string());
    attrs.insert("comm_id".to_string(), event.comm_id.to_string());
    attrs.insert("event_type".to_string(), event.event_type.to_string());
    attrs.insert("wire".to_string(), "event_v2".to_string());
    append_cgroup_attrs(&mut attrs, event.cgroup_id);
    if event.event_type == EVENT_TYPE_TC {
        attrs.insert(
            "tc_verdict".to_string(),
            if event.tc_verdict == 1 {
                "deny"
            } else {
                "allow"
            }
            .to_string(),
        );
    }

    match event.event_type {
        EVENT_TYPE_FILE => batch.file_events.push(FileEvent {
            pid: event.pid,
            tgid: event.pid,
            uid: event.uid,
            gid: 0,
            comm: event.comm.clone(),
            operation: "observed".to_string(),
            path: format!("vertex:{}->{}", event.vertex_id, event.dst_vertex_id),
            attrs,
        }),
        EVENT_TYPE_NET | EVENT_TYPE_TC => batch.net_events.push(NetEvent {
            pid: event.pid,
            tgid: event.pid,
            uid: event.uid,
            gid: 0,
            comm: event.comm.clone(),
            direction: "outbound".to_string(),
            protocol: if event.event_type == EVENT_TYPE_TC {
                "tc".to_string()
            } else {
                "unknown".to_string()
            },
            src_ip: None,
            dst_ip: (event.net_dst_ip != 0).then(|| Ipv4Addr::from(event.net_dst_ip).to_string()),
            src_port: None,
            dst_port: (event.net_dst_port != 0).then_some(event.net_dst_port),
            attrs,
        }),
        EVENT_TYPE_SQL => {
            let crate::sql_norm::UnpackedTables { database, tables } =
                crate::sql_norm::unpack_tables(&event.sql_tables);
            attrs.insert(
                "sql_query_class".to_string(),
                event.sql_query_class.to_string(),
            );
            attrs.insert("db_port".to_string(), event.sql_db_port.to_string());
            append_sql_policy_attrs(
                &mut attrs,
                event.sql_policy_verdict,
                event.sql_policy_prepared,
            );
            if event.sql_norm_hash != 0 {
                attrs.insert(
                    "raw_statement_hash".to_string(),
                    format!("{:08x}", event.sql_query_hash),
                );
            }
            batch.db_query_events.push(DbQueryEvent {
                pid: event.pid,
                tgid: event.pid,
                uid: event.uid,
                gid: 0,
                comm: event.comm.clone(),
                db_engine: db_engine_for_port(event.sql_db_port).to_string(),
                db_server: (event.sql_db_port != 0)
                    .then(|| format!("unknown:{}", event.sql_db_port)),
                database,
                operation: sql_operation_label(event.sql_query_class).to_string(),
                tables,
                statement_fingerprint: if event.sql_norm_hash != 0 {
                    format!("{:08x}", event.sql_norm_hash)
                } else {
                    format!("{:08x}", event.sql_query_hash)
                },
                attrs,
            });
        }
        EVENT_TYPE_SSL => {
            attrs.insert("ssl_data_len".to_string(), event.ssl_data_len.to_string());
            attrs.insert(
                "ssl_operation".to_string(),
                if event.ssl_operation == 0 {
                    "encrypt".to_string()
                } else {
                    "decrypt".to_string()
                },
            );
            batch.net_events.push(NetEvent {
                pid: event.pid,
                tgid: event.pid,
                uid: event.uid,
                gid: 0,
                comm: event.comm.clone(),
                direction: "outbound".to_string(),
                protocol: "tls".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                attrs,
            });
        }
        EVENT_TYPE_DNS => {
            if !event.dns_query.is_empty() {
                attrs.insert("dns_query".to_string(), event.dns_query.clone());
            }
            attrs.insert(
                "dns_query_hash".to_string(),
                event.dns_query_hash.to_string(),
            );
            batch.net_events.push(NetEvent {
                pid: event.pid,
                tgid: event.pid,
                uid: event.uid,
                gid: 0,
                comm: event.comm.clone(),
                direction: "outbound".to_string(),
                protocol: "dns".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: Some(53),
                attrs,
            });
        }
        _ => batch.process_exec_events.push(ProcessExecEvent {
            pid: event.pid,
            tgid: event.pid,
            ppid: event.dst_vertex_id,
            uid: event.uid,
            gid: 0,
            comm: event.comm.clone(),
            filename: "<event>".to_string(),
            attrs,
        }),
    }
}

fn append_evt_line(batch: &mut IngestBatchRequest, line: &str) {
    let fields = parse_kv_fields(line);
    let pid = parse_u32(fields.get("pid").copied()).unwrap_or(0);
    let uid = parse_u32(fields.get("uid").copied()).unwrap_or(0);
    let ppid = parse_u32(fields.get("dst").copied()).unwrap_or(0);
    let comm = fields.get("comm").copied().unwrap_or("unknown").to_string();

    let mut attrs = HashMap::new();
    for key in ["ts", "risk", "src", "dst"] {
        if let Some(v) = fields.get(key) {
            attrs.insert(key.to_string(), (*v).to_string());
        }
    }
    attrs.insert("wire".to_string(), "evt_line".to_string());
    attrs.insert("raw".to_string(), line.to_string());

    batch.process_exec_events.push(ProcessExecEvent {
        pid,
        tgid: pid,
        ppid,
        uid,
        gid: 0,
        comm,
        filename: "<event>".to_string(),
        attrs,
    });
}

fn append_metric_line(batch: &mut IngestBatchRequest, line: &str) {
    let fields = parse_kv_fields(line);
    let count = parse_u64(fields.get("count").copied()).unwrap_or(0);

    let mut attrs = HashMap::new();
    attrs.insert("wire".to_string(), "metric_line".to_string());
    attrs.insert("raw".to_string(), line.to_string());
    for key in ["comm_id", "min", "max", "mean", "p50", "p95", "p99"] {
        if let Some(v) = fields.get(key) {
            attrs.insert(key.to_string(), (*v).to_string());
        }
    }

    batch.agent_heartbeats.push(AgentHeartbeat {
        agent_version: "olopa".to_string(),
        kernel_version: "unknown".to_string(),
        events_read_total: count,
        events_dropped_total: 0,
        queue_depth: 0,
        attrs,
    });
}

/// Map a Secure Connect subsystem event onto the agent-heartbeat family.
///
/// Secure Connect rides the existing telemetry stream rather than opening its
/// own ingest surface, so tunnel/posture events land in the same store the
/// detection pipeline already reads.
fn append_secure_connect_line(batch: &mut IngestBatchRequest, line: &str) {
    let fields = parse_kv_fields(line);

    let mut attrs = HashMap::new();
    attrs.insert("wire".to_string(), "secure_connect".to_string());
    attrs.insert("kind".to_string(), "sc_session_event".to_string());
    for (key, value) in &fields {
        attrs.insert((*key).to_string(), (*value).to_string());
    }

    batch.agent_heartbeats.push(AgentHeartbeat {
        agent_version: fields
            .get("agent_version")
            .map(|value| (*value).to_string())
            .unwrap_or_else(|| "olopa".to_string()),
        kernel_version: fields
            .get("kernel_version")
            .map(|value| (*value).to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        events_read_total: parse_u64(fields.get("bytes_rx").copied()).unwrap_or(0),
        events_dropped_total: parse_u64(fields.get("reconnect_count").copied()).unwrap_or(0),
        queue_depth: 0,
        attrs,
    });
}

fn append_unknown_payload_heartbeat(batch: &mut IngestBatchRequest, kind: &str, len: usize) {
    let mut attrs = HashMap::new();
    attrs.insert("kind".to_string(), kind.to_string());
    attrs.insert("payload_len".to_string(), len.to_string());
    batch.agent_heartbeats.push(AgentHeartbeat {
        agent_version: "olopa".to_string(),
        kernel_version: "unknown".to_string(),
        events_read_total: 0,
        events_dropped_total: 0,
        queue_depth: 0,
        attrs,
    });
}

fn append_cgroup_attrs(attrs: &mut HashMap<String, String>, cgroup_id: u64) {
    attrs.insert("cgroup_id".to_string(), cgroup_id.to_string());
    if let Some(metadata) = crate::cgroup::lookup(cgroup_id) {
        attrs.insert("cgroup_path".to_string(), metadata.path);
        if let Some(container_id) = metadata.container_id {
            attrs.insert("container_id".to_string(), container_id);
        }
        if let Some(pod_uid) = metadata.pod_uid {
            attrs.insert("pod_uid".to_string(), pod_uid);
        }
    }
}

fn append_alert_to_batch(batch: &mut IngestBatchRequest, alert: &DecodedAlert) {
    let mut attrs = HashMap::new();
    attrs.insert("ts_ns".to_string(), alert.ts_ns.to_string());
    attrs.insert("risk_score".to_string(), format!("{:.6}", alert.risk_score));
    attrs.insert("vertex_id".to_string(), alert.vertex_id.to_string());
    attrs.insert("dst_vertex_id".to_string(), alert.dst_vertex_id.to_string());
    attrs.insert("comm_id".to_string(), alert.comm_id.to_string());
    attrs.insert("rule_id".to_string(), alert.rule_id.clone());
    attrs.insert("rule_name".to_string(), alert.rule_name.clone());
    attrs.insert("wire".to_string(), "alert_binary".to_string());
    append_cgroup_attrs(&mut attrs, alert.cgroup_id);

    let comm = alert.comm_label();

    match alert.event_type {
        EVENT_TYPE_NET | EVENT_TYPE_TC => {
            batch.net_events.push(NetEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm,
                direction: "outbound".to_string(),
                protocol: if alert.event_type == EVENT_TYPE_TC {
                    "tc".to_string()
                } else {
                    "unknown".to_string()
                },
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                attrs,
            });
        }
        EVENT_TYPE_FILE => {
            batch.file_events.push(FileEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm,
                operation: "alert_triggered".to_string(),
                path: format!("vertex:{}->{}", alert.vertex_id, alert.dst_vertex_id),
                attrs,
            });
        }
        EVENT_TYPE_SQL => {
            // `dst_vertex_id` carries the statement hash on v1 payloads, where
            // the extension block (and therefore class/port) is absent.
            let ext = alert.ext.clone().unwrap_or(AlertExt {
                sql_query_hash: alert.dst_vertex_id,
                ..AlertExt::default()
            });
            let db_port = ext.sql_db_port;
            let crate::sql_norm::UnpackedTables { database, tables } =
                crate::sql_norm::unpack_tables(&ext.sql_tables);

            attrs.insert(
                "sql_query_class".to_string(),
                ext.sql_query_class.to_string(),
            );
            attrs.insert("db_port".to_string(), db_port.to_string());
            append_sql_policy_attrs(&mut attrs, alert.sql_policy_verdict, false);
            if ext.sql_norm_hash != 0 {
                attrs.insert(
                    "raw_statement_hash".to_string(),
                    format!("{:08x}", ext.sql_query_hash),
                );
            }

            batch.db_query_events.push(DbQueryEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm,
                db_engine: db_engine_for_port(db_port).to_string(),
                db_server: (db_port != 0).then(|| format!("unknown:{db_port}")),
                database,
                operation: sql_operation_label(ext.sql_query_class).to_string(),
                tables,
                // Prefer the redacted-statement fingerprint so the same query
                // shape groups regardless of literal values; fall back to the
                // raw hash for payloads that predate normalization.
                statement_fingerprint: if ext.sql_norm_hash != 0 {
                    format!("{:08x}", ext.sql_norm_hash)
                } else {
                    format!("{:08x}", ext.sql_query_hash)
                },
                attrs,
            });
        }
        EVENT_TYPE_SSL => {
            if let Some(ext) = alert.ext.as_ref() {
                attrs.insert("ssl_data_len".to_string(), ext.ssl_data_len.to_string());
                attrs.insert(
                    "ssl_operation".to_string(),
                    if ext.ssl_operation == 0 {
                        "encrypt".to_string()
                    } else {
                        "decrypt".to_string()
                    },
                );
            }
            batch.net_events.push(NetEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm,
                direction: "outbound".to_string(),
                protocol: "tls".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                attrs,
            });
        }
        EVENT_TYPE_DNS => {
            let query = alert
                .ext
                .as_ref()
                .map(|ext| ext.dns_query.clone())
                .unwrap_or_default();
            if !query.is_empty() {
                attrs.insert("dns_query".to_string(), query);
            }
            if let Some(ext) = alert.ext.as_ref() {
                attrs.insert("dns_query_hash".to_string(), ext.dns_query_hash.to_string());
            }
            // The queried name stays in `attrs`: `dst_ip` is an IP-typed field
            // downstream, and the uprobe fires before resolution completes.
            batch.net_events.push(NetEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm,
                direction: "outbound".to_string(),
                protocol: "dns".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: Some(53),
                attrs,
            });
        }
        _ => {
            batch.process_exec_events.push(ProcessExecEvent {
                pid: alert.pid,
                tgid: alert.pid,
                ppid: alert.dst_vertex_id,
                uid: alert.uid,
                gid: 0,
                comm,
                filename: "alert_triggered".to_string(),
                attrs,
            });
        }
    }
}

/// Map an observed database port to an engine label.
fn db_engine_for_port(port: u16) -> &'static str {
    match port {
        5432 => "postgresql",
        3306 => "mysql",
        _ => "unknown",
    }
}

/// Map the kernel-side statement class to a normalized operation label.
///
/// Mirrors `query_class` in `olopa_common::SqlEvent`.
fn sql_operation_label(class: u8) -> &'static str {
    match class {
        1 => "select",
        2 => "dml",
        3 => "ddl",
        4 => "admin",
        _ => "other",
    }
}

fn decode_alert_payload(payload: &[u8]) -> Option<DecodedAlert> {
    if payload.len() < 44 {
        return None;
    }
    if &payload[0..4] != ALERT_MAGIC {
        return None;
    }

    let version = u16::from_le_bytes([payload[4], payload[5]]);
    if !(ALERT_WIRE_VERSION_MIN..=ALERT_WIRE_VERSION_CGROUP).contains(&version) {
        return None;
    }

    let event_type = payload[6];
    let sql_policy_verdict = payload[7];
    let ts_ns = u64::from_le_bytes(payload[8..16].try_into().ok()?);
    let pid = u32::from_le_bytes(payload[16..20].try_into().ok()?);
    let uid = u32::from_le_bytes(payload[20..24].try_into().ok()?);
    let vertex_id = u32::from_le_bytes(payload[24..28].try_into().ok()?);
    let dst_vertex_id = u32::from_le_bytes(payload[28..32].try_into().ok()?);
    let comm_id = u32::from_le_bytes(payload[32..36].try_into().ok()?);
    let risk_score = f32::from_le_bytes(payload[36..40].try_into().ok()?);
    let rule_id_len = u16::from_le_bytes(payload[40..42].try_into().ok()?) as usize;
    let rule_name_len = u16::from_le_bytes(payload[42..44].try_into().ok()?) as usize;

    let mut cursor = 44usize;
    let end_rule_id = cursor.saturating_add(rule_id_len);
    if end_rule_id > payload.len() {
        return None;
    }
    let rule_id = String::from_utf8(payload[cursor..end_rule_id].to_vec()).ok()?;
    cursor = end_rule_id;

    let end_rule_name = cursor.saturating_add(rule_name_len);
    if end_rule_name > payload.len() {
        return None;
    }
    let rule_name = String::from_utf8(payload[cursor..end_rule_name].to_vec()).ok()?;
    cursor = end_rule_name;

    // A truncated or malformed extension degrades to `None` rather than
    // dropping the alert — rule identity is the part that must not be lost.
    let ext = (version >= ALERT_WIRE_VERSION_EXT)
        .then(|| decode_alert_ext(payload, cursor))
        .flatten();
    let cgroup_id = if version >= ALERT_WIRE_VERSION_CGROUP {
        let tail = payload.len().checked_sub(8)?;
        u64::from_le_bytes(payload.get(tail..)?.try_into().ok()?)
    } else {
        0
    };

    Some(DecodedAlert {
        event_type,
        sql_policy_verdict,
        ts_ns,
        pid,
        uid,
        vertex_id,
        dst_vertex_id,
        comm_id,
        risk_score,
        rule_id,
        rule_name,
        cgroup_id,
        ext,
    })
}

fn append_sql_policy_attrs(
    attrs: &mut HashMap<String, String>,
    verdict: u8,
    prepared: bool,
) {
    let label = match verdict {
        olopa_common::SQL_POLICY_EVENT_ALLOWED => "allowed",
        olopa_common::SQL_POLICY_EVENT_WOULD_BLOCK => "would_block",
        olopa_common::SQL_POLICY_EVENT_BLOCKED => "blocked",
        _ => return,
    };
    attrs.insert("sql_policy_verdict".to_string(), label.to_string());
    attrs.insert("sql_policy_prepared".to_string(), prepared.to_string());
}

/// Parse the v2 extension block starting at `cursor`.
fn decode_alert_ext(payload: &[u8], mut cursor: usize) -> Option<AlertExt> {
    let comm_len = *payload.get(cursor)? as usize;
    cursor += 1;
    let comm_end = cursor.checked_add(comm_len)?;
    let comm = String::from_utf8(payload.get(cursor..comm_end)?.to_vec()).ok()?;
    cursor = comm_end;

    let sql_query_hash = u32::from_le_bytes(payload.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;
    let sql_query_class = *payload.get(cursor)?;
    cursor += 1;
    let sql_db_port = u16::from_le_bytes(payload.get(cursor..cursor + 2)?.try_into().ok()?);
    cursor += 2;
    let ssl_data_len = u32::from_le_bytes(payload.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;
    let ssl_operation = *payload.get(cursor)?;
    cursor += 1;
    let dns_query_hash = u32::from_le_bytes(payload.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;

    let dns_query_len = *payload.get(cursor)? as usize;
    cursor += 1;
    let dns_end = cursor.checked_add(dns_query_len)?;
    let dns_query = String::from_utf8(payload.get(cursor..dns_end)?.to_vec()).ok()?;
    cursor = dns_end;

    // The SQL table block is optional within the extension, so payloads from
    // before it existed still yield every field above.
    let (sql_norm_hash, sql_tables) = decode_sql_table_block(payload, cursor).unwrap_or_default();

    Some(AlertExt {
        comm,
        sql_query_hash,
        sql_query_class,
        sql_db_port,
        ssl_data_len,
        ssl_operation,
        dns_query_hash,
        dns_query,
        sql_norm_hash,
        sql_tables,
    })
}

/// Parse the optional trailing `[sql_norm_hash][len][tables]` block.
fn decode_sql_table_block(payload: &[u8], mut cursor: usize) -> Option<(u32, String)> {
    let norm_hash = u32::from_le_bytes(payload.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;
    let len = *payload.get(cursor)? as usize;
    cursor += 1;
    let end = cursor.checked_add(len)?;
    let tables = String::from_utf8(payload.get(cursor..end)?.to_vec()).ok()?;
    Some((norm_hash, tables))
}

fn parse_kv_fields(line: &str) -> HashMap<&str, &str> {
    let mut out = HashMap::new();
    for part in line.split_whitespace() {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(k, v);
        }
    }
    out
}

fn parse_u32(value: Option<&str>) -> Option<u32> {
    value.and_then(|v| v.parse::<u32>().ok())
}

fn parse_u64(value: Option<&str>) -> Option<u64> {
    value.and_then(|v| v.parse::<u64>().ok())
}

fn next_batch_id(seq: &mut u64) -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let id = format!("agent-batch-{now_ms}-{}", *seq);
    *seq = seq.saturating_add(1);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{encode_telemetry_payload, IngestEvent};
    use crate::data::batcher_compressor::Batcher;
    use crate::data::mdkp_scheduler::BudgetSnapshot;

    fn comm_bytes(value: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..value.len()].copy_from_slice(value);
        out
    }

    #[test]
    fn secure_connect_events_map_onto_the_agent_heartbeat_family() {
        let line = "sc_event event=access_revoked session_id=sess-1 to_state=quarantined \
                    revoke_ms=42 kill_switch_ms=7 reason=control_plane_quarantine";
        let batches = payload_to_batches_for_tests(line.as_bytes(), "tenant-a", "host-a");

        assert_eq!(batches.len(), 1);
        let heartbeats = batches[0]["agent_heartbeats"].as_array().expect("heartbeats");
        assert_eq!(heartbeats.len(), 1);
        let attrs = &heartbeats[0]["attrs"];
        assert_eq!(attrs["wire"], "secure_connect");
        assert_eq!(attrs["kind"], "sc_session_event");
        assert_eq!(attrs["event"], "access_revoked");
        assert_eq!(attrs["session_id"], "sess-1");
        assert_eq!(attrs["revoke_ms"], "42");
        assert_eq!(batches[0]["tenant_id"], "tenant-a");
        assert_eq!(batches[0]["host_id"], "host-a");
    }

    #[test]
    fn compressed_normal_events_preserve_all_telemetry_families() {
        let mut batcher = Batcher::new(7, 32);
        let budget = BudgetSnapshot::default_budgets();

        let process = IngestEvent {
            event_type: 1,
            pid: 101,
            uid: 1001,
            dst_vertex_id: 10,
            comm: comm_bytes(b"bash"),
            ..Default::default()
        };
        let file = IngestEvent {
            event_type: EVENT_TYPE_FILE,
            pid: 102,
            uid: 1002,
            vertex_id: 102,
            dst_vertex_id: 202,
            comm: comm_bytes(b"cat"),
            ..Default::default()
        };
        let network = IngestEvent {
            event_type: EVENT_TYPE_NET,
            pid: 103,
            uid: 1003,
            net_dst_ip: u32::from(Ipv4Addr::new(8, 8, 8, 8)),
            net_dst_port: 443,
            comm: comm_bytes(b"curl"),
            ..Default::default()
        };

        let mut sql_tables = [0u8; crate::sql_norm::SQL_TABLES_LEN];
        sql_tables[..14].copy_from_slice(b"finance.ledger");
        let sql = IngestEvent {
            event_type: EVENT_TYPE_SQL,
            pid: 104,
            uid: 1004,
            comm: comm_bytes(b"psql"),
            sql_query_hash: 0x1111_2222,
            sql_query_class: 3,
            sql_db_port: 5432,
            sql_norm_hash: 0xaabb_ccdd,
            sql_tables,
            ..Default::default()
        };
        let ssl = IngestEvent {
            event_type: EVENT_TYPE_SSL,
            pid: 105,
            uid: 1005,
            comm: comm_bytes(b"openssl"),
            ssl_data_len: 4096,
            ssl_operation: 1,
            ..Default::default()
        };
        let mut dns_query = [0u8; 64];
        dns_query[..11].copy_from_slice(b"evil.c2.net");
        let dns = IngestEvent {
            event_type: EVENT_TYPE_DNS,
            pid: 106,
            uid: 1006,
            comm: comm_bytes(b"resolver"),
            dns_query_hash: 99,
            dns_query,
            ..Default::default()
        };

        for event in [process, file, network, sql, ssl, dns] {
            let encoded = encode_telemetry_payload(&event).expect("encode telemetry event");
            let _ = batcher.push(&encoded, &budget);
        }
        let compressed = batcher.flush().expect("flush telemetry batch");

        let cfg = HttpSenderConfig::for_mapping("t", "h");
        let mut dec = DictDecompressor::new();
        let mut seq = 0;
        let out = payload_to_batches(&compressed.payload, &cfg, &mut dec, &mut seq);
        let batch = &out[0];

        assert_eq!(batch.process_exec_events.len(), 1);
        assert_eq!(batch.process_exec_events[0].comm, "bash");
        assert_eq!(batch.file_events.len(), 1);
        assert_eq!(batch.file_events[0].comm, "cat");
        assert_eq!(batch.db_query_events.len(), 1);
        assert_eq!(
            batch.db_query_events[0].database.as_deref(),
            Some("finance")
        );
        assert_eq!(batch.db_query_events[0].tables, vec!["ledger"]);
        assert_eq!(batch.db_query_events[0].operation, "ddl");
        assert_eq!(batch.db_query_events[0].statement_fingerprint, "aabbccdd");

        assert_eq!(batch.net_events.len(), 3);
        let ordinary_net = batch
            .net_events
            .iter()
            .find(|event| event.protocol == "unknown")
            .expect("ordinary network event");
        assert_eq!(ordinary_net.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(ordinary_net.dst_port, Some(443));
        let tls = batch
            .net_events
            .iter()
            .find(|event| event.protocol == "tls")
            .expect("tls event");
        assert_eq!(
            tls.attrs.get("ssl_data_len").map(String::as_str),
            Some("4096")
        );
        let dns = batch
            .net_events
            .iter()
            .find(|event| event.protocol == "dns")
            .expect("dns event");
        assert_eq!(
            dns.attrs.get("dns_query").map(String::as_str),
            Some("evil.c2.net")
        );
        assert!(batch.agent_heartbeats.is_empty());
    }

    /// Build a legacy (extension-less) alert payload.
    fn v1_alert_payload(event_type: u8, dst_vertex_id: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(ALERT_MAGIC);
        payload.extend_from_slice(&ALERT_WIRE_VERSION_MIN.to_le_bytes());
        payload.push(event_type);
        payload.push(0u8);
        payload.extend_from_slice(&123u64.to_le_bytes());
        payload.extend_from_slice(&1000u32.to_le_bytes());
        payload.extend_from_slice(&1001u32.to_le_bytes());
        payload.extend_from_slice(&42u32.to_le_bytes());
        payload.extend_from_slice(&dst_vertex_id.to_le_bytes());
        payload.extend_from_slice(&9u32.to_le_bytes());
        payload.extend_from_slice(&0.75f32.to_le_bytes());
        payload.extend_from_slice(&(4u16).to_le_bytes());
        payload.extend_from_slice(&(5u16).to_le_bytes());
        payload.extend_from_slice(b"rid1");
        payload.extend_from_slice(b"rname");
        payload
    }

    #[test]
    fn decodes_alert_binary_payload() {
        let payload = v1_alert_payload(3, 43);
        let decoded = decode_alert_payload(&payload).expect("decode");
        assert_eq!(decoded.event_type, 3);
        assert_eq!(decoded.pid, 1000);
        assert_eq!(decoded.rule_id, "rid1");
        assert_eq!(decoded.rule_name, "rname");
        assert!(decoded.ext.is_none(), "v1 payloads carry no extension");
    }

    #[test]
    fn v1_sql_alert_still_routes_to_db_query_family() {
        // Legacy senders encode the statement hash in `dst_vertex_id` and have
        // no class/port, so the row degrades to `unknown`/`other` rather than
        // being mis-filed as a process exec.
        let payload = v1_alert_payload(EVENT_TYPE_SQL, 0xdead_beef);
        let cfg = HttpSenderConfig::for_mapping("t", "h");
        let mut dec = DictDecompressor::new();
        let mut seq = 0;
        let out = payload_to_batches(&payload, &cfg, &mut dec, &mut seq);

        assert_eq!(out[0].db_query_events.len(), 1);
        assert!(out[0].process_exec_events.is_empty());
        let event = &out[0].db_query_events[0];
        assert_eq!(event.statement_fingerprint, "deadbeef");
        assert_eq!(event.db_engine, "unknown");
        assert_eq!(event.operation, "other");
        assert_eq!(event.db_server, None);
        assert_eq!(event.comm, "comm_id_9");
    }

    #[test]
    fn ssl_alert_routes_to_net_family_as_tls() {
        let payload = v1_alert_payload(EVENT_TYPE_SSL, 0);
        let cfg = HttpSenderConfig::for_mapping("t", "h");
        let mut dec = DictDecompressor::new();
        let mut seq = 0;
        let out = payload_to_batches(&payload, &cfg, &mut dec, &mut seq);

        assert_eq!(out[0].net_events.len(), 1);
        assert_eq!(out[0].net_events[0].protocol, "tls");
        assert!(out[0].process_exec_events.is_empty());
    }

    #[test]
    fn maps_evt_line_into_process_event() {
        let cfg = HttpSenderConfig::for_mapping("t", "h");
        let mut dec = DictDecompressor::new();
        let mut seq = 0;
        let payload = b"evt ts=10 pid=20 uid=30 risk=0.4 src=20 dst=1 comm=bash";
        let out = payload_to_batches(payload, &cfg, &mut dec, &mut seq);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].process_exec_events.len(), 1);
        assert_eq!(out[0].process_exec_events[0].pid, 20);
        assert_eq!(out[0].process_exec_events[0].uid, 30);
    }
}
