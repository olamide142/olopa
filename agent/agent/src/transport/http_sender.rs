use anyhow::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::agent::{SenderLike, SenderStats};
use crate::data::batcher_compressor::{BatchParser, DictDecompressor};

const ALERT_MAGIC: &[u8; 4] = b"OLRT";
/// Oldest alert wire version this sender still decodes.
const ALERT_WIRE_VERSION_MIN: u16 = 1;
/// Alert wire version that carries the SQL/TLS/DNS extension block.
const ALERT_WIRE_VERSION_EXT: u16 = 2;

/// Ring-buffer event type discriminants shared with `agent::IngestEvent`.
const EVENT_TYPE_FILE: u8 = 2;
const EVENT_TYPE_NET: u8 = 3;
const EVENT_TYPE_SQL: u8 = 4;
const EVENT_TYPE_SSL: u8 = 5;
const EVENT_TYPE_DNS: u8 = 6;

#[derive(Clone, Debug)]
struct HttpSenderConfig {
    ingest_url: String,
    tenant_id: String,
    host_id: String,
    auth: Option<HttpSenderAuth>,
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
///
/// The uprobe (`agent/ebpf/src/sql_probe.rs`) hashes the statement text in
/// kernel space rather than copying it out, so `database` and `tables` are not
/// resolvable yet — populating them needs the statement-capture/normalization
/// work tracked as Epic 1.0 step 2. They serialize as `null`/`[]` until then,
/// keeping the field contract stable for consumers.
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
    ts_ns: u64,
    pid: u32,
    uid: u32,
    vertex_id: u32,
    dst_vertex_id: u32,
    comm_id: u32,
    risk_score: f32,
    rule_id: String,
    rule_name: String,
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
struct QueuedBatch {
    batch: IngestBatchRequest,
    approx_bytes: usize,
}

pub struct HttpIngestSender {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    local_spool: Vec<Vec<u8>>,
    shared: Arc<SharedSenderState>,
}

impl HttpIngestSender {
    pub fn from_env() -> Self {
        let cfg = HttpSenderConfig::from_env();
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(SharedSenderState::default());
        let auth_mode = match &cfg.auth {
            Some(HttpSenderAuth::BearerToken(_)) => "bearer",
            Some(HttpSenderAuth::ApiKey(_)) => "x-api-key",
            None => "none",
        };

        info!(
            "sender: http ingest enabled url={} tenant={} host={} auth={}",
            cfg.ingest_url, cfg.tenant_id, cfg.host_id, auth_mode
        );

        tokio::spawn(sender_worker(rx, cfg, Arc::clone(&shared)));

        Self {
            tx,
            local_spool: Vec::new(),
            shared,
        }
    }
}

impl SenderLike for HttpIngestSender {
    fn send_or_spool(&mut self, payload: Vec<u8>) -> Result<()> {
        if let Err(e) = self.tx.send(payload) {
            self.local_spool.push(e.0);
            self.shared.spooling.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn stats(&self) -> SenderStats {
        let worker_pending = self.shared.spool_pending_bytes.load(Ordering::Relaxed);
        let local_pending = self.local_spool.iter().map(|b| b.len() as u64).sum::<u64>();
        let pending = worker_pending.saturating_add(local_pending);
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
        let mut drained = 0usize;
        while !self.local_spool.is_empty() && Instant::now() < deadline {
            let payload = self.local_spool.remove(0);
            match self.tx.send(payload) {
                Ok(()) => drained = drained.saturating_add(1),
                Err(e) => {
                    self.local_spool.insert(0, e.0);
                    break;
                }
            }
        }
        Ok(drained)
    }
}

async fn sender_worker(
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cfg: HttpSenderConfig,
    shared: Arc<SharedSenderState>,
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

    let mut retry_tick = tokio::time::interval(Duration::from_millis(250));
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut backlog: VecDeque<QueuedBatch> = VecDeque::new();
    let mut dec = DictDecompressor::new();
    let mut seq = 0u64;

    loop {
        tokio::select! {
            payload = rx.recv() => {
                match payload {
                    Some(payload) => {
                        let batches = payload_to_batches(&payload, &cfg, &mut dec, &mut seq);
                        let approx = payload.len().max(1);
                        for batch in batches {
                            backlog.push_back(QueuedBatch {
                                batch,
                                approx_bytes: approx,
                            });
                        }
                    }
                    None => break,
                }
            }
            _ = retry_tick.tick() => {}
        }

        flush_backlog(&client, &cfg, &shared, &mut backlog).await;
        update_shared_state(&shared, &backlog);
    }

    flush_backlog(&client, &cfg, &shared, &mut backlog).await;
    update_shared_state(&shared, &backlog);
}

fn update_shared_state(shared: &SharedSenderState, backlog: &VecDeque<QueuedBatch>) {
    let pending = backlog.iter().map(|b| b.approx_bytes as u64).sum::<u64>();
    shared.spool_pending_bytes.store(pending, Ordering::Relaxed);
    shared
        .spooling
        .store(!backlog.is_empty(), Ordering::Relaxed);
}

async fn flush_backlog(
    client: &reqwest::Client,
    cfg: &HttpSenderConfig,
    shared: &SharedSenderState,
    backlog: &mut VecDeque<QueuedBatch>,
) {
    while let Some(item) = backlog.front() {
        let started = Instant::now();
        match post_batch(client, cfg, &item.batch).await {
            Ok(()) => {
                shared
                    .backend_reachability_known
                    .store(true, Ordering::Relaxed);
                shared.backend_reachable.store(true, Ordering::Relaxed);
                let rtt_ms = started.elapsed().as_millis() as u64;
                shared
                    .backend_rtt_ms
                    .store(rtt_ms.max(1), Ordering::Relaxed);
                backlog.pop_front();
            }
            Err(err) => {
                shared
                    .backend_reachability_known
                    .store(true, Ordering::Relaxed);
                shared.backend_reachable.store(false, Ordering::Relaxed);
                debug!("sender: backlog send paused: {}", err);
                break;
            }
        }
    }
}

async fn post_batch(
    client: &reqwest::Client,
    cfg: &HttpSenderConfig,
    batch: &IngestBatchRequest,
) -> Result<()> {
    let mut req = client.post(&cfg.ingest_url).json(batch);
    if let Some(auth) = cfg.auth.as_ref() {
        req = match auth {
            HttpSenderAuth::BearerToken(token) => req.bearer_auth(token),
            HttpSenderAuth::ApiKey(api_key) => req.header("x-api-key", api_key),
        };
    }

    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "http status {} body={}",
            status,
            truncate_for_log(&body, 256)
        );
    }

    let ack = resp.json::<AckResponse>().await.unwrap_or(AckResponse {
        accepted: true,
        retry_after_ms: 0,
        message: None,
    });

    if !ack.accepted {
        anyhow::bail!(
            "server rejected batch retry_after_ms={} message={:?}",
            ack.retry_after_ms,
            ack.message
        );
    }

    Ok(())
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
    if let Some(alert) = decode_alert_payload(payload) {
        let mut batch = IngestBatchRequest::new(cfg, next_batch_id(seq));
        append_alert_to_batch(&mut batch, &alert);
        return vec![batch];
    }

    if let Ok(mut parser) = BatchParser::new(payload) {
        let mut batch = IngestBatchRequest::new(cfg, next_batch_id(seq));
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
        let mut batch = IngestBatchRequest::new(cfg, next_batch_id(seq));
        append_line_to_batch(&mut batch, text.trim());
        if batch.row_count() == 0 {
            append_unknown_payload_heartbeat(&mut batch, "text_payload_no_rows", payload.len());
        }
        return vec![batch];
    }

    let mut batch = IngestBatchRequest::new(cfg, next_batch_id(seq));
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
    let cfg = HttpSenderConfig {
        ingest_url: "http://127.0.0.1:8000/api/v1/ingest/batches".to_string(),
        tenant_id: tenant_id.to_string(),
        host_id: host_id.to_string(),
        auth: None,
    };
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

    if line.starts_with("evt ") {
        append_evt_line(batch, line);
        return;
    }

    if line.starts_with("metric ") {
        append_metric_line(batch, line);
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

    let comm = alert.comm_label();

    match alert.event_type {
        EVENT_TYPE_NET => {
            batch.net_events.push(NetEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm,
                direction: "outbound".to_string(),
                protocol: "unknown".to_string(),
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
            let (database, tables) = split_table_refs(&ext.sql_tables);

            attrs.insert(
                "sql_query_class".to_string(),
                ext.sql_query_class.to_string(),
            );
            attrs.insert("db_port".to_string(), db_port.to_string());
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

/// Split the packed `db.table` list into a database name and bare table names.
///
/// A database is only reported when every qualified reference agrees on it —
/// a cross-database join has no single answer, and guessing one would be worse
/// than reporting none.
fn split_table_refs(packed: &str) -> (Option<String>, Vec<String>) {
    let mut tables = Vec::new();
    let mut qualifiers = Vec::new();

    for entry in packed.split(',').filter(|s| !s.is_empty()) {
        match entry.rsplit_once('.') {
            Some((qualifier, name)) if !qualifier.is_empty() && !name.is_empty() => {
                qualifiers.push(qualifier.to_string());
                tables.push(name.to_string());
            }
            _ => tables.push(entry.to_string()),
        }
    }

    let database = match qualifiers.first() {
        Some(first) if qualifiers.iter().all(|q| q == first) => Some(first.clone()),
        _ => None,
    };

    (database, tables)
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
    if !(ALERT_WIRE_VERSION_MIN..=ALERT_WIRE_VERSION_EXT).contains(&version) {
        return None;
    }

    let event_type = payload[6];
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

    Some(DecodedAlert {
        event_type,
        ts_ns,
        pid,
        uid,
        vertex_id,
        dst_vertex_id,
        comm_id,
        risk_score,
        rule_id,
        rule_name,
        ext,
    })
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
        let cfg = HttpSenderConfig {
            ingest_url: "http://127.0.0.1:8000/api/v1/ingest/batches".to_string(),
            tenant_id: "t".to_string(),
            host_id: "h".to_string(),
            auth: None,
        };
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
        let cfg = HttpSenderConfig {
            ingest_url: "http://127.0.0.1:8000/api/v1/ingest/batches".to_string(),
            tenant_id: "t".to_string(),
            host_id: "h".to_string(),
            auth: None,
        };
        let mut dec = DictDecompressor::new();
        let mut seq = 0;
        let out = payload_to_batches(&payload, &cfg, &mut dec, &mut seq);

        assert_eq!(out[0].net_events.len(), 1);
        assert_eq!(out[0].net_events[0].protocol, "tls");
        assert!(out[0].process_exec_events.is_empty());
    }

    #[test]
    fn maps_evt_line_into_process_event() {
        let cfg = HttpSenderConfig {
            ingest_url: "http://127.0.0.1:8000/api/v1/ingest/batches".to_string(),
            tenant_id: "t".to_string(),
            host_id: "h".to_string(),
            auth: None,
        };
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
