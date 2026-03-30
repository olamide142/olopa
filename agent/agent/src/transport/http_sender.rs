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
const ALERT_WIRE_VERSION: u16 = 1;

#[derive(Clone, Debug)]
struct HttpSenderConfig {
    ingest_url: String,
    tenant_id: String,
    host_id: String,
}

impl HttpSenderConfig {
    fn from_env() -> Self {
        Self {
            ingest_url: std::env::var("OLOPA_INGEST_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8000/api/v1/ingest/batches".to_string()),
            tenant_id: std::env::var("OLOPA_INGEST_TENANT_ID")
                .unwrap_or_else(|_| "default".to_string()),
            host_id: std::env::var("OLOPA_INGEST_HOST_ID")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "agent-local".to_string()),
        }
    }
}

#[derive(Default)]
struct SharedSenderState {
    spool_pending_bytes: AtomicU64,
    spooling: AtomicBool,
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
    agent_heartbeats: Vec<AgentHeartbeat>,
}

impl IngestBatchRequest {
    fn new(cfg: &HttpSenderConfig, batch_id: String) -> Self {
        Self {
            tenant_id: cfg.tenant_id.clone(),
            host_id: cfg.host_id.clone(),
            schema_version: 1,
            batch_id: Some(batch_id),
            process_exec_events: Vec::new(),
            file_events: Vec::new(),
            net_events: Vec::new(),
            agent_heartbeats: Vec::new(),
        }
    }

    fn row_count(&self) -> usize {
        self.process_exec_events.len()
            + self.file_events.len()
            + self.net_events.len()
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

        info!(
            "sender: http ingest enabled url={} tenant={} host={}",
            cfg.ingest_url, cfg.tenant_id, cfg.host_id
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
        SenderStats {
            spool_pending_bytes: pending,
            spooling,
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

        flush_backlog(&client, &cfg, &mut backlog).await;
        update_shared_state(&shared, &backlog);
    }

    flush_backlog(&client, &cfg, &mut backlog).await;
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
    backlog: &mut VecDeque<QueuedBatch>,
) {
    while let Some(item) = backlog.front() {
        match post_batch(client, &cfg.ingest_url, &item.batch).await {
            Ok(()) => {
                backlog.pop_front();
            }
            Err(err) => {
                debug!("sender: backlog send paused: {}", err);
                break;
            }
        }
    }
}

async fn post_batch(client: &reqwest::Client, url: &str, batch: &IngestBatchRequest) -> Result<()> {
    let resp = client.post(url).json(batch).send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("http status {}", status);
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
        agent_version: "olopa-agent".to_string(),
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
        agent_version: "olopa-agent".to_string(),
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
        agent_version: "olopa-agent".to_string(),
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

    match alert.event_type {
        3 => {
            batch.net_events.push(NetEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm: format!("comm_id_{}", alert.comm_id),
                direction: "outbound".to_string(),
                protocol: "unknown".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                attrs,
            });
        }
        2 => {
            batch.file_events.push(FileEvent {
                pid: alert.pid,
                tgid: alert.pid,
                uid: alert.uid,
                gid: 0,
                comm: format!("comm_id_{}", alert.comm_id),
                operation: "alert_triggered".to_string(),
                path: format!("vertex:{}->{}", alert.vertex_id, alert.dst_vertex_id),
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
                comm: format!("comm_id_{}", alert.comm_id),
                filename: "alert_triggered".to_string(),
                attrs,
            });
        }
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
    if version != ALERT_WIRE_VERSION {
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
    })
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

    #[test]
    fn decodes_alert_binary_payload() {
        let mut payload = Vec::new();
        payload.extend_from_slice(ALERT_MAGIC);
        payload.extend_from_slice(&ALERT_WIRE_VERSION.to_le_bytes());
        payload.push(3u8);
        payload.push(0u8);
        payload.extend_from_slice(&123u64.to_le_bytes());
        payload.extend_from_slice(&1000u32.to_le_bytes());
        payload.extend_from_slice(&1001u32.to_le_bytes());
        payload.extend_from_slice(&42u32.to_le_bytes());
        payload.extend_from_slice(&43u32.to_le_bytes());
        payload.extend_from_slice(&9u32.to_le_bytes());
        payload.extend_from_slice(&0.75f32.to_le_bytes());
        payload.extend_from_slice(&(4u16).to_le_bytes());
        payload.extend_from_slice(&(5u16).to_le_bytes());
        payload.extend_from_slice(b"rid1");
        payload.extend_from_slice(b"rname");

        let decoded = decode_alert_payload(&payload).expect("decode");
        assert_eq!(decoded.event_type, 3);
        assert_eq!(decoded.pid, 1000);
        assert_eq!(decoded.rule_id, "rid1");
        assert_eq!(decoded.rule_name, "rname");
    }

    #[test]
    fn maps_evt_line_into_process_event() {
        let cfg = HttpSenderConfig {
            ingest_url: "http://127.0.0.1:8000/api/v1/ingest/batches".to_string(),
            tenant_id: "t".to_string(),
            host_id: "h".to_string(),
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
