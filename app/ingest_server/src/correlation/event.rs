//! Unified event model and zero-copy field extractors.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::telemetry::{
    AgentHeartbeat, DbQueryEvent, FileEvent, NetEvent, ProcessExecEvent,
};
use super::value::Value;

/// Furthest an agent-stamped event time may lag arrival and still be trusted.
///
/// Agents spool while a backend is unreachable, so a genuinely old event is
/// normal; a full day bounds how far a correlation window can be dragged back.
const MAX_EVENT_TS_LAG_MS: u64 = 24 * 60 * 60 * 1_000;

/// Furthest an agent-stamped event time may lead arrival and still be trusted.
///
/// Anything further ahead is clock skew, not a real observation.
const MAX_EVENT_TS_LEAD_MS: u64 = 5 * 60 * 1_000;

/// Resolve the event time used for correlation windows.
///
/// Prefers the agent's own observation time, which is what makes window
/// semantics reproducible on replay. Falls back to batch arrival time when the
/// agent sent none (schema_version < 3) or when the stamp is far enough outside
/// the arrival time to indicate a skewed agent clock rather than a late event.
/// Returns the resolved time and whether the fallback was taken.
pub fn resolve_event_ts(agent_ts_unix_ms: Option<u64>, arrival_ms: u64) -> (u64, bool) {
    match agent_ts_unix_ms {
        Some(ts)
            if ts >= arrival_ms.saturating_sub(MAX_EVENT_TS_LAG_MS)
                && ts <= arrival_ms.saturating_add(MAX_EVENT_TS_LEAD_MS) =>
        {
            (ts, false)
        }
        Some(_) => (arrival_ms, true),
        None => (arrival_ms, true),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventFamily {
    ProcessExec,
    File,
    Net,
    DbQuery,
    AgentHeartbeat,
}

impl EventFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventFamily::ProcessExec => "process_exec",
            EventFamily::File => "file",
            EventFamily::Net => "net",
            EventFamily::DbQuery => "db_query",
            EventFamily::AgentHeartbeat => "agent_heartbeat",
        }
    }

    pub fn matches_source(&self, domain: &str, event: &str) -> bool {
        match self {
            EventFamily::ProcessExec => {
                domain == "endpoint" && (event == "process" || event == "process_exec" || event == "spawn")
                    || domain == "process"
                    || domain.is_empty() && (event == "process" || event == "process_exec" || event == "spawn")
            }
            EventFamily::File => {
                domain == "endpoint" && (event == "file" || event == "open" || event == "write")
                    || domain == "file"
                    || domain.is_empty() && (event == "file" || event == "open" || event == "file_open")
            }
            EventFamily::Net => {
                domain == "network" && (event == "flow" || event == "connect" || event == "traffic")
                    || domain == "net"
                    || domain.is_empty() && (event == "network" || event == "connect" || event == "net_event")
            }
            EventFamily::DbQuery => {
                domain == "database" && (event == "query" || event == "sql")
                    || domain == "db"
                    || domain.is_empty() && (event == "db_query" || event == "query" || event == "sql")
            }
            EventFamily::AgentHeartbeat => {
                domain == "agent" && (event == "heartbeat" || event == "health")
                    || domain == "heartbeat"
                    || domain.is_empty() && (event == "agent_heartbeat" || event == "heartbeat")
            }
        }
    }
}

/// Zero-copy view of a single telemetry event within an ingested batch.
#[derive(Clone, Copy)]
pub enum EventDataRef<'a> {
    Process(&'a ProcessExecEvent),
    File(&'a FileEvent),
    Net(&'a NetEvent),
    DbQuery(&'a DbQueryEvent),
    Heartbeat(&'a AgentHeartbeat),
}

#[derive(Clone, Copy)]
pub struct UnifiedEventRef<'a> {
    pub tenant_id: &'a str,
    pub host_id: &'a str,
    pub batch_id: Option<&'a str>,
    pub ts_unix_ms: u64,
    pub kind: EventFamily,
    pub data: EventDataRef<'a>,
}

impl<'a> UnifiedEventRef<'a> {
    /// Extract a field value by path, stripping alias prefix if present.
    pub fn get_field(&self, path: &str, alias: Option<&str>) -> Value {
        let clean_path = if let Some(a) = alias {
            if path.starts_with(a) && path.as_bytes().get(a.len()) == Some(&b'.') {
                &path[a.len() + 1..]
            } else {
                path
            }
        } else {
            path
        };

        // Top-level envelope fields
        match clean_path {
            "tenant_id" | "tenant" => return Value::Str(self.tenant_id.to_string()),
            "host_id" | "host.id" | "p.host_id" => return Value::Str(self.host_id.to_string()),
            "batch_id" => {
                return self
                    .batch_id
                    .map(|b| Value::Str(b.to_string()))
                    .unwrap_or(Value::Null)
            }
            "ts" | "timestamp" | "ts_unix_ms" => return Value::Int(self.ts_unix_ms as i64),
            "event_type" | "event_kind" | "kind" => {
                return Value::Str(self.kind.as_str().to_string())
            }
            _ => {}
        }

        // Extract by family
        match self.data {
            EventDataRef::Process(p) => get_process_field(p, clean_path),
            EventDataRef::File(f) => get_file_field(f, clean_path),
            EventDataRef::Net(n) => get_net_field(n, clean_path),
            EventDataRef::DbQuery(q) => get_db_query_field(q, clean_path),
            EventDataRef::Heartbeat(h) => get_heartbeat_field(h, clean_path),
        }
    }

    /// Stable content identity for this event.
    ///
    /// Derived only from what the agent observed - never from arrival or
    /// evaluation time - so the same event yields the same key in the hot path
    /// and when replayed later out of a persistent store.
    pub fn identity_key(&self) -> String {
        let body = match self.data {
            EventDataRef::Process(p) => {
                format!("{}|{}|{}|{}", p.pid, p.ppid, p.comm, p.filename)
            }
            EventDataRef::File(f) => format!("{}|{}|{}", f.pid, f.operation, f.path),
            EventDataRef::Net(n) => format!(
                "{}|{}|{}|{}|{}",
                n.pid,
                n.protocol,
                n.direction,
                n.dst_ip.as_deref().unwrap_or(""),
                n.dst_port.unwrap_or(0)
            ),
            EventDataRef::DbQuery(q) => format!(
                "{}|{}|{}|{}|{}",
                q.pid,
                q.db_engine,
                q.operation,
                q.database.as_deref().unwrap_or(""),
                q.statement_fingerprint
            ),
            EventDataRef::Heartbeat(h) => {
                format!("{}|{}", h.agent_version, h.kernel_version)
            }
        };

        format!(
            "{}|{}|{}|{}",
            self.kind.as_str(),
            self.host_id,
            self.ts_unix_ms,
            body
        )
    }

    /// Convert to an owned event for sliding-window buffering.
    pub fn to_owned_event(&self) -> OwnedEvent {
        OwnedEvent {
            tenant_id: self.tenant_id.to_string(),
            host_id: self.host_id.to_string(),
            batch_id: self.batch_id.map(String::from),
            ts_unix_ms: self.ts_unix_ms,
            kind: self.kind,
            data: match self.data {
                EventDataRef::Process(p) => OwnedEventData::Process(p.clone()),
                EventDataRef::File(f) => OwnedEventData::File(f.clone()),
                EventDataRef::Net(n) => OwnedEventData::Net(n.clone()),
                EventDataRef::DbQuery(q) => OwnedEventData::DbQuery(q.clone()),
                EventDataRef::Heartbeat(h) => OwnedEventData::Heartbeat(h.clone()),
            },
        }
    }
}

/// Owned telemetry event stored in correlation window buffers.
#[derive(Clone, Debug)]
pub enum OwnedEventData {
    Process(ProcessExecEvent),
    File(FileEvent),
    Net(NetEvent),
    DbQuery(DbQueryEvent),
    Heartbeat(AgentHeartbeat),
}

#[derive(Clone, Debug)]
pub struct OwnedEvent {
    pub tenant_id: String,
    pub host_id: String,
    pub batch_id: Option<String>,
    pub ts_unix_ms: u64,
    pub kind: EventFamily,
    pub data: OwnedEventData,
}

impl OwnedEvent {
    pub fn as_ref(&self) -> UnifiedEventRef<'_> {
        UnifiedEventRef {
            tenant_id: &self.tenant_id,
            host_id: &self.host_id,
            batch_id: self.batch_id.as_deref(),
            ts_unix_ms: self.ts_unix_ms,
            kind: self.kind,
            data: match &self.data {
                OwnedEventData::Process(p) => EventDataRef::Process(p),
                OwnedEventData::File(f) => EventDataRef::File(f),
                OwnedEventData::Net(n) => EventDataRef::Net(n),
                OwnedEventData::DbQuery(q) => EventDataRef::DbQuery(q),
                OwnedEventData::Heartbeat(h) => EventDataRef::Heartbeat(h),
            },
        }
    }

    pub fn get_field(&self, path: &str, alias: Option<&str>) -> Value {
        self.as_ref().get_field(path, alias)
    }
}

fn get_process_field(p: &ProcessExecEvent, path: &str) -> Value {
    match path {
        "pid" | "process.pid" | "id" | "process_id" => Value::Int(p.pid as i64),
        "ppid" | "process.ppid" | "parent.pid" | "parent.id" => Value::Int(p.ppid as i64),
        "tgid" | "process.tgid" => Value::Int(p.tgid as i64),
        "uid" | "process.uid" | "user.uid" => Value::Int(p.uid as i64),
        "gid" | "process.gid" => Value::Int(p.gid as i64),
        "name" | "comm" | "process.name" | "process.comm" => Value::Str(p.comm.clone()),
        "filename" | "binary.path" | "binary.filename" | "process.binary.filename" => {
            Value::Str(p.filename.clone())
        }
        "elevated" => Value::Bool(p.uid == 0),
        _ => get_attr_or_nested(&p.attrs, path),
    }
}

fn get_file_field(f: &FileEvent, path: &str) -> Value {
    match path {
        "pid" | "process_id" | "file.process_id" => Value::Int(f.pid as i64),
        "tgid" => Value::Int(f.tgid as i64),
        "uid" => Value::Int(f.uid as i64),
        "gid" => Value::Int(f.gid as i64),
        "comm" | "process_name" => Value::Str(f.comm.clone()),
        "path" | "file.path" => Value::Str(f.path.clone()),
        "mode" | "operation" | "file.mode" | "file.operation" => Value::Str(f.operation.clone()),
        _ => get_attr_or_nested(&f.attrs, path),
    }
}

fn get_net_field(n: &NetEvent, path: &str) -> Value {
    match path {
        "pid" | "process_id" | "network.process_id" => Value::Int(n.pid as i64),
        "tgid" => Value::Int(n.tgid as i64),
        "uid" => Value::Int(n.uid as i64),
        "gid" => Value::Int(n.gid as i64),
        "comm" | "process_name" => Value::Str(n.comm.clone()),
        "direction" | "network.direction" => Value::Str(n.direction.clone()),
        "protocol" | "proto" | "network.protocol" => Value::Str(n.protocol.clone()),
        "src_ip" | "network.src_ip" => n
            .src_ip
            .as_deref()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .map(Value::Ip)
            .or_else(|| n.src_ip.clone().map(Value::Str))
            .unwrap_or(Value::Null),
        "dst_ip" | "dest.ip" | "dest_ip" | "network.dest.ip" | "network.dst_ip" => n
            .dst_ip
            .as_deref()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .map(Value::Ip)
            .or_else(|| n.dst_ip.clone().map(Value::Str))
            .unwrap_or(Value::Null),
        "src_port" | "network.src_port" => n
            .src_port
            .map(|p| Value::Int(p as i64))
            .unwrap_or(Value::Null),
        "dst_port" | "dest.port" | "dest_port" | "network.dest.port" | "network.dst_port" => n
            .dst_port
            .map(|p| Value::Int(p as i64))
            .unwrap_or(Value::Null),
        "bytes_out" | "network.bytes_out" => {
            get_attr_number(&n.attrs, "bytes_out").unwrap_or(Value::Int(0))
        }
        "bytes_in" | "network.bytes_in" => {
            get_attr_number(&n.attrs, "bytes_in").unwrap_or(Value::Int(0))
        }
        "dest.domain" | "domain" | "network.dest.domain" => {
            get_attr_str(&n.attrs, "dest.domain").or_else(|| get_attr_str(&n.attrs, "domain"))
                .unwrap_or(Value::Null)
        }
        "dest.reputation" | "reputation" | "network.dest.reputation" => {
            get_attr_str(&n.attrs, "dest.reputation")
                .or_else(|| get_attr_str(&n.attrs, "reputation"))
                .unwrap_or(Value::Null)
        }
        _ => get_attr_or_nested(&n.attrs, path),
    }
}

fn get_db_query_field(q: &DbQueryEvent, path: &str) -> Value {
    match path {
        "pid" | "process_id" | "db.process_id" => Value::Int(q.pid as i64),
        "tgid" => Value::Int(q.tgid as i64),
        "uid" => Value::Int(q.uid as i64),
        "gid" => Value::Int(q.gid as i64),
        "comm" | "process_name" => Value::Str(q.comm.clone()),
        "db_engine" | "engine" | "db.engine" => Value::Str(q.db_engine.clone()),
        "db_server" | "server" | "db.server" => q
            .db_server
            .clone()
            .map(Value::Str)
            .unwrap_or(Value::Null),
        "database" | "db.database" => q
            .database
            .clone()
            .map(Value::Str)
            .unwrap_or(Value::Null),
        "operation" | "db.operation" => Value::Str(q.operation.clone()),
        "statement_fingerprint" | "fingerprint" | "query_hash" => {
            Value::Str(q.statement_fingerprint.clone())
        }
        "tables" | "db.tables" => {
            Value::List(q.tables.iter().map(|t| Value::Str(t.clone())).collect())
        }
        _ => get_attr_or_nested(&q.attrs, path),
    }
}

fn get_heartbeat_field(h: &AgentHeartbeat, path: &str) -> Value {
    match path {
        "agent_version" | "heartbeat.agent_version" => Value::Str(h.agent_version.clone()),
        "kernel_version" | "heartbeat.kernel_version" => Value::Str(h.kernel_version.clone()),
        "events_read_total" => Value::Int(h.events_read_total as i64),
        "events_dropped_total" => Value::Int(h.events_dropped_total as i64),
        "queue_depth" => Value::Int(h.queue_depth as i64),
        _ => get_attr_or_nested(&h.attrs, path),
    }
}

fn get_attr_str(attrs: &HashMap<String, String>, key: &str) -> Option<Value> {
    attrs.get(key).map(|v| Value::Str(v.clone()))
}

fn get_attr_number(attrs: &HashMap<String, String>, key: &str) -> Option<Value> {
    attrs.get(key).and_then(|v| v.parse::<i64>().ok()).map(Value::Int)
}

fn get_attr_or_nested(attrs: &HashMap<String, String>, key: &str) -> Value {
    if let Some(val) = attrs.get(key) {
        if let Ok(num) = val.parse::<i64>() {
            return Value::Int(num);
        }
        if let Ok(b) = val.parse::<bool>() {
            return Value::Bool(b);
        }
        return Value::Str(val.clone());
    }
    Value::Null
}
