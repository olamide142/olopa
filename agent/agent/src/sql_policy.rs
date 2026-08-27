//! Synchronous SQL policy service for client-library guards.
//!
//! A guarded process sends statement text over a local Unix socket before it
//! calls libpq/libmysqlclient. The main agent loop evaluates the same runtime
//! OIL program used for kernel events and replies before the database client
//! function runs. Raw SQL is bounded, redacted in the main loop, and never
//! logged or persisted.

use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use log::{info, warn};
use olopa_common::{
    SQL_POLICY_ENGINE_MYSQL, SQL_POLICY_ENGINE_POSTGRES, SQL_POLICY_MAX_QUERY_LEN,
    SQL_POLICY_MODE_ENFORCE, SQL_POLICY_MODE_OBSERVE, SQL_POLICY_REQUEST_HEADER_LEN,
    SQL_POLICY_REQUEST_MAGIC, SQL_POLICY_RESPONSE_LEN, SQL_POLICY_RESPONSE_MAGIC,
    SQL_POLICY_VERDICT_ERROR,
};

use crate::agent::IngestEvent;
use crate::sql_norm;

const DEFAULT_SOCKET_PATH: &str = "/run/olopa/sql-policy.sock";
const DEFAULT_TIMEOUT_MS: u64 = 250;
const DEFAULT_WORKERS: usize = 4;
const DEFAULT_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlPolicyMode {
    Observe,
    Enforce,
}

impl SqlPolicyMode {
    fn from_env() -> Result<Self> {
        match std::env::var("OLOPA_SQL_POLICY_MODE")
            .unwrap_or_else(|_| "observe".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            value => bail!(
                "invalid OLOPA_SQL_POLICY_MODE '{}': expected observe or enforce",
                value
            ),
        }
    }

    pub fn wire_value(self) -> u8 {
        match self {
            Self::Observe => SQL_POLICY_MODE_OBSERVE,
            Self::Enforce => SQL_POLICY_MODE_ENFORCE,
        }
    }

    pub fn enforces(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

#[derive(Debug)]
pub struct SqlPolicyRequest {
    pub peer_pid: u32,
    pub peer_uid: u32,
    pub engine: u8,
    pub flags: u8,
    pub query: Vec<u8>,
    reply: SyncSender<SqlPolicyDecision>,
}

impl SqlPolicyRequest {
    pub fn reply(self, verdict: u8, mode: SqlPolicyMode) {
        let _ = self.reply.send(SqlPolicyDecision { verdict, mode });
    }
}

#[derive(Clone, Copy, Debug)]
struct SqlPolicyDecision {
    verdict: u8,
    mode: SqlPolicyMode,
}

pub struct SqlPolicyService {
    pub requests: Receiver<SqlPolicyRequest>,
    pub mode: SqlPolicyMode,
    pub socket_path: PathBuf,
}

/// Start the policy socket when explicitly enabled.
pub fn spawn_from_env() -> Result<Option<SqlPolicyService>> {
    if !env_flag("OLOPA_SQL_POLICY_ENABLED") {
        return Ok(None);
    }

    let mode = SqlPolicyMode::from_env()?;
    let socket_path = std::env::var("OLOPA_SQL_POLICY_SOCKET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
    let timeout = Duration::from_millis(
        env_usize("OLOPA_SQL_POLICY_TIMEOUT_MS", DEFAULT_TIMEOUT_MS as usize).max(1) as u64,
    );
    let workers = env_usize("OLOPA_SQL_POLICY_WORKERS", DEFAULT_WORKERS).clamp(1, 64);
    let queue_capacity =
        env_usize("OLOPA_SQL_POLICY_QUEUE_CAPACITY", DEFAULT_QUEUE_CAPACITY).clamp(workers, 65_536);

    prepare_socket_path(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind SQL policy socket {}", socket_path.display()))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("set permissions on {}", socket_path.display()))?;
    if let Some(gid) = std::env::var("OLOPA_SQL_POLICY_GID")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
    {
        let path = CString::new(socket_path.as_os_str().as_bytes())
            .context("SQL policy socket path contains a NUL byte")?;
        // SAFETY: path is a valid NUL-terminated filesystem path. A uid of -1
        // leaves ownership unchanged while assigning the configured group.
        let result = unsafe { libc::chown(path.as_ptr(), u32::MAX, gid) };
        if result != 0 {
            return Err(io::Error::last_os_error()).with_context(|| {
                format!(
                    "set group {} on SQL policy socket {}",
                    gid,
                    socket_path.display()
                )
            });
        }
    }

    let (request_tx, request_rx) = mpsc::sync_channel(queue_capacity);
    let (stream_tx, stream_rx) = mpsc::sync_channel::<UnixStream>(workers * 4);
    let shared_stream_rx = Arc::new(Mutex::new(stream_rx));

    for worker_id in 0..workers {
        let streams = Arc::clone(&shared_stream_rx);
        let requests = request_tx.clone();
        thread::Builder::new()
            .name(format!("olopa-sql-policy-{worker_id}"))
            .spawn(move || worker_loop(streams, requests, timeout))
            .context("spawn SQL policy worker")?;
    }

    let listener_path = socket_path.clone();
    thread::Builder::new()
        .name("olopa-sql-policy-listener".to_string())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        if stream_tx.send(stream).is_err() {
                            break;
                        }
                    }
                    Err(error) => warn!(
                        "SQL policy socket accept failed path={}: {}",
                        listener_path.display(),
                        error
                    ),
                }
            }
        })
        .context("spawn SQL policy listener")?;

    info!(
        "SQL policy service listening path={} mode={:?} workers={}",
        socket_path.display(),
        mode,
        workers
    );
    Ok(Some(SqlPolicyService {
        requests: request_rx,
        mode,
        socket_path,
    }))
}

fn worker_loop(
    streams: Arc<Mutex<Receiver<UnixStream>>>,
    requests: SyncSender<SqlPolicyRequest>,
    timeout: Duration,
) {
    loop {
        let stream = {
            let receiver = streams
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            receiver.recv()
        };
        let Ok(stream) = stream else {
            return;
        };
        if let Err(error) = handle_stream(stream, &requests, timeout) {
            warn!("SQL policy request rejected: {}", error);
        }
    }
}

fn handle_stream(
    mut stream: UnixStream,
    requests: &SyncSender<SqlPolicyRequest>,
    timeout: Duration,
) -> Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let (peer_pid, peer_uid) = peer_credentials(&stream)?;
    let mut header = [0u8; SQL_POLICY_REQUEST_HEADER_LEN];
    stream.read_exact(&mut header)?;
    if header[..8] != SQL_POLICY_REQUEST_MAGIC {
        write_response(
            &mut stream,
            SQL_POLICY_VERDICT_ERROR,
            SqlPolicyMode::Observe,
        )?;
        bail!("invalid request magic from pid={peer_pid}");
    }

    let engine = header[8];
    if !matches!(engine, SQL_POLICY_ENGINE_POSTGRES | SQL_POLICY_ENGINE_MYSQL) {
        write_response(
            &mut stream,
            SQL_POLICY_VERDICT_ERROR,
            SqlPolicyMode::Observe,
        )?;
        bail!("unsupported database engine {} from pid={peer_pid}", engine);
    }
    let flags = header[9];
    let query_len = u32::from_le_bytes(header[12..16].try_into().expect("fixed header")) as usize;
    if query_len == 0 || query_len > SQL_POLICY_MAX_QUERY_LEN {
        write_response(
            &mut stream,
            SQL_POLICY_VERDICT_ERROR,
            SqlPolicyMode::Observe,
        )?;
        bail!("invalid query length {} from pid={peer_pid}", query_len);
    }

    let mut query = vec![0u8; query_len];
    stream.read_exact(&mut query)?;
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if requests
        .try_send(SqlPolicyRequest {
            peer_pid,
            peer_uid,
            engine,
            flags,
            query,
            reply: reply_tx,
        })
        .is_err()
    {
        write_response(
            &mut stream,
            SQL_POLICY_VERDICT_ERROR,
            SqlPolicyMode::Observe,
        )?;
        bail!("agent SQL policy queue unavailable for pid={peer_pid}");
    }

    let decision = reply_rx
        .recv_timeout(timeout)
        .context("agent SQL policy verdict timed out")?;
    write_response(&mut stream, decision.verdict, decision.mode)?;
    Ok(())
}

/// Convert a guarded statement to the canonical event form without retaining
/// its raw text. The request owns the only raw buffer and is dropped after the
/// verdict is sent.
pub fn event_from_request(request: &SqlPolicyRequest) -> IngestEvent {
    let raw = String::from_utf8_lossy(&request.query);
    let redacted = sql_norm::redact_statement(&raw);
    let tables = sql_norm::extract_tables(&redacted);
    let query_class = sql_norm::classify_statement(&redacted);
    let mut comm = [0u8; 16];
    if let Ok(value) = fs::read(format!("/proc/{}/comm", request.peer_pid)) {
        let length = value
            .iter()
            .position(|byte| matches!(*byte, 0 | b'\n'))
            .unwrap_or(value.len())
            .min(comm.len().saturating_sub(1));
        comm[..length].copy_from_slice(&value[..length]);
    }

    let query_hash = fnv1a_32(&request.query);
    IngestEvent {
        ts_ns: now_unix_ns(),
        cgroup_id: cgroup_id_for_pid(request.peer_pid).unwrap_or(0),
        pid: request.peer_pid,
        uid: request.peer_uid,
        event_type: 4,
        vertex_id: request.peer_pid,
        dst_vertex_id: query_hash,
        net_dst_ip: 0,
        net_dst_port: 0,
        comm,
        comm_id: fnv1a_32(&comm),
        risk_score: match query_class {
            3 => 0.85,
            4 => 0.90,
            _ => 0.40,
        },
        sql_query_hash: query_hash,
        sql_query_class: query_class,
        sql_db_port: match request.engine {
            SQL_POLICY_ENGINE_POSTGRES => 5432,
            SQL_POLICY_ENGINE_MYSQL => 3306,
            _ => 0,
        },
        sql_norm_hash: sql_norm::normalized_fingerprint(&redacted),
        sql_tables: sql_norm::pack_tables(&tables),
        ssl_data_len: 0,
        ssl_operation: 0,
        _pad_aux: [
            0,
            u8::from(request.flags & olopa_common::SQL_POLICY_FLAG_PREPARED != 0),
        ],
        dns_query_hash: 0,
        dns_query: [0; 64],
        tc_verdict: 0,
    }
}

fn cgroup_id_for_pid(pid: u32) -> Option<u64> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim_start_matches('/');
    let root = std::env::var("OLOPA_CGROUP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));
    fs::metadata(root.join(relative))
        .ok()
        .map(|metadata| metadata.ino())
}

fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in bytes {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn now_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

fn write_response(stream: &mut UnixStream, verdict: u8, mode: SqlPolicyMode) -> io::Result<()> {
    let mut response = [0u8; SQL_POLICY_RESPONSE_LEN];
    response[..8].copy_from_slice(&SQL_POLICY_RESPONSE_MAGIC);
    response[8] = verdict;
    response[9] = mode.wire_value();
    stream.write_all(&response)
}

fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output pointer and its length describe a live ucred value,
    // and the file descriptor belongs to the borrowed UnixStream.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((credentials.pid.max(0) as u32, credentials.uid))
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("SQL policy socket needs a parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create SQL policy socket directory {}", parent.display()))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)
            .with_context(|| format!("remove stale SQL policy socket {}", path.display())),
        Ok(_) => bail!(
            "refusing to replace non-socket SQL policy path {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect SQL policy socket path {}", path.display()))
        }
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_match_current_process() {
        let (left, right) = UnixStream::pair().expect("UnixStream pair");
        let (pid, uid) = match peer_credentials(&left) {
            Ok(credentials) => credentials,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                // The repository test sandbox blocks SO_PEERCRED. Production
                // startup requires it and rejects requests if it is denied.
                return;
            }
            Err(error) => panic!("peer credentials: {error}"),
        };
        assert_eq!(pid, std::process::id());
        // SAFETY: getuid has no preconditions.
        assert_eq!(uid, unsafe { libc::getuid() });
        drop(right);
    }

    #[test]
    fn refuses_to_replace_a_regular_file() {
        let path =
            std::env::temp_dir().join(format!("olopa-sql-policy-regular-{}", std::process::id()));
        fs::write(&path, b"keep").expect("write fixture");
        let error = prepare_socket_path(&path).expect_err("regular file must be preserved");
        assert!(error.to_string().contains("refusing to replace non-socket"));
        assert_eq!(fs::read(&path).expect("fixture retained"), b"keep");
        fs::remove_file(path).expect("remove fixture");
    }
}
