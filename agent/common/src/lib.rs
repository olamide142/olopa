//! Shared types between the eBPF kernel programs and the userspace agent.
//! Must be #![no_std] so it compiles for both bpfel-unknown-none and the host.
//!
//! Contract notes:
//! - `#[repr(C)]` keeps ABI layout stable across kernel/userspace boundary.
//! - Any field changes here must be coordinated with:
//!   - eBPF probe writers (`agent/ebpf/src/*`)
//!   - userspace ring-buffer decoders (`agent/agent/src/agent.rs`)
//! - Fixed-size byte arrays are NUL-terminated when sourced from kernel helpers.
//!
//! # Ring-buffer discrimination
//!
//! Every event emitted to the shared ring buffer begins with a `kind: u32` tag
//! holding one of the `EVENT_KIND_*` constants, followed by `pid` so the tag
//! costs no padding against the 8-byte-aligned `ts_ns`.
//!
//! The decoder dispatches on that tag and then checks the payload length
//! against the tagged type. It must never dispatch on length alone: sizes are
//! not unique (`NetEvent` and `SslEvent` are both 48 bytes; `ExecEvent` and
//! `DnsEvent` are both 112), and an earlier length-based decoder silently
//! parsed every `DnsEvent` as a `FileEvent`. Which sizes happen to collide
//! shifts as fields are added — `SqlEvent` left the 48-byte group when it
//! gained `query` — so nothing may start relying on a size being unique.
#![no_std]

/// Process execution event (`ExecEvent`).
pub const EVENT_KIND_EXEC: u32 = 1;
/// File open event (`FileEvent`).
pub const EVENT_KIND_FILE: u32 = 2;
/// Outbound connection event (`NetEvent`).
pub const EVENT_KIND_NET: u32 = 3;
/// SQL query event (`SqlEvent`).
pub const EVENT_KIND_SQL: u32 = 4;
/// TLS encrypt/decrypt event (`SslEvent`).
pub const EVENT_KIND_SSL: u32 = 5;
/// DNS resolution event (`DnsEvent`).
pub const EVENT_KIND_DNS: u32 = 6;
/// TC egress enforcement verdict event (`TcEvent`).
pub const EVENT_KIND_TC: u32 = 7;

/// Local SQL policy protocol request magic (`OLOPASQ1`).
pub const SQL_POLICY_REQUEST_MAGIC: [u8; 8] = *b"OLOPASQ1";
/// Local SQL policy protocol response magic (`OLOPASR1`).
pub const SQL_POLICY_RESPONSE_MAGIC: [u8; 8] = *b"OLOPASR1";
/// Fixed request header: magic, engine, flags, reserved, query length.
pub const SQL_POLICY_REQUEST_HEADER_LEN: usize = 16;
/// Fixed response: magic, verdict, policy mode, reserved.
pub const SQL_POLICY_RESPONSE_LEN: usize = 12;
/// Maximum raw statement bytes accepted over the local policy socket.
pub const SQL_POLICY_MAX_QUERY_LEN: usize = 8 * 1024;

pub const SQL_POLICY_ENGINE_POSTGRES: u8 = 1;
pub const SQL_POLICY_ENGINE_MYSQL: u8 = 2;
pub const SQL_POLICY_FLAG_PREPARED: u8 = 1;

pub const SQL_POLICY_VERDICT_ALLOW: u8 = 0;
pub const SQL_POLICY_VERDICT_BLOCK: u8 = 1;
pub const SQL_POLICY_VERDICT_ERROR: u8 = 2;

pub const SQL_POLICY_MODE_OBSERVE: u8 = 0;
pub const SQL_POLICY_MODE_ENFORCE: u8 = 1;

/// SQL telemetry did not originate from the synchronous guard.
pub const SQL_POLICY_EVENT_UNGUARDED: u8 = 0;
/// The synchronous guard allowed the statement.
pub const SQL_POLICY_EVENT_ALLOWED: u8 = 1;
/// Observe mode matched a block action but allowed the statement.
pub const SQL_POLICY_EVENT_WOULD_BLOCK: u8 = 2;
/// Enforce mode blocked the statement before the real client call.
pub const SQL_POLICY_EVENT_BLOCKED: u8 = 3;

/// Process execution event (execve / execveat syscall)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub kind: u32, // EVENT_KIND_EXEC
    pub pid: u32,
    pub ts_ns: u64,
    /// Stable cgroup-v2 identifier returned by `bpf_get_current_cgroup_id`.
    pub cgroup_id: u64,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub argv_hash: u32,     // simple hash of the full argv string
    pub comm: [u8; 16],     // TASK_COMM_LEN — kernel-enforced max
    pub filename: [u8; 64], // truncated path of the executable
}

/// File open/read/write event (openat syscall)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub kind: u32, // EVENT_KIND_FILE
    pub pid: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub flags: u32, // O_RDONLY / O_WRONLY / O_RDWR etc.
    pub comm: [u8; 16],
    pub filename: [u8; 64],
}

/// Outbound network connection event (connect syscall)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub kind: u32, // EVENT_KIND_NET
    pub pid: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub dst_ip: u32, // IPv4 big-endian
    pub dst_port: u16,
    pub proto: u8, // IPPROTO_TCP=6 IPPROTO_UDP=17
    pub _pad: u8,
    pub comm: [u8; 16],
}

/// Bytes of statement text captured by the SQL uprobes.
///
/// Enough to cover the table-bearing prefix of most statements while staying
/// within eBPF stack/copy limits.
pub const SQL_QUERY_LEN: usize = 128;

/// SQL query event (uprobe on PQexec / mysql_real_query)
///
/// `query` holds **raw, unredacted** statement text and may contain literal
/// values. It exists so userspace can derive table names and a normalized
/// fingerprint; it is redacted at ring-buffer decode time and must never be
/// copied into an outbound payload or persisted. See
/// `olopa::sql_norm::redact_statement`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SqlEvent {
    pub kind: u32, // EVENT_KIND_SQL
    pub pid: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub query_hash: u32, // FNV-1a hash of first SQL_QUERY_LEN bytes of query text
    pub db_port: u16,    // 5432 (postgres) or 3306 (mysql); 0 if unknown
    pub query_class: u8, // 0=other 1=select 2=dml 3=ddl 4=admin
    pub _pad: u8,
    pub comm: [u8; 16],             // TASK_COMM_LEN
    pub query: [u8; SQL_QUERY_LEN], // NUL-terminated, truncated statement text
}

/// TLS/OpenSSL encryption event (uprobe on EVP_EncryptUpdate / EVP_DecryptUpdate)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SslEvent {
    pub kind: u32, // EVENT_KIND_SSL
    pub pid: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub data_len: u32, // input bytes processed in this call
    pub operation: u8, // 0=encrypt 1=decrypt
    pub _pad: [u8; 3],
    pub comm: [u8; 16], // TASK_COMM_LEN
}

/// DNS name resolution event (uprobe on libc getaddrinfo).
///
/// Fires on the process that initiated the lookup, capturing the hostname
/// before the kernel resolver runs.  Useful for detecting C2 callback domains,
/// DGA patterns, and data-exfiltration via DNS.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub kind: u32, // EVENT_KIND_DNS
    pub pid: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub query_hash: u32, // FNV-1a hash of `query` up to NUL
    pub query_len: u16,  // byte length of query string (capped at 63)
    pub _pad: [u8; 2],
    pub comm: [u8; 16],  // TASK_COMM_LEN
    pub query: [u8; 64], // NUL-terminated queried hostname (truncated to 63 chars)
}

/// XDP packet verdict counters — stored in a BPF array map, index = action
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XdpStats {
    pub passed: u64,
    pub dropped: u64,
    pub redirected: u64,
}

/// TC (traffic control) packet event — egress hook
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcEvent {
    pub kind: u32, // EVENT_KIND_TC
    pub pid: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub proto: u8,
    pub direction: u8, // 0 = ingress, 1 = egress
    pub verdict: u8,   // 0 = allow, 1 = deny
    pub _pad: [u8; 3],
    pub comm: [u8; 16],
}

pub const TC_VERDICT_ALLOW: u8 = 0;
pub const TC_VERDICT_DENY: u8 = 1;

/// TC egress policy key used by kernel/userspace shared policy maps.
///
/// Matching supports process, cgroup, and global scopes. A zero `pid` or
/// `cgroup_id` is a wildcard inserted intentionally by userspace.
///
/// Fields are normalized for stable userspace insertion and kernel lookup:
/// - `dst_ip` uses canonical `u32::from(Ipv4Addr)` form (for example `1.2.3.4 -> 0x01020304`).
/// - `dst_port` is host-order numeric port (e.g. 443).
/// - `proto` is IANA protocol number (6=tcp, 17=udp).
/// - `_pad` keeps the key naturally aligned for BPF map value access.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcEgressPolicyKey {
    pub cgroup_id: u64,
    pub pid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// Allow decision for TC egress policy map values.
///
/// Current TC program default is allow when no rule matches.
pub const TC_POLICY_ACTION_ALLOW: u8 = 0;
/// Deny decision for TC egress policy map values.
///
/// TC enforcement path maps this to `TC_ACT_SHOT`.
pub const TC_POLICY_ACTION_DENY: u8 = 1;
/// Rate-limit decision. Parameters are stored in `TC_EGRESS_RATE_CONFIG`.
pub const TC_POLICY_ACTION_RATE_LIMIT: u8 = 2;

/// Packet token-bucket configuration for a TC policy key.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TcRateLimitConfig {
    pub packets_per_second: u32,
    pub burst: u32,
}

/// Mutable kernel token-bucket state for a rate-limited TC policy key.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcRateLimitState {
    pub last_refill_ns: u64,
    pub tokens: u32,
    pub _pad: u32,
}

// Safety: all fields are plain integer types — safe to send across the
// kernel/userspace boundary via the ring buffer.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcEgressPolicyKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcRateLimitConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcRateLimitState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for XdpStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SqlEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SslEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}
