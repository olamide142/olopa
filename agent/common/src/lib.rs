//! Shared types between the eBPF kernel programs and the userspace agent.
//! Must be #![no_std] so it compiles for both bpfel-unknown-none and the host.
//!
//! Contract notes:
//! - `#[repr(C)]` keeps ABI layout stable across kernel/userspace boundary.
//! - Any field changes here must be coordinated with:
//!   - eBPF probe writers (`agent/ebpf/src/*`)
//!   - userspace ring-buffer decoders (`agent/agent/src/agent.rs`)
//! - Fixed-size byte arrays are NUL-terminated when sourced from kernel helpers.
#![no_std]

/// Process execution event (execve / execveat syscall)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],     // TASK_COMM_LEN — kernel-enforced max
    pub filename: [u8; 64], // truncated path of the executable
    pub argv_hash: u32,     // simple hash of the full argv string
}

/// File open/read/write event (openat syscall)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32, // O_RDONLY / O_WRONLY / O_RDWR etc.
    pub comm: [u8; 16],
    pub filename: [u8; 64],
}

/// Outbound network connection event (connect syscall)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub dst_ip: u32, // IPv4 big-endian
    pub dst_port: u16,
    pub proto: u8, // IPPROTO_TCP=6 IPPROTO_UDP=17
    pub _pad: u8,
    pub comm: [u8; 16],
}

/// SQL query event (uprobe on PQexec / mysql_real_query)
///
/// Size: 48 bytes (unique — avoids ring-buffer size collision with NetEvent/SslEvent).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SqlEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],     // TASK_COMM_LEN
    pub query_hash: u32,    // FNV-1a hash of first 128 bytes of query text
    pub query_class: u8,    // 0=other 1=select 2=dml 3=ddl 4=admin
    pub db_port: u16,       // 5432 (postgres) or 3306 (mysql); 0 if unknown
    pub _pad: u8,
    pub _ext: [u8; 8],      // reserved — keeps struct size unique (48 bytes)
}

/// TLS/OpenSSL encryption event (uprobe on EVP_EncryptUpdate / EVP_DecryptUpdate)
///
/// Size: 44 bytes (unique — avoids ring-buffer size collision with NetEvent/SqlEvent).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SslEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],    // TASK_COMM_LEN
    pub data_len: u32,     // input bytes processed in this call
    pub operation: u8,     // 0=encrypt 1=decrypt
    pub _pad: [u8; 7],     // extended to 7 bytes to reach 44-byte unique size
}

/// DNS name resolution event (uprobe on libc getaddrinfo).
///
/// Fires on the process that initiated the lookup, capturing the hostname
/// before the kernel resolver runs.  Useful for detecting C2 callback domains,
/// DGA patterns, and data-exfiltration via DNS.
///
/// Size: 104 bytes (unique).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],    // TASK_COMM_LEN
    pub query: [u8; 64],   // NUL-terminated queried hostname (truncated to 63 chars)
    pub query_hash: u32,   // FNV-1a hash of `query` up to NUL
    pub query_len: u16,    // byte length of query string (capped at 63)
    pub _pad: [u8; 2],
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
    pub ts_ns: u64,
    pub pid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub proto: u8,
    pub direction: u8, // 0 = ingress, 1 = egress
}

/// TC egress policy key used by kernel/userspace shared policy maps.
///
/// Matching is exact on all fields (`pid + ip + port + proto`).
///
/// Fields are normalized for stable userspace insertion and kernel lookup:
/// - `dst_ip` uses canonical `u32::from(Ipv4Addr)` form (for example `1.2.3.4 -> 0x01020304`).
/// - `dst_port` is host-order numeric port (e.g. 443).
/// - `proto` is IANA protocol number (6=tcp, 17=udp).
/// - `_pad` keeps the key naturally aligned for BPF map value access.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcEgressPolicyKey {
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
unsafe impl aya::Pod for XdpStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SqlEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SslEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}
