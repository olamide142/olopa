//! DNS resolution uprobe — hook on libc `getaddrinfo`.
//!
//! `getaddrinfo` is the POSIX resolver entry point used by virtually every
//! userspace application that resolves hostnames.  Hooking it gives us the
//! queried name before it hits the kernel resolver or the DNS wire, making
//! it suitable for:
//!   - C2 callback domain detection
//!   - DGA (Domain Generation Algorithm) pattern detection via high entropy
//!   - Data-exfiltration tracking via DNS tunnelling (long subdomain labels)
//!
//! Signature:
//!   int getaddrinfo(const char *node, const char *service,
//!                   const struct addrinfo *hints, struct addrinfo **res)
//!
//! Argument layout (0-indexed):
//!   arg 0 = `node`    - hostname string (what we capture)
//!   arg 1 = `service` - port/service string (ignored here)
//!   arg 2 = `hints`   - addrinfo struct pointer (ignored)
//!   arg 3 = `res`     - result pointer (ignored; return path not hooked)
//!
//! VERIFIER RULE: after bpf_ringbuf_reserve() succeeds, every exit path must
//! call entry.submit(0) or entry.discard(0). Never use ? after reservation.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::uprobe,
    programs::ProbeContext,
};
use olopa_common::{DnsEvent, EVENT_KIND_DNS};

use crate::EVENTS;

/// Maximum hostname length we capture and hash.
/// DNS labels are ≤ 63 chars; full FQDN ≤ 253 chars.
/// 63 bytes fits comfortably in one eBPF stack frame and covers ~99% of queries.
const NAME_BUF_LEN: usize = 64;

/// Uprobe on libc `getaddrinfo`.
/// Fires whenever any process calls getaddrinfo(), capturing the target hostname.
#[uprobe]
pub fn uprobe_getaddrinfo(ctx: ProbeContext) -> u32 {
    unsafe { try_dns_query(&ctx) }
}

/// Core DNS query event handler.
///
/// Reads the `node` argument (arg 0), hashes it, and emits a DnsEvent to the
/// shared ring buffer.  Null hostname pointer is silently discarded.
unsafe fn try_dns_query(ctx: &ProbeContext) -> u32 {
    let mut entry = match EVENTS.reserve::<DnsEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    // After reservation every exit path must submit or discard.
    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_DNS;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

    (*event).comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    // arg 0 = `const char *node` — hostname being resolved.
    let node_ptr: u64 = match ctx.arg(0_usize) {
        Some(p) => p,
        None => {
            // No node arg — null lookup (getaddrinfo(NULL, ...) uses local hostname).
            // Zero out the query fields and still emit; rules can filter on empty.
            (*event).query = [0u8; NAME_BUF_LEN];
            (*event).query_hash = 0;
            (*event).query_len = 0;
            (*event)._pad = [0u8; 2];
            entry.submit(0);
            return 0;
        }
    };

    if node_ptr == 0 {
        (*event).query = [0u8; NAME_BUF_LEN];
        (*event).query_hash = 0;
        (*event).query_len = 0;
        (*event)._pad = [0u8; 2];
        entry.submit(0);
        return 0;
    }

    // Copy hostname into event buffer; bpf_probe_read_user_str_bytes NUL-terminates.
    let mut buf = [0u8; NAME_BUF_LEN];
    let read_len = match bpf_probe_read_user_str_bytes(node_ptr as *const u8, &mut buf) {
        Ok(bytes) => bytes.len(),
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    (*event).query = buf;
    (*event).query_hash = fnv1a_hash(&buf);
    // query_len = number of hostname bytes excluding the NUL terminator.
    let name_len = if read_len > 0 { read_len - 1 } else { 0 };
    (*event).query_len = name_len.min(NAME_BUF_LEN - 1) as u16;
    (*event)._pad = [0u8; 2];

    entry.submit(0);
    0
}

/// FNV-1a 32-bit hash over the hostname buffer up to the first NUL byte.
///
/// Bounded loop (NAME_BUF_LEN iterations max) — safe for the BPF verifier.
#[inline(always)]
fn fnv1a_hash(buf: &[u8; NAME_BUF_LEN]) -> u32 {
    const OFFSET_BASIS: u32 = 2_166_136_261;
    const PRIME: u32 = 16_777_619;

    let mut hash = OFFSET_BASIS;
    let mut i = 0usize;

    while i < NAME_BUF_LEN {
        let b = buf[i];
        if b == 0 {
            break;
        }
        hash ^= b as u32;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}
