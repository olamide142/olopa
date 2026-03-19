//! Network connection probe — tracepoint on sys_enter_connect.
//!
//! Fires on every outbound TCP/UDP connect attempt.
//! Combined with exec_probe, enables kill chain reconstruction:
//!   nginx (1241) spawned bash (4821) → bash connected to 185.x.x.x:4444
//!
//! sys_enter_connect args:
//!   offset  0: int fd
//!   offset  8: struct sockaddr* addr
//!   offset 16: int addrlen
//!
//! Strategy: do ALL validation before reserving the ring buffer slot.
//! This avoids needing to discard on most early-exit paths.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use olopa_common::NetEvent;

use crate::EVENTS;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrIn {
    sin_family: u16,
    sin_port:   u16,
    sin_addr:   u32,
}

#[tracepoint]
pub fn on_connect(ctx: TracePointContext) -> u32 {
    unsafe { try_connect(&ctx) }
}

unsafe fn try_connect(ctx: &TracePointContext) -> u32 {
    // All validation happens BEFORE reservation — clean early returns, no discard needed.

    let addr_ptr: u64 = match ctx.read_at(8) {
        Ok(p) => p,
        Err(_) => return 1,
    };
    if addr_ptr == 0 {
        return 0;
    }

    // Check address family — only IPv4 (AF_INET=2) for now
    let _family: u16 = match bpf_probe_read_user(addr_ptr as *const u16) {
        Ok(f) => f,
        Err(_) => return 1,
    };

    // Read full sockaddr_in
    let addr: SockAddrIn = match bpf_probe_read_user(addr_ptr as *const SockAddrIn) {
        Ok(a) => a,
        Err(_) => return 1,
    };

    // Skip loopback 127.x.x.x
    if addr.sin_addr & 0xFF == 0x7F {
        return 0;
    }

    // Validation done — now reserve. Only one exit path from here: submit.
    let mut entry = match EVENTS.reserve::<NetEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    let event = entry.as_mut_ptr();

    (*event).ts_ns    = bpf_ktime_get_ns();
    (*event).dst_ip   = addr.sin_addr;
    (*event).dst_port = addr.sin_port;
    (*event).proto    = 6; // TCP
    (*event)._pad     = 0;

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid = (pid_tgid >> 32) as u32;

    let uid_gid  = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

    // bpf_get_current_comm() takes no args — returns Result<[u8; 16], i64>
    (*event).comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    entry.submit(0);
    0
}