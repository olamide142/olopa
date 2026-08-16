//! Network connection probe — tracepoint on sys_enter_connect.
//!
//! Fires on every outbound TCP/UDP connect attempt.
//! Combined with exec_probe, enables kill chain reconstruction:
//!   nginx (1241) spawned bash (4821) → bash connected to 185.x.x.x:4444
//!
//! sys_enter_connect args (after tracepoint common header):
//!   ctx.read_at(16): int fd
//!   ctx.read_at(24): struct sockaddr* addr
//!   ctx.read_at(32): int addrlen
//!
//! Strategy: do ALL validation before reserving the ring buffer slot.
//! This avoids needing to discard on most early-exit paths.
//!
//! Current scope:
//! - IPv4 connect events only (AF_INET).
//! - IPv6 can be added later with sockaddr_in6 decoding and wider payload.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use olopa_common::{NetEvent, EVENT_KIND_NET};

use crate::EVENTS;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

#[tracepoint]
pub fn on_connect(ctx: TracePointContext) -> u32 {
    unsafe { try_connect(&ctx) }
}

unsafe fn try_connect(ctx: &TracePointContext) -> u32 {
    const AF_INET: u16 = 2;

    // fd is currently unused but still parsed to keep offsets explicit.
    let fd_raw: i64 = match ctx.read_at(16) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let _fd = fd_raw as i32;

    let addr_ptr: u64 = match ctx.read_at(24) {
        Ok(p) => p,
        Err(_) => return 1,
    };
    if addr_ptr == 0 {
        return 0;
    }

    let addrlen_raw: i64 = match ctx.read_at(32) {
        Ok(v) => v,
        Err(_) => return 1,
    };
    let addrlen = addrlen_raw as i32;

    if addrlen < core::mem::size_of::<SockAddrIn>() as i32 {
        return 0;
    }

    let family: u16 = match bpf_probe_read_user(addr_ptr as *const u16) {
        Ok(f) => f,
        Err(_) => return 1,
    };

    if family != AF_INET {
        return 0;
    }

    let addr: SockAddrIn = match bpf_probe_read_user(addr_ptr as *const SockAddrIn) {
        Ok(a) => a,
        Err(_) => return 1,
    };

    let mut entry = match EVENTS.reserve::<NetEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_NET;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();
    // Keep network-byte-order values in the event payload.
    // Userspace is responsible for converting for display.
    (*event).dst_ip = addr.sin_addr;
    (*event).dst_port = addr.sin_port;
    (*event).proto = 6;
    (*event)._pad = 0;

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

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
