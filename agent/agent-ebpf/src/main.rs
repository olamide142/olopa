#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{cgroup_sock_addr, map, tracepoint};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{SockAddrContext, TracePointContext};
use aya_log_ebpf::info;

// Policy maps (filled by userspace):
// - IP/port/process-level block lists
// - allow-list for privileged workloads
#[map(name = "BLOCKED_IPV4")]
static BLOCKED_IPV4: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

#[map(name = "BLOCKED_PORTS")]
static BLOCKED_PORTS: HashMap<u32, u8> = HashMap::with_max_entries(2048, 0);

#[map(name = "BLOCKED_TGIDS")]
static BLOCKED_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(2048, 0);

#[map(name = "ALLOW_TGIDS")]
static ALLOW_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(2048, 0);

// Counter map used by userspace response loop.
#[map(name = "VIOLATION_COUNTS")]
static VIOLATION_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(8192, 0);

macro_rules! simple_tracepoint {
    ($section:ident, $program:ident, $message:literal) => {
        #[tracepoint(name = stringify!($program))]
        pub fn $program(ctx: TracePointContext) -> u32 {
            match unsafe { $section(ctx) } {
                Ok(ret) => ret,
                Err(_) => 1,
            }
        }

        unsafe fn $section(ctx: TracePointContext) -> Result<u32, ()> {
            info!(&ctx, $message);
            Ok(0)
        }
    };
}

simple_tracepoint!(on_exec, trace_exec, "execve observed");
simple_tracepoint!(on_openat2, trace_openat2, "openat2 observed");
simple_tracepoint!(on_openat, trace_openat, "openat observed");
simple_tracepoint!(on_read, trace_read, "read observed");
simple_tracepoint!(on_write, trace_write, "write observed");
simple_tracepoint!(on_close, trace_close, "close observed");
simple_tracepoint!(on_unlinkat, trace_unlinkat, "unlinkat observed");
simple_tracepoint!(on_renameat2, trace_renameat2, "renameat2 observed");
simple_tracepoint!(on_socket, trace_socket, "socket observed");
simple_tracepoint!(on_bind, trace_bind, "bind observed");
simple_tracepoint!(on_listen, trace_listen, "listen observed");
simple_tracepoint!(on_accept4, trace_accept4, "accept4 observed");
simple_tracepoint!(on_connect, trace_connect, "connect observed");
simple_tracepoint!(on_sendto, trace_sendto, "sendto observed");
simple_tracepoint!(on_recvfrom, trace_recvfrom, "recvfrom observed");
simple_tracepoint!(on_sendmsg, trace_sendmsg, "sendmsg observed");
simple_tracepoint!(on_recvmsg, trace_recvmsg, "recvmsg observed");
simple_tracepoint!(on_shutdown, trace_shutdown, "shutdown observed");
simple_tracepoint!(on_setsockopt, trace_setsockopt, "setsockopt observed");

#[cgroup_sock_addr(connect4, name = "enforce_connect4")]
pub fn enforce_connect4(ctx: SockAddrContext) -> i32 {
    match unsafe { try_enforce_connect4(ctx) } {
        Ok(v) => v,
        Err(_) => 1,
    }
}

unsafe fn try_enforce_connect4(ctx: SockAddrContext) -> Result<i32, ()> {
    let sa = ctx.sock_addr;
    if sa.is_null() {
        return Ok(1);
    }

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if is_allowed_tgid(tgid) {
        return Ok(1);
    }

    let blocked =
        is_blocked_tgid(tgid) || is_blocked_ipv4((*sa).user_ip4) || is_blocked_port((*sa).user_port);
    if blocked {
        bump_violation(tgid);
        info!(&ctx, "connect4 denied");
        return Ok(0);
    }
    Ok(1)
}

#[cgroup_sock_addr(connect6, name = "enforce_connect6")]
pub fn enforce_connect6(ctx: SockAddrContext) -> i32 {
    match unsafe { try_enforce_connect6(ctx) } {
        Ok(v) => v,
        Err(_) => 1,
    }
}

unsafe fn try_enforce_connect6(ctx: SockAddrContext) -> Result<i32, ()> {
    let sa = ctx.sock_addr;
    if sa.is_null() {
        return Ok(1);
    }

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if is_allowed_tgid(tgid) {
        return Ok(1);
    }

    if is_blocked_tgid(tgid) || is_blocked_port((*sa).user_port) {
        bump_violation(tgid);
        info!(&ctx, "connect6 denied");
        return Ok(0);
    }
    Ok(1)
}

unsafe fn is_allowed_tgid(tgid: u32) -> bool {
    ALLOW_TGIDS.get(&tgid).is_some()
}

unsafe fn is_blocked_tgid(tgid: u32) -> bool {
    BLOCKED_TGIDS.get(&tgid).is_some()
}

unsafe fn is_blocked_ipv4(ip: u32) -> bool {
    BLOCKED_IPV4.get(&ip).is_some()
}

unsafe fn is_blocked_port(port_be: u32) -> bool {
    BLOCKED_PORTS.get(&port_be).is_some()
}

unsafe fn bump_violation(tgid: u32) {
    if let Some(count) = VIOLATION_COUNTS.get_ptr_mut(&tgid) {
        *count += 1;
        return;
    }
    let one: u64 = 1;
    let _ = VIOLATION_COUNTS.insert(&tgid, &one, 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

aya_ebpf::macros::license!("GPL");

