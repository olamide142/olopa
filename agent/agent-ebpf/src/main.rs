#![no_std]
#![no_main]

use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes};
use aya_ebpf::macros::{cgroup_sock_addr, map, tracepoint};
use aya_ebpf::maps::{HashMap, PerfEventArray};
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

#[repr(C)]
pub struct FileEvent {
    pub op: u8,
    pub _pad: [u8; 3],
    pub tgid: u32,
    pub pid: u32,
    pub comm: [u8; 16],
    pub path: [u8; 128],
}

#[map(name = "FILE_EVENTS")]
static FILE_EVENTS: PerfEventArray<FileEvent> = PerfEventArray::new(0);

const SYS_ENTER_ARGS_OFFSET: usize = 16;
const SYS_ARG_SIZE: usize = 8;

macro_rules! simple_tracepoint {
    ($section:ident, $program:ident, $message:literal, $emit_log:expr) => {
        #[tracepoint]
        pub fn $program(ctx: TracePointContext) -> u32 {
            match unsafe { $section(ctx) } {
                Ok(ret) => ret,
                Err(_) => 1,
            }
        }

        unsafe fn $section(ctx: TracePointContext) -> Result<u32, ()> {
            if $emit_log {
                info!(&ctx, $message);
            }
            Ok(0)
        }
    };
}

simple_tracepoint!(on_exec, trace_exec, "execve observed", false);
simple_tracepoint!(on_read, trace_read, "read observed", false);
simple_tracepoint!(on_write, trace_write, "write observed", false);
simple_tracepoint!(on_close, trace_close, "close observed", false);
simple_tracepoint!(on_socket, trace_socket, "socket observed", false);
simple_tracepoint!(on_bind, trace_bind, "bind observed", false);
simple_tracepoint!(on_listen, trace_listen, "listen observed", false);
simple_tracepoint!(on_accept4, trace_accept4, "accept4 observed", false);
simple_tracepoint!(on_connect, trace_connect, "connect observed", false);
simple_tracepoint!(on_sendto, trace_sendto, "sendto observed", false);
simple_tracepoint!(on_recvfrom, trace_recvfrom, "recvfrom observed", false);
simple_tracepoint!(on_sendmsg, trace_sendmsg, "sendmsg observed", false);
simple_tracepoint!(on_recvmsg, trace_recvmsg, "recvmsg observed", false);
simple_tracepoint!(on_shutdown, trace_shutdown, "shutdown observed", false);
simple_tracepoint!(on_setsockopt, trace_setsockopt, "setsockopt observed", false);
simple_tracepoint!(on_renameat2, trace_renameat2, "renameat2 observed", true);

#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_openat(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn trace_openat2(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_openat2(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[tracepoint] 
pub fn trace_unlinkat(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_unlinkat(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,      
    }
}

unsafe fn try_trace_openat(ctx: TracePointContext) -> Result<u32, ()> {
    let filename_ptr = read_syscall_arg_ptr(&ctx, 1)?;
    emit_file_event(&ctx, 1, filename_ptr);
    Ok(0)
}

unsafe fn try_trace_openat2(ctx: TracePointContext) -> Result<u32, ()> {
    let filename_ptr = read_syscall_arg_ptr(&ctx, 1)?;
    emit_file_event(&ctx, 2, filename_ptr);
    Ok(0)
}

unsafe fn try_trace_unlinkat(ctx: TracePointContext) -> Result<u32, ()> {
    let pathname_ptr = read_syscall_arg_ptr(&ctx, 1)?;
    emit_file_event(&ctx, 3, pathname_ptr);
    Ok(0)
}

unsafe fn read_syscall_arg_ptr(ctx: &TracePointContext, arg_idx: usize) -> Result<*const u8, ()> {
    let offset = SYS_ENTER_ARGS_OFFSET + (arg_idx * SYS_ARG_SIZE);
    let value: u64 = ctx.read_at(offset).map_err(|_| ())?;
    Ok(value as *const u8)
}

unsafe fn emit_file_event(ctx: &TracePointContext, op: u8, path_ptr: *const u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let mut event = FileEvent {
        op,
        _pad: [0; 3],
        tgid,
        pid,
        comm: [0; 16],
        path: [0; 128],
    };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    event.comm = comm;

    if !path_ptr.is_null() {
        let _ = bpf_probe_read_user_str_bytes(path_ptr, &mut event.path);
    }

    let _ = FILE_EVENTS.output(ctx, &event, 0);
}

#[cgroup_sock_addr(connect4)]
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

#[cgroup_sock_addr(connect6)]
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
