//! Olopa eBPF programs — kernel side.
//!
//! Single ELF containing all probes. Userspace agent loads and attaches each.
//!
//! Programs:
//!   xdp_filter  — XDP hook: drop/pass at NIC driver level
//!   tc_egress   — TC hook:  egress (has PID context, unlike XDP)
//!   on_execve   — tracepoint: process execution
//!   on_execveat — tracepoint: process execution via execveat
//!   on_openat   — tracepoint: file open
//!   on_openat2  — tracepoint: file open via openat2
//!   on_connect  — tracepoint: outbound network connect

#![no_std]
#![no_main]

mod xdp;
mod tc;
mod exec_probe;
mod file_probe;
mod net_probe;

use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;

/// Shared ring buffer — all tracepoint probes write events here.
/// 256 KB = 64 pages (must be power-of-2 pages).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
