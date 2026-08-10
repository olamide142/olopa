//! Olopa eBPF programs — kernel side.
//!
//! Single ELF containing all probes. Userspace agent loads and attaches each.
//!
//! Programs:
//!   xdp_filter              — XDP hook: drop/pass at NIC driver level
//!   tc_egress               — TC hook:  egress (has PID context, unlike XDP)
//!   on_execve               — tracepoint: process execution
//!   on_execveat             — tracepoint: process execution via execveat
//!   on_openat               — tracepoint: file open
//!   on_openat2              — tracepoint: file open via openat2
//!   on_connect              — tracepoint: outbound network connect
//!   uprobe_pqexec           — uprobe: libpq PQexec / PQexecParams
//!   uprobe_pqprepare        — uprobe: libpq PQprepare (records text, no event)
//!   uprobe_pqexecprepared   — uprobe: libpq PQexecPrepared (replays recorded text)
//!   uprobe_mysql_query      — uprobe: libmysqlclient mysql_real_query
//!   uprobe_mysql_stmt_prepare — uprobe: mysql_stmt_prepare (records text, no event)
//!   uprobe_mysql_stmt_execute — uprobe: mysql_stmt_execute (replays recorded text)
//!   uprobe_evp_encrypt_update — uprobe: libssl EVP_EncryptUpdate
//!   uprobe_evp_decrypt_update — uprobe: libssl EVP_DecryptUpdate
//!   uprobe_getaddrinfo      — uprobe: libc getaddrinfo (DNS resolution)

#![no_std]
#![no_main]

mod dns_probe;
mod exec_probe;
mod file_probe;
mod net_probe;
mod sql_probe;
mod ssl_probe;
mod tc;
mod xdp;

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
