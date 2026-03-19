//! File access probe — tracepoint on sys_enter_openat.
//!
//! Fires on every file open. Detects:
//!   - Credential reads:  /etc/shadow, ~/.ssh/id_rsa
//!   - Config tampering:  /etc/sudoers, systemd units
//!   - Secret access:     .env files, k8s service account tokens
//!
//! sys_enter_openat args:
//!   offset  0: int dfd          (directory fd — AT_FDCWD for cwd)
//!   offset  8: const char* filename
//!   offset 16: int flags        (O_RDONLY=0, O_WRONLY=1, O_RDWR=2)
//!   offset 24: umode_t mode
//!
//! VERIFIER RULE: no ? after reservation. Discard on all error paths.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use olopa_common::FileEvent;

use crate::EVENTS;

#[tracepoint]
pub fn on_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_openat(&ctx) }
}

unsafe fn try_openat(ctx: &TracePointContext) -> u32 {
    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    let event = entry.as_mut_ptr();

    (*event).ts_ns = bpf_ktime_get_ns();

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid  = (pid_tgid >> 32) as u32;

    let uid_gid  = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

    (*event).flags = match ctx.read_at::<u32>(16) {
        Ok(f) => f,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    // bpf_get_current_comm() takes no args — returns Result<[u8; 16], i64>
    (*event).comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    let filename_ptr: u64 = match ctx.read_at(8) {
        Ok(ptr) => ptr,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    let _ = bpf_probe_read_user_str_bytes(
        filename_ptr as *const u8,
        &mut (*event).filename,
    );

    entry.submit(0);
    0
}