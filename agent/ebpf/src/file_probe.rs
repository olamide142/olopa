//! File access probes — tracepoints on sys_enter_openat and sys_enter_openat2.
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
//!
//! openat2 specifics:
//! - Kernel passes `struct open_how*` instead of raw `flags`.
//! - We read the first `u64` from `open_how` and downcast to `u32` flags.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use olopa_common::{FileEvent, EVENT_KIND_FILE};

use crate::EVENTS;

#[tracepoint]
pub fn on_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_openat(&ctx, false) }
}

#[tracepoint]
pub fn on_openat2(ctx: TracePointContext) -> u32 {
    // sys_enter_openat2 args:
    //   dfd @ 16, filename ptr @ 24, open_how* @ 32, size @ 40
    // Aya tracepoint context exposes syscall args beginning at offset 0,
    // so we keep the same filename offset used by openat and switch flag extraction.
    unsafe { try_openat(&ctx, true) }
}

unsafe fn try_openat(ctx: &TracePointContext, openat2: bool) -> u32 {
    let mut entry = match EVENTS.reserve::<FileEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_FILE;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

    (*event).flags = if openat2 {
        // openat2 passes pointer to `struct open_how` at arg index 2.
        // `flags` is the first u64 field in that struct.
        let how_ptr: u64 = match ctx.read_at(16) {
            Ok(ptr) => ptr,
            Err(_) => {
                entry.discard(0);
                return 1;
            }
        };
        if how_ptr == 0 {
            0
        } else {
            match bpf_probe_read_user(how_ptr as *const u64) {
                Ok(f) => f as u32,
                Err(_) => 0,
            }
        }
    } else {
        match ctx.read_at::<u32>(16) {
            Ok(f) => f,
            Err(_) => {
                entry.discard(0);
                return 1;
            }
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

    let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*event).filename);

    entry.submit(0);
    0
}
