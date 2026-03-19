//! Process execution probe — tracepoint on sys_enter_execve.
//!
//! Fires on every execve() call — every new program launch.
//! Foundation of process lineage: pid + ppid on every exec lets the agent
//! reconstruct the full process tree for kill chain detection.
//!
//! VERIFIER RULE: after bpf_ringbuf_reserve() succeeds, every exit path
//! must call entry.submit(0) or entry.discard(0). Never use ? after reservation.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use olopa_common::ExecEvent;

use crate::EVENTS;

#[tracepoint]
pub fn on_execve(ctx: TracePointContext) -> u32 {
    unsafe { try_execve(&ctx) }
}

unsafe fn try_execve(ctx: &TracePointContext) -> u32 {
    // Reserve ring buffer slot. None = buffer full, drop silently.
    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    // After this point: every return MUST call submit or discard.
    // No ? operator — it would exit without releasing the reservation.

    let event = entry.as_mut_ptr();

    (*event).ts_ns = bpf_ktime_get_ns();

    let pid_tgid  = bpf_get_current_pid_tgid();
    (*event).pid  = (pid_tgid >> 32) as u32;
    (*event).ppid = 0; // TODO: sched_process_fork kprobe for lineage

    let uid_gid  = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;
    (*event).gid = (uid_gid >> 32) as u32;

    // bpf_get_current_comm() takes no args — returns Result<[u8; 16], i64>
    (*event).comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    // filename pointer at offset 16 in sys_enter_execve args
    let filename_ptr: u64 = match ctx.read_at(16) {
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

    (*event).argv_hash = 0;

    entry.submit(0);
    0
}