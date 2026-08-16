//! Process execution probes — tracepoints on sys_enter_execve and sys_enter_execveat.
//!
//! Fires on process execution syscalls — every new program launch image.
//! Foundation of process lineage: pid + ppid on every exec lets the agent
//! reconstruct the full process tree for kill chain detection.
//!
//! VERIFIER RULE: after bpf_ringbuf_reserve() succeeds, every exit path
//! must call entry.submit(0) or entry.discard(0). Never use ? after reservation.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use olopa_common::{ExecEvent, EVENT_KIND_EXEC};

use crate::EVENTS;

#[map]
static PID_LINEAGE: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

#[tracepoint]
pub fn on_sched_process_fork(ctx: TracePointContext) -> u32 {
    unsafe { try_sched_process_fork(&ctx) }
}

unsafe fn try_sched_process_fork(ctx: &TracePointContext) -> u32 {
    // tracepoint:sched:sched_process_fork
    // parent_pid @ offset 24, child_pid @ offset 44
    let parent_pid: i32 = match ctx.read_at(24) {
        Ok(pid) => pid,
        Err(_) => return 1,
    };
    let child_pid: i32 = match ctx.read_at(44) {
        Ok(pid) => pid,
        Err(_) => return 1,
    };

    if parent_pid <= 0 || child_pid <= 0 {
        return 1;
    }

    let child_pid = child_pid as u32;
    let parent_pid = parent_pid as u32;
    let _ = PID_LINEAGE.insert(&child_pid, &parent_pid, 0);
    0
}

#[tracepoint]
pub fn on_execve(ctx: TracePointContext) -> u32 {
    unsafe { try_execve(&ctx, 16) }
}

#[tracepoint]
pub fn on_execveat(ctx: TracePointContext) -> u32 {
    // sys_enter_execveat args:
    //   dfd @ 16, filename ptr @ 24, argv @ 32, envp @ 40, flags @ 48
    // We only need filename for the shared ExecEvent payload.
    unsafe { try_execve(&ctx, 24) }
}

unsafe fn try_execve(ctx: &TracePointContext, filename_ptr_offset: usize) -> u32 {
    // Reserve ring buffer slot. None = buffer full, drop silently.
    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    // After this point: every return MUST call submit or discard.
    // No ? operator — it would exit without releasing the reservation.

    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_EXEC;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    (*event).pid = pid;
    (*event).ppid = match PID_LINEAGE.get(&pid) {
        Some(ppid) => *ppid,
        None => 0,
    };

    let uid_gid = bpf_get_current_uid_gid();
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

    // filename pointer offset differs by syscall variant:
    // - execve:   16
    // - execveat: 24
    let filename_ptr: u64 = match ctx.read_at(filename_ptr_offset) {
        Ok(ptr) => ptr,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*event).filename);

    (*event).argv_hash = 0;

    entry.submit(0);
    0
}
