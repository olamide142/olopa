//! TC (Traffic Control) egress probe.
//!
//! Runs AFTER the kernel network stack, BEFORE the packet leaves the NIC.
//! Unlike XDP, TC sees sk_buff and has PID context via bpf_get_current_pid_tgid().
//!
//! This makes TC the right hook for per-process egress monitoring:
//!   - Which process is connecting to where
//!   - Per-container bandwidth accounting
//!   - Egress blocking after routing
//!
//! Userspace attaches via SchedClassifier + clsact qdisc (Aya handles qdisc creation).

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::classifier,
    programs::TcContext,
};

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match unsafe { process(&ctx) } {
        Ok(action) => action,
        Err(_) => TC_ACT_OK as i32, // on error always let packet through
    }
}

unsafe fn process(_ctx: &TcContext) -> Result<i32, i32> {
    // Future:
    // 1. Parse IP header: ctx.load::<u32>(ETH_HDR_LEN + DST_IP_OFFSET)?
    // 2. Parse TCP/UDP dst_port
    // 3. bpf_get_current_pid_tgid() → look up egress policy for this pid
    // 4. Policy DENY → return TC_ACT_SHOT
    // 5. Write TcEvent to EVENTS ring buffer

    Ok(TC_ACT_OK as i32)
}