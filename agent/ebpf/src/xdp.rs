//! XDP (eXpress Data Path) probe.
//!
//! Runs at the NIC driver level — before the kernel allocates an sk_buff.
//! Fastest possible interception point in the Linux network stack.
//!
//! Server (eth0/ens3): native XDP — full line rate
//! Laptop  (wlo1):     SKB_MODE fallback — works on all interfaces
//!
//! Current: pass everything and count packets.
//! Future:  blacklist map → XDP_DROP
//!          risk score map → XDP_REDIRECT to honeypot

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};

/// Packet counters — index 0=passed, 1=dropped, 2=redirected.
/// Agent reads these for Prometheus metrics.
#[map]
static XDP_COUNTERS: Array<u64> = Array::with_max_entries(3, 0);

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match unsafe { process(ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn process(_ctx: XdpContext) -> Result<u32, u32> {
    // Future:
    // 1. Parse ethernet/IP header (bounds-check required by verifier)
    // 2. Blacklist map lookup → XDP_DROP
    // 3. Risk score map: >70 → XDP_REDIRECT to honeypot
    // 4. Consistent-hash 5-tuple → select backend (load balancing)

    if let Some(counter) = XDP_COUNTERS.get_ptr_mut(0) {
        *counter = (*counter).saturating_add(1);
    }

    Ok(xdp_action::XDP_PASS)
}