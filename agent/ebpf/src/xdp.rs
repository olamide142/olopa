//! XDP (eXpress Data Path) probe.
//!
//! Runs at the NIC driver level — before the kernel allocates an sk_buff.
//! Fastest possible interception point in the Linux network stack.
//!
//! Server (eth0/ens3): native XDP — full line rate
//! Laptop  (wlo1):     SKB_MODE fallback — works on all interfaces
//!
//! Current: parse IPv4 ingress traffic, drop exact source-IP threat matches,
//! and count pass/drop verdicts.
//!
//! Design note:
//! - XDP program currently mutates only counter map state and does not emit
//!   ring-buffer events. Process-aware telemetry remains in tracepoint/TC paths.

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};

/// Packet counters — index 0=passed, 1=dropped, 2=redirected.
/// Agent reads these for Prometheus metrics.
#[map]
static XDP_COUNTERS: Array<u64> = Array::with_max_entries(3, 0);

/// Exact IPv4 source-address deny map populated by userspace.
#[map]
static XDP_BLOCKLIST_V4: HashMap<u32, u8> = HashMap::with_max_entries(65_536, 0);

const ETH_HDR_LEN: usize = 14;
const ETH_PROTO_OFFSET: usize = 12;
const IPV4_SOURCE_OFFSET: usize = ETH_HDR_LEN + 12;
const ETH_P_IP: u16 = 0x0800;

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match unsafe { process(ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn process(ctx: XdpContext) -> Result<u32, u32> {
    let eth_proto = u16::from_be(core::ptr::read_unaligned(ptr_at::<u16>(
        &ctx,
        ETH_PROTO_OFFSET,
    )?));
    if eth_proto == ETH_P_IP {
        let source_ip = u32::from_be(core::ptr::read_unaligned(ptr_at::<u32>(
            &ctx,
            IPV4_SOURCE_OFFSET,
        )?));
        if XDP_BLOCKLIST_V4.get(&source_ip).is_some() {
            if let Some(counter) = XDP_COUNTERS.get_ptr_mut(1) {
                *counter = (*counter).saturating_add(1);
            }
            return Ok(xdp_action::XDP_DROP);
        }
    }

    if let Some(counter) = XDP_COUNTERS.get_ptr_mut(0) {
        *counter = (*counter).saturating_add(1);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start.saturating_add(offset).saturating_add(len) > end {
        return Err(xdp_action::XDP_ABORTED);
    }
    Ok((start + offset) as *const T)
}
