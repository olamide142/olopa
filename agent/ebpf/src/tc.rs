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
//!
//! Current behavior:
//! - Policy-driven allow/deny based on `(pid, dst_ip, dst_port, proto)` key.
//! - Userspace writes deny rules into `TC_EGRESS_POLICY`.
//! - Deny decision returns `TC_ACT_SHOT` (drop).

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_get_current_pid_tgid,
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use olopa_common::{TcEgressPolicyKey, TC_POLICY_ACTION_DENY};

/// Policy map:
/// key   = process + destination tuple (`pid,dst_ip,dst_port,proto`)
/// value = allow/deny action byte.
///
/// Userspace writes entries at startup (or future control-plane updates).
/// Kernel fast path does read-only lookups per packet.
#[map]
static TC_EGRESS_POLICY: HashMap<TcEgressPolicyKey, u8> = HashMap::with_max_entries(16_384, 0);

/// TC stats counters:
/// index 0 = allowed packets
/// index 1 = denied packets
/// index 2 = parse errors
#[map]
static TC_EGRESS_STATS: Array<u64> = Array::with_max_entries(3, 0);

// Ethernet header constants (fixed for Ethernet II framing).
const ETH_HDR_LEN: usize = 14;
// Ethertype field offset within Ethernet header.
const ETH_PROTO_OFFSET: usize = 12;
const ETH_P_IP: u16 = 0x0800;
// IPv4 base header offsets (relative to L2 start).
const IP_VERSION_IHL_OFFSET: usize = ETH_HDR_LEN;
const IP_PROTO_OFFSET: usize = ETH_HDR_LEN + 9;
const IP_DST_OFFSET: usize = ETH_HDR_LEN + 16;
// Destination port offset within TCP/UDP header.
const L4_DST_PORT_OFFSET: usize = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Increment a counter in `TC_EGRESS_STATS`.
///
/// This helper intentionally avoids panicking and silently skips updates
/// when map access fails, keeping packet decision path robust.
#[inline(always)]
fn inc_stat(index: u32) {
    if let Some(counter) = TC_EGRESS_STATS.get_ptr_mut(index) {
        unsafe {
            *counter = (*counter).saturating_add(1);
        }
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    // On parse/helper failure, fail open (allow) to avoid accidental outages.
    // Tightening this behavior can be done behind explicit "fail-closed" mode.
    match unsafe { process(&ctx) } {
        Ok(action) => action,
        Err(_) => TC_ACT_OK as i32, // on error always let packet through
    }
}

/// Packet-level enforcement pipeline:
/// 1) Parse Ethernet + IPv4 + TCP/UDP destination tuple.
/// 2) Build policy key with current PID.
/// 3) Lookup deny/allow decision in `TC_EGRESS_POLICY`.
/// 4) Return `TC_ACT_SHOT` on deny, else `TC_ACT_OK`.
unsafe fn process(ctx: &TcContext) -> Result<i32, i32> {
    // Read L2 ethertype and proceed only for IPv4.
    let eth_proto_raw: u16 = match ctx.load(ETH_PROTO_OFFSET) {
        Ok(v) => v,
        Err(_) => {
            inc_stat(2);
            return Ok(TC_ACT_OK as i32);
        }
    };
    if u16::from_be(eth_proto_raw) != ETH_P_IP {
        inc_stat(0);
        return Ok(TC_ACT_OK as i32);
    }

    // Extract IPv4 header length from version+IHL byte.
    // Needed because IP options can extend header beyond 20 bytes.
    let version_ihl: u8 = match ctx.load(IP_VERSION_IHL_OFFSET) {
        Ok(v) => v,
        Err(_) => {
            inc_stat(2);
            return Ok(TC_ACT_OK as i32);
        }
    };
    let ip_version = version_ihl >> 4;
    if ip_version != 4 {
        inc_stat(0);
        return Ok(TC_ACT_OK as i32);
    }
    let ip_header_len = ((version_ihl & 0x0f) as usize).saturating_mul(4);
    if ip_header_len < 20 {
        inc_stat(2);
        return Ok(TC_ACT_OK as i32);
    }

    let proto: u8 = match ctx.load(IP_PROTO_OFFSET) {
        Ok(v) => v,
        Err(_) => {
            inc_stat(2);
            return Ok(TC_ACT_OK as i32);
        }
    };
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        inc_stat(0);
        return Ok(TC_ACT_OK as i32);
    }

    let dst_ip_raw: u32 = match ctx.load(IP_DST_OFFSET) {
        Ok(v) => v,
        Err(_) => {
            inc_stat(2);
            return Ok(TC_ACT_OK as i32);
        }
    };
    let dst_ip = u32::from_be(dst_ip_raw);

    // Layer-4 header begins immediately after variable-length IPv4 header.
    let l4_offset = ETH_HDR_LEN + ip_header_len;
    let dst_port_raw: u16 = match ctx.load(l4_offset + L4_DST_PORT_OFFSET) {
        Ok(v) => v,
        Err(_) => {
            inc_stat(2);
            return Ok(TC_ACT_OK as i32);
        }
    };
    let dst_port = u16::from_be(dst_port_raw);

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let key = TcEgressPolicyKey {
        pid,
        dst_ip,
        dst_port,
        proto,
        _pad: 0,
    };

    // Enforce deny when userspace policy map says so.
    // Any non-deny value currently falls through to allow.
    if let Some(action) = TC_EGRESS_POLICY.get(&key) {
        if *action == TC_POLICY_ACTION_DENY {
            inc_stat(1);
            return Ok(TC_ACT_SHOT as i32);
        }
    }

    inc_stat(0);
    Ok(TC_ACT_OK as i32)
}
