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
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use olopa_common::{
    TcEgressPolicyKey, TcEvent, TcRateLimitConfig, TcRateLimitState, EVENT_KIND_TC,
    TC_POLICY_ACTION_ALLOW, TC_POLICY_ACTION_DENY, TC_POLICY_ACTION_RATE_LIMIT, TC_VERDICT_DENY,
};

use crate::EVENTS;

/// Policy map:
/// key   = process + destination tuple (`pid,dst_ip,dst_port,proto`)
/// value = allow/deny action byte.
///
/// Userspace writes entries at startup (or future control-plane updates).
/// Kernel fast path does read-only lookups per packet.
#[map]
static TC_EGRESS_POLICY: HashMap<TcEgressPolicyKey, u8> = HashMap::with_max_entries(16_384, 0);

/// Rate parameters for keys whose action is `TC_POLICY_ACTION_RATE_LIMIT`.
#[map]
static TC_EGRESS_RATE_CONFIG: HashMap<TcEgressPolicyKey, TcRateLimitConfig> =
    HashMap::with_max_entries(16_384, 0);

/// Mutable token-bucket state. Kept separate from immutable policy so control
/// updates do not race packet counters.
#[map]
static TC_EGRESS_RATE_STATE: HashMap<TcEgressPolicyKey, TcRateLimitState> =
    HashMap::with_max_entries(16_384, 0);

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
    let cgroup_id = bpf_get_current_cgroup_id();

    // Most-specific to least-specific lookup: exact process+cgroup, process,
    // cgroup, then a global destination tuple. This keeps the map exact-match
    // fast path while supporting container-scoped policy without duplicating
    // packet parsing or requiring a linear rule scan.
    if let Some((key, action)) = policy_action(cgroup_id, pid, dst_ip, dst_port, proto) {
        let denied = action == TC_POLICY_ACTION_DENY
            || (action == TC_POLICY_ACTION_RATE_LIMIT && rate_limit_denies(&key));
        if denied {
            inc_stat(1);
            emit_deny_event(cgroup_id, pid, dst_ip, dst_port, proto);
            return Ok(TC_ACT_SHOT as i32);
        }
        if action == TC_POLICY_ACTION_ALLOW || action == TC_POLICY_ACTION_RATE_LIMIT {
            inc_stat(0);
            return Ok(TC_ACT_OK as i32);
        }
    }

    inc_stat(0);
    Ok(TC_ACT_OK as i32)
}

/// Emit only denied packets. Allowed traffic is already represented by the
/// connect tracepoint, so emitting every TC allow would duplicate telemetry
/// and place packet-rate pressure on the shared ring buffer.
#[inline(always)]
unsafe fn emit_deny_event(cgroup_id: u64, pid: u32, dst_ip: u32, dst_port: u16, proto: u8) {
    let mut entry = match EVENTS.reserve::<TcEvent>(0) {
        Some(entry) => entry,
        None => return,
    };
    let event = entry.as_mut_ptr();
    (*event).kind = EVENT_KIND_TC;
    (*event).pid = pid;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = cgroup_id;
    (*event).uid = bpf_get_current_uid_gid() as u32;
    (*event).dst_ip = dst_ip;
    (*event).dst_port = dst_port;
    (*event).proto = proto;
    (*event).direction = 1;
    (*event).verdict = TC_VERDICT_DENY;
    (*event)._pad = [0; 3];
    (*event).comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0; 16],
    };
    entry.submit(0);
}

#[inline(always)]
unsafe fn lookup_action(
    cgroup_id: u64,
    pid: u32,
    dst_ip: u32,
    dst_port: u16,
    proto: u8,
) -> Option<(TcEgressPolicyKey, u8)> {
    let key = TcEgressPolicyKey {
        cgroup_id,
        pid,
        dst_ip,
        dst_port,
        proto,
        _pad: 0,
    };
    TC_EGRESS_POLICY.get(&key).map(|action| (key, *action))
}

#[inline(always)]
unsafe fn policy_action(
    cgroup_id: u64,
    pid: u32,
    dst_ip: u32,
    dst_port: u16,
    proto: u8,
) -> Option<(TcEgressPolicyKey, u8)> {
    lookup_action(cgroup_id, pid, dst_ip, dst_port, proto)
        .or_else(|| lookup_action(0, pid, dst_ip, dst_port, proto))
        .or_else(|| lookup_action(cgroup_id, 0, dst_ip, dst_port, proto))
        .or_else(|| lookup_action(0, 0, dst_ip, dst_port, proto))
}

#[inline(always)]
unsafe fn rate_limit_denies(key: &TcEgressPolicyKey) -> bool {
    let Some(config) = TC_EGRESS_RATE_CONFIG.get(key) else {
        // A malformed policy entry fails closed for the affected tuple.
        return true;
    };
    if config.packets_per_second == 0 || config.burst == 0 {
        return true;
    }
    let now = bpf_ktime_get_ns();
    if let Some(state) = TC_EGRESS_RATE_STATE.get_ptr_mut(key) {
        let elapsed = now.saturating_sub((*state).last_refill_ns);
        let refill = if elapsed >= 1_000_000_000 {
            config.burst
        } else {
            ((elapsed.saturating_mul(config.packets_per_second as u64)) / 1_000_000_000) as u32
        };
        if refill > 0 {
            (*state).tokens = (*state).tokens.saturating_add(refill).min(config.burst);
            (*state).last_refill_ns = now;
        }
        if (*state).tokens == 0 {
            return true;
        }
        (*state).tokens -= 1;
        return false;
    }
    let state = TcRateLimitState {
        last_refill_ns: now,
        tokens: config.burst.saturating_sub(1),
        _pad: 0,
    };
    if TC_EGRESS_RATE_STATE.insert(key, &state, 0).is_err() {
        return true;
    }
    false
}
