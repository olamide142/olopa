//! Olopa agent — userspace orchestrator.
//!
//! Loads the compiled eBPF ELF, attaches each program to its kernel hook,
//! and reads events from the shared ring buffer in an async Tokio loop.
//!
//! Attachment map:
//!   xdp_filter  → XDP hook on <iface>        (NIC driver level, ~150ns)
//!   tc_egress   → TC clsact egress on <iface> (after routing, has PID context)
//!   on_sched_process_fork → tracepoint sched/sched_process_fork
//!   on_execve   → tracepoint syscalls/sys_enter_execve
//!   on_openat   → tracepoint syscalls/sys_enter_openat
//!   on_connect  → tracepoint syscalls/sys_enter_connect
//!
//! WiFi vs Ethernet:
//!   XDP native mode requires driver support — most wired NICs support it.
//!   WiFi drivers (wlo1, wlan0) almost never do. The agent automatically
//!   falls back to XDP SKB_MODE which works on all interfaces but is slower.
//!   TC works on all interface types without a fallback needed.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{
        tc::{SchedClassifier, TcAttachType},
        TracePoint, Xdp, XdpFlags,
    },
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use olopa_common::{ExecEvent, FileEvent, NetEvent};
use tokio::signal;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(name = "olopa-agent", about = "Olopa kernel security agent")]
struct Opt {
    /// Network interface to attach XDP and TC programs to.
    /// Use `ip link show` to find your interface name.
    /// Examples: eth0, ens3, wlo1, wlan0
    #[arg(short, long, default_value = "wl01")]
    iface: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    info!("olopa-agent starting | iface={}", opt.iface);

    // ── Load the eBPF object ─────────────────────────────────────────────
    // The ELF was compiled by build.rs and embedded into this binary.
    // include_bytes_aligned! ensures the bytes are aligned to 8 bytes
    // as required by the eBPF loader.
    info!("{:?}",env!("OUT_DIR"));
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/olopa-ebpf-bin")
    )).context("failed to load embedded eBPF object")?;

    // eBPF-side logging (optional — may fail on older kernels, non-fatal)
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("eBPF logger unavailable (kernel too old?): {e}");
    }

    // ── Attach XDP ──────────────────────────────────────────────────────
    // XDP_FILTER is the function name in xdp.rs — must match exactly.
    // attach_xdp(&mut bpf, &opt.iface)?;

    // ── Attach TC egress ────────────────────────────────────────────────
    // attach_tc(&mut bpf, &opt.iface)?;

    // ── Attach tracepoints ──────────────────────────────────────────────
    // attach_tracepoint(&mut bpf, "on_sched_process_fork", "sched", "sched_process_fork")?;
    // attach_tracepoint(&mut bpf, "on_execve",  "syscalls", "sys_enter_execve")?;
    // attach_tracepoint(&mut bpf, "on_openat",  "syscalls", "sys_enter_openat")?;
    attach_tracepoint(&mut bpf, "on_connect", "syscalls", "sys_enter_connect")?;

    info!("all probes attached — reading events (Ctrl-C to stop)");

    // ── Ring buffer reader ───────────────────────────────────────────────
    // Spawn a blocking task to drain the ring buffer continuously.
    // We use spawn_blocking because the ring buffer poll is not async-native.
    let ring_map = bpf
        .map_mut("EVENTS")
        .context("EVENTS ring buffer map not found")?;

    let mut ring = RingBuf::try_from(ring_map)
        .context("failed to open EVENTS as RingBuf")?;

    // Run the event loop until Ctrl-C
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutting down — detaching probes");
                break;
            }
            // Poll the ring buffer for new events
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                drain_ring_buffer(&mut ring);
            }
        }
    }

    Ok(())
    // When bpf drops here, Aya automatically detaches all attached programs.
}


// ── Probe attachment helpers ──────────────────────────────────────────────────
fn attach_xdp(bpf: &mut Ebpf, iface: &str) -> Result<()> {
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .context("xdp_filter program not found — check SEC name in xdp.rs")?
        .try_into()?;

    prog.load().context("failed to load XDP program")?;

    // Try native mode first (requires driver support — works on most wired NICs)
    match prog.attach(iface, XdpFlags::default()) {
        Ok(_) => {
            info!("XDP attached on {} (native mode)", iface);
        }
        Err(e) => {
            // Native failed — fall back to SKB mode (works on WiFi and VMs)
            warn!("XDP native mode failed on {}: {} — trying SKB_MODE", iface, e);
            prog.attach(iface, XdpFlags::SKB_MODE)
                .with_context(|| {
                    format!(
                        "XDP attach failed on {} in both native and SKB mode. \
                         Try: sudo ./olopa-agent --iface <correct-iface>\n\
                         Available interfaces: run `ip link show`",
                        iface
                    )
                })?;
            info!("XDP attached on {} (SKB_MODE fallback)", iface);
        }
    }
    Ok(())
}


fn attach_tc(bpf: &mut Ebpf, iface: &str) -> Result<()> {
    // TC requires a clsact qdisc on the interface.
    // Aya creates this automatically via netlink when we attach.
    let _ = aya::programs::tc::qdisc_add_clsact(iface); // ok if already exists

    let prog: &mut SchedClassifier = bpf
        .program_mut("tc_egress")
        .context("tc_egress program not found — check SEC name in tc.rs")?
        .try_into()?;

    prog.load().context("failed to load TC program")?;
    prog.attach(iface, TcAttachType::Egress)
        .with_context(|| format!("failed to attach TC egress on {}", iface))?;

    info!("TC egress attached on {}", iface);
    Ok(())
}


fn attach_tracepoint(
    bpf:      &mut Ebpf,
    fn_name:  &str,
    category: &str,
    name:     &str,
) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(fn_name)
        .with_context(|| format!("tracepoint program '{}' not found", fn_name))?
        .try_into()?;

    prog.load()
        .with_context(|| format!("failed to load tracepoint '{}'", fn_name))?;

    prog.attach(category, name)
        .with_context(|| format!("failed to attach {}/{}", category, name))?;

    info!("tracepoint attached: {}/{}", category, name);
    Ok(())
}

// ── Ring buffer event handler ─────────────────────────────────────────────────

/// Drain all available events from the ring buffer and dispatch by type.
/// Called every 10ms — in production this would be replaced with an
/// io_uring or epoll-based wakeup for true zero-latency delivery.
fn drain_ring_buffer(ring: &mut RingBuf<&mut aya::maps::MapData>) {
    use core::mem::size_of;

    while let Some(item) = ring.next() {
        let data: &[u8] = &item;
        let len = data.len();

        // Dispatch by event size — each event type has a unique fixed size.
        // In the next iteration this will use an explicit event_type field
        // in a common header so we don't rely on size disambiguation.
        if len == size_of::<ExecEvent>() {
            let event = unsafe { &*(data.as_ptr() as *const ExecEvent) };
            handle_exec(event);
        } else if len == size_of::<FileEvent>() {
            let event = unsafe { &*(data.as_ptr() as *const FileEvent) };
            handle_file(event);
        } else if len == size_of::<NetEvent>() {
            let event = unsafe { &*(data.as_ptr() as *const NetEvent) };
            handle_net(event);
        } else {
            warn!("unknown event size {} — skipping", len);
        }
    }
}


fn handle_exec(e: &ExecEvent) {
    let comm     = cstr_to_str(&e.comm);
    let filename = cstr_to_str(&e.filename);
    info!(
        "[EXEC] pid={} uid={} comm={} file={}",
        e.pid, e.uid, comm, filename
    );
    // TODO: forward to relevance scorer → OR scheduler → gRPC sender
}

fn handle_file(e: &FileEvent) {
    let comm     = cstr_to_str(&e.comm);
    let filename = cstr_to_str(&e.filename);
    let mode = if e.flags & 0x3 == 0 { "R" } else { "W" };
    info!(
        "[FILE] pid={} uid={} comm={} flags={} ({}) file={}",
        e.pid, e.uid, comm, e.flags, mode, filename
    );
    // TODO: match against sensitive path list (Falco-compatible rules)
}

fn handle_net(e: &NetEvent) {
    let comm = cstr_to_str(&e.comm);
    let ip   = format!(
        "{}.{}.{}.{}",
        (e.dst_ip)        & 0xFF,
        (e.dst_ip >> 8)   & 0xFF,
        (e.dst_ip >> 16)  & 0xFF,
        (e.dst_ip >> 24)  & 0xFF,
    );
    // Port is big-endian from the kernel — swap bytes for display
    let port = u16::from_be(e.dst_port);
    info!(
        "[NET]  pid={} uid={} comm={} → {}:{}",
        e.pid, e.uid, comm, ip, port
    );
    // TODO: check dst_ip against threat intel map
    //       check (pid, dst_ip) for unexpected outbound from known-benign proc
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert a NUL-terminated fixed-size byte array to a &str, safely.
/// The eBPF probe writes process names as [u8; 16] or [u8; 64] with NUL termination.
fn cstr_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("<invalid utf8>")
}
