//! Probe manager for kernel hook attachment.
//!
//! This module handles only probe attachment and attachment bookkeeping.
//! It intentionally does not own event ingestion, scoring, scheduling,
//! batching, or sending logic.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::{
    programs::{
        tc::{SchedClassifier, TcAttachType},
        TracePoint, Xdp, XdpFlags,
    },
    Ebpf,
};
use log::{info, warn};

use olopa_common::{ExecEvent, FileEvent, NetEvent};

/// Logical probe kinds used for userspace attachment bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeKind {
    /// XDP program attached to interface.
    Xdp,
    /// TC egress program attached to interface.
    Tc,
    /// Tracepoint for connect syscall.
    NetTracepoint,
    /// Tracepoint for process fork lineage map updates.
    ForkTracepoint,
    /// Tracepoint for exec syscall.
    ExecTracepoint,
    /// Tracepoint for openat syscall.
    FileTracepoint,
}

/// Probe manager state.
///
/// `attached` maps each kind to a list of target descriptors
/// (interface names or tracepoint path strings).
pub struct ProbeManager {
    attached: HashMap<ProbeKind, Vec<String>>,
}

impl ProbeManager {
    /// Construct an empty manager.
    pub fn new() -> Self {
        Self {
            attached: HashMap::new(),
        }
    }

    /// Attach default probes for current runtime profile.
    ///
    /// Current baseline:
    /// - `sched/sched_process_fork` (build PID lineage)
    /// - `syscalls/sys_enter_execve`
    /// - `syscalls/sys_enter_execveat`
    /// - `syscalls/sys_enter_openat`
    /// - `syscalls/sys_enter_openat2`
    /// - `syscalls/sys_enter_connect`
    pub fn attach_defaults(&mut self, bpf: &mut Ebpf, iface: &str) -> Result<()> {
        self.attach_tracepoint(
            bpf,
            "on_sched_process_fork",
            "sched",
            "sched_process_fork",
        )?;
        self.record(ProbeKind::ForkTracepoint, "sched:sched_process_fork");

        self.attach_tracepoint(bpf, "on_execve", "syscalls", "sys_enter_execve")?;
        self.record(ProbeKind::ExecTracepoint, "syscalls:sys_enter_execve");
        if self.attach_tracepoint_if_present(
            bpf,
            "on_execveat",
            "syscalls",
            "sys_enter_execveat",
        )? {
            self.record(ProbeKind::ExecTracepoint, "syscalls:sys_enter_execveat");
        }

        self.attach_tracepoint(bpf, "on_openat", "syscalls", "sys_enter_openat")?;
        self.record(ProbeKind::FileTracepoint, "syscalls:sys_enter_openat");
        if self.attach_tracepoint_if_present(
            bpf,
            "on_openat2",
            "syscalls",
            "sys_enter_openat2",
        )? {
            self.record(ProbeKind::FileTracepoint, "syscalls:sys_enter_openat2");
        }

        self.attach_tracepoint(bpf, "on_connect", "syscalls", "sys_enter_connect")?;
        self.record(ProbeKind::NetTracepoint, "syscalls:sys_enter_connect");
        info!("all default probes attached");

        // Optional hooks kept for staged rollout:
        // self.attach_xdp(bpf, iface)?;
        // self.record(ProbeKind::Xdp, iface);
        // self.attach_tc(bpf, iface)?;
        // self.record(ProbeKind::Tc, iface);
        let _ = iface;
        Ok(())
    }

    /// Return records for a given probe kind.
    pub fn attached_for(&self, kind: ProbeKind) -> &[String] {
        self.attached
            .get(&kind)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Internal attachment recorder.
    fn record(&mut self, kind: ProbeKind, target: &str) {
        self.attached
            .entry(kind)
            .or_default()
            .push(target.to_owned());
    }

    /// Attach XDP to interface.
    ///
    /// Tries native mode first; falls back to SKB mode when unsupported.
    pub fn attach_xdp(&self, bpf: &mut Ebpf, iface: &str) -> Result<()> {
        let prog: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .context("xdp_filter program not found — check SEC name in xdp.rs")?
            .try_into()?;

        prog.load().context("failed to load XDP program")?;

        match prog.attach(iface, XdpFlags::default()) {
            Ok(_) => info!("XDP attached on {} (native mode)", iface),
            Err(e) => {
                warn!("XDP native mode failed on {}: {} — trying SKB_MODE", iface, e);
                prog.attach(iface, XdpFlags::SKB_MODE).with_context(|| {
                    format!(
                        "XDP attach failed on {} in both native and SKB mode",
                        iface
                    )
                })?;
                info!("XDP attached on {} (SKB_MODE fallback)", iface);
            }
        }
        Ok(())
    }

    /// Attach TC egress classifier to interface.
    pub fn attach_tc(&self, bpf: &mut Ebpf, iface: &str) -> Result<()> {
        // Ensure clsact exists; ignore errors like "already exists".
        let _ = aya::programs::tc::qdisc_add_clsact(iface);

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

    /// Attach tracepoint function to category/name.
    pub fn attach_tracepoint(
        &self,
        bpf: &mut Ebpf,
        fn_name: &str,
        category: &str,
        name: &str,
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

    /// Attach tracepoint if present on this kernel.
    ///
    /// Returns:
    /// - `Ok(true)` when attached
    /// - `Ok(false)` when tracepoint is unavailable and skipped
    /// - `Err(...)` for other failures (load/program lookup/etc)
    pub fn attach_tracepoint_if_present(
        &self,
        bpf: &mut Ebpf,
        fn_name: &str,
        category: &str,
        name: &str,
    ) -> Result<bool> {
        match self.attach_tracepoint(bpf, fn_name, category, name) {
            Ok(()) => Ok(true),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No such file or directory") || msg.contains("ENOENT") {
                    warn!(
                        "tracepoint not available on this kernel: {}/{} (skipping)",
                        category, name
                    );
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }
}

/// Debug formatter for exec events (manual diagnostics).
fn handle_exec(e: &ExecEvent) {
    let comm = cstr_to_str(&e.comm);
    let filename = cstr_to_str(&e.filename);
    info!(
        "[EXEC] pid={} uid={} comm={} file={}",
        e.pid, e.uid, comm, filename
    );
}

/// Debug formatter for file events (manual diagnostics).
fn handle_file(e: &FileEvent) {
    let comm = cstr_to_str(&e.comm);
    let filename = cstr_to_str(&e.filename);
    let mode = if e.flags & 0x3 == 0 { "R" } else { "W" };
    info!(
        "[FILE] pid={} uid={} comm={} flags={} ({}) file={}",
        e.pid, e.uid, comm, e.flags, mode, filename
    );
}

/// Debug formatter for network events (manual diagnostics).
fn handle_net(e: &NetEvent) {
    let comm = cstr_to_str(&e.comm);
    let ip = Ipv4Addr::from(u32::from_be(e.dst_ip));
    let port = u16::from_be(e.dst_port);
    info!(
        "[NET]  pid={} uid={} comm={} -> {}:{}",
        e.pid, e.uid, comm, ip, port
    );
}

/// Convert fixed-size NUL-terminated bytes to UTF-8 string safely.
fn cstr_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("<invalid utf8>")
}
