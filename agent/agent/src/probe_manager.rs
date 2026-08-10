//! Probe manager for kernel hook attachment.
//!
//! This module handles only probe attachment and attachment bookkeeping.
//! It intentionally does not own event ingestion, scoring, scheduling,
//! batching, or sending logic.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::{
    programs::{
        tc::{SchedClassifier, TcAttachType},
        TracePoint, UProbe, Xdp, XdpFlags,
    },
    Ebpf,
};
use log::{info, warn};

use olopa_common::{ExecEvent, FileEvent, NetEvent};

/// CLI-selectable probe groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeSelection {
    Fork,
    Exec,
    File,
    Net,
    Xdp,
    Tc,
    /// Uprobes on the libpq and libmysqlclient entry points carrying statement text.
    Sql,
    /// Uprobes on libssl (EVP_EncryptUpdate / EVP_DecryptUpdate).
    Ssl,
    /// Uprobe on libc getaddrinfo (DNS name resolution).
    Dns,
}

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
    /// Uprobe(s) on SQL client libraries (libpq, libmysqlclient).
    SqlUprobe,
    /// Uprobe(s) on OpenSSL libssl (EVP_EncryptUpdate / EVP_DecryptUpdate).
    SslUprobe,
    /// Uprobe on libc getaddrinfo (DNS resolution entry point).
    DnsUprobe,
}

/// SQL client entry points to hook, grouped by the eBPF program that reads the
/// argument position holding statement text.
///
/// Grouping is not cosmetic: `PQprepare` takes the statement name first and the
/// text second, so it needs a handler reading argument 2, while everything on
/// `uprobe_pqexec` carries text at argument 1. Adding a symbol under the wrong
/// program makes the probe read the wrong pointer.
///
/// Only entry points an application calls directly belong here. libpq builds
/// `PQexec` on `PQsendQuery` and `PQexecParams` on `PQsendQueryParams`, and
/// those internal calls land on the same entry a uprobe watches — listing the
/// `PQsend*` family too would report one query twice. `mysql_query` is excluded
/// for the same reason: it delegates to `mysql_real_query`.
const LIBPQ_SQL_UPROBES: &[(&str, &[&str])] = &[
    ("uprobe_pqexec", &["PQexec", "PQexecParams"]),
    ("uprobe_pqprepare", &["PQprepare"]),
];

/// MySQL client entry points carrying statement text at argument 1.
///
/// `mysql_stmt_execute` is absent: it takes only a statement handle, so
/// attributing it needs prepare-time state keyed by that handle.
const LIBMYSQL_SQL_UPROBES: &[(&str, &[&str])] = &[(
    "uprobe_mysql_query",
    &["mysql_real_query", "mysql_stmt_prepare"],
)];

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
        self.attach_selected(bpf, iface, Self::default_probe_selections())
    }

    /// Baseline probe profile used when caller does not specify custom probes.
    pub fn default_probe_selections() -> &'static [ProbeSelection] {
        &[
            ProbeSelection::Fork,
            ProbeSelection::Exec,
            ProbeSelection::File,
            ProbeSelection::Net,
        ]
    }

    /// Attach only the requested probe groups.
    pub fn attach_selected(
        &mut self,
        bpf: &mut Ebpf,
        iface: &str,
        selections: &[ProbeSelection],
    ) -> Result<()> {
        let mut seen = HashSet::new();
        for selection in selections {
            if !seen.insert(*selection) {
                continue;
            }
            match selection {
                ProbeSelection::Fork => self.attach_fork_tracepoints(bpf)?,
                ProbeSelection::Exec => self.attach_exec_tracepoints(bpf)?,
                ProbeSelection::File => self.attach_file_tracepoints(bpf)?,
                ProbeSelection::Net => self.attach_net_tracepoints(bpf)?,
                ProbeSelection::Xdp => self.attach_xdp(bpf, iface)?,
                ProbeSelection::Tc => self.attach_tc(bpf, iface)?,
                ProbeSelection::Sql => self.attach_sql_uprobes(bpf)?,
                ProbeSelection::Ssl => self.attach_ssl_uprobes(bpf)?,
                ProbeSelection::Dns => self.attach_dns_uprobes(bpf)?,
            }
        }

        info!("selected probes attached (count={})", selections.len());
        Ok(())
    }

    /// Return records for a given probe kind.
    pub fn attached_for(&self, kind: ProbeKind) -> &[String] {
        self.attached.get(&kind).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Internal attachment recorder.
    fn record(&mut self, kind: ProbeKind, target: &str) {
        self.attached
            .entry(kind)
            .or_default()
            .push(target.to_owned());
    }

    fn attach_fork_tracepoints(&mut self, bpf: &mut Ebpf) -> Result<()> {
        self.attach_tracepoint(bpf, "on_sched_process_fork", "sched", "sched_process_fork")?;
        self.record(ProbeKind::ForkTracepoint, "sched:sched_process_fork");
        Ok(())
    }

    fn attach_exec_tracepoints(&mut self, bpf: &mut Ebpf) -> Result<()> {
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
        Ok(())
    }

    fn attach_file_tracepoints(&mut self, bpf: &mut Ebpf) -> Result<()> {
        self.attach_tracepoint(bpf, "on_openat", "syscalls", "sys_enter_openat")?;
        self.record(ProbeKind::FileTracepoint, "syscalls:sys_enter_openat");
        if self.attach_tracepoint_if_present(bpf, "on_openat2", "syscalls", "sys_enter_openat2")? {
            self.record(ProbeKind::FileTracepoint, "syscalls:sys_enter_openat2");
        }
        Ok(())
    }

    fn attach_net_tracepoints(&mut self, bpf: &mut Ebpf) -> Result<()> {
        self.attach_tracepoint(bpf, "on_connect", "syscalls", "sys_enter_connect")?;
        self.record(ProbeKind::NetTracepoint, "syscalls:sys_enter_connect");
        Ok(())
    }

    /// Attach SQL uprobes on libpq and libmysqlclient (if present).
    ///
    /// Searches standard shared-library paths for each database client.
    /// Missing libraries are skipped with a warning rather than hard-failing —
    /// an agent running on a host with only PostgreSQL should still work.
    pub fn attach_sql_uprobes(&mut self, bpf: &mut Ebpf) -> Result<()> {
        // PostgreSQL client library candidates (Debian/Ubuntu, RHEL/Fedora, Alpine).
        const LIBPQ_CANDIDATES: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu/libpq.so.5",
            "/usr/lib/aarch64-linux-gnu/libpq.so.5",
            "/usr/lib64/libpq.so.5",
            "/usr/lib/libpq.so.5",
        ];

        // MySQL/MariaDB client library candidates.
        const LIBMYSQL_CANDIDATES: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu/libmysqlclient.so.21",
            "/usr/lib/x86_64-linux-gnu/libmysqlclient.so.20",
            "/usr/lib/aarch64-linux-gnu/libmysqlclient.so.21",
            "/usr/lib64/mysql/libmysqlclient.so.21",
            "/usr/lib/libmysqlclient.so.21",
        ];

        if let Some(lib) = find_lib(LIBPQ_CANDIDATES) {
            self.attach_sql_uprobe_table(bpf, LIBPQ_SQL_UPROBES, &lib);
        } else {
            warn!("libpq not found on this host — SQL/PostgreSQL uprobes skipped");
        }

        if let Some(lib) = find_lib(LIBMYSQL_CANDIDATES) {
            self.attach_sql_uprobe_table(bpf, LIBMYSQL_SQL_UPROBES, &lib);
        } else {
            warn!("libmysqlclient not found on this host — SQL/MySQL uprobes skipped");
        }

        Ok(())
    }

    /// Attach every `(program, symbols)` pair in a table to one library.
    fn attach_sql_uprobe_table(&mut self, bpf: &mut Ebpf, table: &[(&str, &[&str])], lib: &str) {
        for (program, symbols) in table {
            for sym in self.attach_uprobe_symbols(bpf, program, lib, symbols, None) {
                self.record(ProbeKind::SqlUprobe, &format!("{sym}:{lib}"));
            }
        }
    }

    /// Attach SSL uprobes on libssl (EVP_EncryptUpdate + EVP_DecryptUpdate).
    pub fn attach_ssl_uprobes(&mut self, bpf: &mut Ebpf) -> Result<()> {
        // OpenSSL shared library candidates.
        const LIBSSL_CANDIDATES: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/aarch64-linux-gnu/libssl.so.3",
            "/usr/lib64/libssl.so.3",
            "/usr/lib/libssl.so.3",
            "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
            "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
            "/usr/lib64/libssl.so.1.1",
        ];

        let lib = match find_lib(LIBSSL_CANDIDATES) {
            Some(l) => l,
            None => {
                warn!("libssl not found on this host — SSL uprobes skipped");
                return Ok(());
            }
        };

        match self.attach_uprobe(
            bpf,
            "uprobe_evp_encrypt_update",
            &lib,
            "EVP_EncryptUpdate",
            None,
        ) {
            Ok(()) => self.record(ProbeKind::SslUprobe, &format!("EVP_EncryptUpdate:{lib}")),
            Err(e) => warn!("skipping EVP_EncryptUpdate uprobe on {lib}: {e}"),
        }

        match self.attach_uprobe(
            bpf,
            "uprobe_evp_decrypt_update",
            &lib,
            "EVP_DecryptUpdate",
            None,
        ) {
            Ok(()) => self.record(ProbeKind::SslUprobe, &format!("EVP_DecryptUpdate:{lib}")),
            Err(e) => warn!("skipping EVP_DecryptUpdate uprobe on {lib}: {e}"),
        }

        Ok(())
    }

    /// Attach DNS resolution uprobe on libc `getaddrinfo`.
    ///
    /// `getaddrinfo` is called by virtually every userspace resolver — C, C++,
    /// Python, Go (cgo), and others all bottom out here.  Hooking it gives us
    /// DNS query telemetry without requiring a separate XDP/TC packet parser.
    pub fn attach_dns_uprobes(&mut self, bpf: &mut Ebpf) -> Result<()> {
        // libc.so.6 canonical paths across major Linux distributions.
        const LIBC_CANDIDATES: &[&str] = &[
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/aarch64-linux-gnu/libc.so.6",
            "/usr/lib64/libc.so.6",
            "/lib/libc.so.6",
        ];

        let lib = match find_lib(LIBC_CANDIDATES) {
            Some(l) => l,
            None => {
                warn!("libc.so.6 not found on this host — DNS uprobes skipped");
                return Ok(());
            }
        };

        match self.attach_uprobe(bpf, "uprobe_getaddrinfo", &lib, "getaddrinfo", None) {
            Ok(()) => self.record(ProbeKind::DnsUprobe, &format!("getaddrinfo:{lib}")),
            Err(e) => warn!("skipping getaddrinfo uprobe on {lib}: {e}"),
        }

        Ok(())
    }

    /// Attach one uprobe program to several symbols in the same library,
    /// returning the symbols that attached.
    ///
    /// A program is loaded into the kernel once and can then be attached to
    /// many places, which is what lets a single handler cover every entry
    /// point that passes statement text in the same argument position.
    ///
    /// A missing symbol is warned past rather than fatal: client libraries
    /// vary by version and vendor (MariaDB's libmysqlclient does not expose
    /// everything MySQL's does), and losing one entry point should not cost
    /// the others.
    fn attach_uprobe_symbols(
        &mut self,
        bpf: &mut Ebpf,
        fn_name: &str,
        lib: &str,
        syms: &[&str],
        pid: Option<i32>,
    ) -> Vec<String> {
        let prog: &mut UProbe = match bpf
            .program_mut(fn_name)
            .with_context(|| format!("uprobe program '{fn_name}' not found in eBPF object"))
            .and_then(|p| p.try_into().map_err(Into::into))
        {
            Ok(p) => p,
            Err(e) => {
                warn!("skipping uprobe program '{fn_name}': {e}");
                return Vec::new();
            }
        };

        if let Err(e) = prog.load() {
            warn!("failed to load uprobe '{fn_name}': {e}");
            return Vec::new();
        }

        let mut attached = Vec::new();
        for sym in syms {
            match prog.attach(Some(*sym), 0, lib, pid) {
                Ok(_) => {
                    info!("uprobe attached: {fn_name} -> {lib}:{sym}");
                    attached.push((*sym).to_string());
                }
                Err(e) => warn!("skipping {sym} uprobe on {lib}: {e}"),
            }
        }
        attached
    }

    /// Attach a userspace probe (uprobe) to a symbol in a shared library.
    ///
    /// # Arguments
    /// * `fn_name`  — name of the eBPF program section (must match `#[uprobe]` function name).
    /// * `lib`      — absolute path to the target shared library.
    /// * `sym`      — symbol name to hook (resolved via ELF symbol table).
    /// * `pid`      — optional PID filter; `None` hooks all processes.
    fn attach_uprobe(
        &mut self,
        bpf: &mut Ebpf,
        fn_name: &str,
        lib: &str,
        sym: &str,
        pid: Option<i32>,
    ) -> Result<()> {
        let prog: &mut UProbe = bpf
            .program_mut(fn_name)
            .with_context(|| format!("uprobe program '{}' not found in eBPF object", fn_name))?
            .try_into()?;

        prog.load()
            .with_context(|| format!("failed to load uprobe '{}'", fn_name))?;

        prog.attach(Some(sym), 0, lib, pid)
            .with_context(|| format!("failed to attach uprobe '{}' -> {}:{}", fn_name, lib, sym))?;

        info!("uprobe attached: {} -> {}:{}", fn_name, lib, sym);
        Ok(())
    }

    /// Attach XDP to interface.
    ///
    /// Tries native mode first; falls back to SKB mode when unsupported.
    pub fn attach_xdp(&mut self, bpf: &mut Ebpf, iface: &str) -> Result<()> {
        let prog: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .context("xdp_filter program not found — check SEC name in xdp.rs")?
            .try_into()?;

        prog.load().context("failed to load XDP program")?;

        match prog.attach(iface, XdpFlags::default()) {
            Ok(_) => info!("XDP attached on {} (native mode)", iface),
            Err(e) => {
                warn!(
                    "XDP native mode failed on {}: {} — trying SKB_MODE",
                    iface, e
                );
                prog.attach(iface, XdpFlags::SKB_MODE).with_context(|| {
                    format!("XDP attach failed on {} in both native and SKB mode", iface)
                })?;
                info!("XDP attached on {} (SKB_MODE fallback)", iface);
            }
        }
        self.record(ProbeKind::Xdp, iface);
        Ok(())
    }

    /// Attach TC egress classifier to interface.
    pub fn attach_tc(&mut self, bpf: &mut Ebpf, iface: &str) -> Result<()> {
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
        self.record(ProbeKind::Tc, iface);
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

/// Search a list of candidate paths and return the first one that exists on disk.
///
/// Used to locate shared libraries across distros without hard-coding a single path.
fn find_lib(candidates: &[&str]) -> Option<String> {
    for path in candidates {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Convert fixed-size NUL-terminated bytes to UTF-8 string safely.
fn cstr_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("<invalid utf8>")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One application call must produce one SQL event. Listing a symbol under
    /// two handlers attaches two probes to the same entry point, so every query
    /// through it reports twice and inflates any rate-based rule — a corruption
    /// that looks like real traffic rather than like a bug.
    #[test]
    fn no_sql_symbol_is_hooked_by_more_than_one_program() {
        let mut seen: HashSet<&str> = HashSet::new();

        for (_, symbols) in LIBPQ_SQL_UPROBES.iter().chain(LIBMYSQL_SQL_UPROBES) {
            for sym in *symbols {
                assert!(
                    seen.insert(sym),
                    "{sym} is hooked by two programs — one call would emit two events"
                );
            }
        }
    }

    /// libpq implements the synchronous API on top of the async one, so a
    /// `PQsend*` hook fires again for a query already counted at `PQexec*`.
    /// `mysql_query` delegates to `mysql_real_query` the same way.
    #[test]
    fn sql_uprobes_avoid_entry_points_that_delegate_to_hooked_ones() {
        for (_, symbols) in LIBPQ_SQL_UPROBES.iter().chain(LIBMYSQL_SQL_UPROBES) {
            for sym in *symbols {
                assert!(
                    !sym.starts_with("PQsend"),
                    "{sym} is reached from the PQexec* family and would double-count"
                );
                assert_ne!(
                    *sym, "mysql_query",
                    "mysql_query delegates to mysql_real_query and would double-count"
                );
            }
        }
    }

    /// `PQprepare` takes the statement *name* at argument 1 and the text at
    /// argument 2, so it must not ride the argument-1 handler — doing so would
    /// capture statement names as though they were SQL.
    #[test]
    fn pqprepare_uses_its_own_argument_position_handler() {
        let arg1_symbols: Vec<&str> = LIBPQ_SQL_UPROBES
            .iter()
            .filter(|(program, _)| *program == "uprobe_pqexec")
            .flat_map(|(_, symbols)| symbols.iter().copied())
            .collect();

        assert!(
            !arg1_symbols.contains(&"PQprepare"),
            "PQprepare's statement text is at argument 2, not 1"
        );
        assert!(arg1_symbols.contains(&"PQexecParams"));
    }
}
