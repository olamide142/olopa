use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, TracePoint};
use aya::Ebpf;
use aya_log::EbpfLogger;

pub const REQUIRED_TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("trace_exec", "syscalls", "sys_enter_execve"),
    ("trace_openat", "syscalls", "sys_enter_openat"),
    ("trace_read", "syscalls", "sys_enter_read"),
    ("trace_write", "syscalls", "sys_enter_write"),
    ("trace_close", "syscalls", "sys_enter_close"),
    ("trace_unlinkat", "syscalls", "sys_enter_unlinkat"),
    ("trace_socket", "syscalls", "sys_enter_socket"),
    ("trace_bind", "syscalls", "sys_enter_bind"),
    ("trace_listen", "syscalls", "sys_enter_listen"),
    ("trace_connect", "syscalls", "sys_enter_connect"),
    ("trace_accept4", "syscalls", "sys_enter_accept4"),
    ("trace_sendto", "syscalls", "sys_enter_sendto"),
    ("trace_recvfrom", "syscalls", "sys_enter_recvfrom"),
    ("trace_sendmsg", "syscalls", "sys_enter_sendmsg"),
    ("trace_recvmsg", "syscalls", "sys_enter_recvmsg"),
    ("trace_shutdown", "syscalls", "sys_enter_shutdown"),
    ("trace_setsockopt", "syscalls", "sys_enter_setsockopt"),
];

pub const OPTIONAL_TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("trace_openat2", "syscalls", "sys_enter_openat2"),
    ("trace_renameat2", "syscalls", "sys_enter_renameat2"),
];

pub fn load_ebpf(path: &Path) -> Result<Ebpf> {
    let mut bpf = Ebpf::load_file(path)
        .with_context(|| format!("failed to load eBPF object at {}", path.to_string_lossy()))?;
    if let Err(err) = EbpfLogger::init(&mut bpf) {
        eprintln!("logger init skipped: {err}");
    }
    Ok(bpf)
}

pub fn attach_all_tracepoints(bpf: &mut Ebpf) -> Result<()> {
    for (prog, category, event) in REQUIRED_TRACEPOINTS {
        attach_required_tracepoint(bpf, prog, category, event)?;
    }
    for (prog, category, event) in OPTIONAL_TRACEPOINTS {
        attach_optional_tracepoint(bpf, prog, category, event);
    }
    Ok(())
}

pub fn attach_cgroup_enforcement(bpf: &mut Ebpf, cgroup_path: &Path) -> Result<()> {
    let cgroup = File::open(cgroup_path)
        .with_context(|| format!("failed to open cgroup path {}", cgroup_path.to_string_lossy()))?;

    let connect4: &mut CgroupSockAddr = bpf
        .program_mut("enforce_connect4")
        .context("missing enforce_connect4 program")?
        .try_into()
        .context("enforce_connect4 is not a cgroup sock addr program")?;
    connect4.load().context("failed loading enforce_connect4")?;
    connect4
        .attach(&cgroup, CgroupAttachMode::Single)
        .context("failed attaching enforce_connect4 to cgroup")?;

    let connect6: &mut CgroupSockAddr = bpf
        .program_mut("enforce_connect6")
        .context("missing enforce_connect6 program")?
        .try_into()
        .context("enforce_connect6 is not a cgroup sock addr program")?;
    connect6.load().context("failed loading enforce_connect6")?;
    connect6
        .attach(&cgroup, CgroupAttachMode::Single)
        .context("failed attaching enforce_connect6 to cgroup")?;

    Ok(())
}

fn attach_required_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("missing {program_name} program in eBPF object"))?
        .try_into()
        .with_context(|| format!("{program_name} is not a TracePoint program"))?;

    program
        .load()
        .with_context(|| format!("failed to load {program_name}"))?;
    program
        .attach(category, event)
        .with_context(|| format!("failed to attach {program_name} to {category}:{event}"))?;
    Ok(())
}

fn attach_optional_tracepoint(bpf: &mut Ebpf, program_name: &str, category: &str, event: &str) {
    if let Err(err) = attach_required_tracepoint(bpf, program_name, category, event) {
        eprintln!("optional tracepoint skipped {category}:{event} ({program_name}): {err}");
    }
}

