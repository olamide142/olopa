use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, TracePoint};
use aya::util::online_cpus;
use aya::Ebpf;
use aya_log::EbpfLogger;
use bytes::BytesMut;

#[repr(C)]
#[derive(Clone, Copy)]
struct FileEvent {
    op: u8,
    _pad: [u8; 3],
    tgid: u32,
    pid: u32,
    comm: [u8; 16],
    path: [u8; 128],
}

unsafe impl aya::Pod for FileEvent {}

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

pub fn start_file_event_logger(bpf: &mut Ebpf) -> Result<()> {
    let map = bpf
        .take_map("FILE_EVENTS")
        .context("missing FILE_EVENTS map")?;
    let mut events = AsyncPerfEventArray::try_from(map).context("FILE_EVENTS map type mismatch")?;
    let cmd_cache: Arc<Mutex<std::collections::HashMap<u32, String>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    let cpus = online_cpus()
        .map_err(|(_, e)| e)
        .context("failed to list online CPUs")?;
    for cpu in cpus {
        let mut buf = events
            .open(cpu, None)
            .with_context(|| format!("failed to open FILE_EVENTS buffer for cpu {cpu}"))?;
        let cache = Arc::clone(&cmd_cache);
        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 64];
            loop {
                let Ok(read) = buf.read_events(&mut buffers).await else {
                    continue;
                };
                for raw in buffers.iter().take(read.read) {
                    if raw.len() < core::mem::size_of::<FileEvent>() {
                        continue;
                    }

                    let evt = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const FileEvent) };
                    let op = match evt.op {
                        1 => "openat",
                        2 => "openat2",
                        3 => "unlinkat",
                        _ => "unknown",
                    };
                    let path = cstr_bytes(&evt.path);
                    let path_str = core::str::from_utf8(path).unwrap_or("<non-utf8>");
                    let cmd = resolve_cmdline(evt.tgid, &evt.comm, &cache);

                    println!(
                        "file op={} tgid={} pid={} cmd=\"{}\" path=\"{}\"",
                        op, evt.tgid, evt.pid, cmd, path_str
                    );
                }
            }
        });
    }

    Ok(())
}

fn cstr_bytes(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|b| *b == 0) {
        Some(i) => &buf[..i],
        None => buf,
    }
}

fn resolve_cmdline(
    tgid: u32,
    fallback_comm: &[u8; 16],
    cache: &Arc<Mutex<std::collections::HashMap<u32, String>>>,
) -> String {
    if let Ok(guard) = cache.lock() {
        if let Some(cmd) = guard.get(&tgid) {
            return cmd.clone();
        }
    }

    let cmd = std::fs::read(format!("/proc/{tgid}/cmdline"))
        .ok()
        .and_then(|bytes| {
            if bytes.is_empty() {
                None
            } else {
                let s = String::from_utf8_lossy(&bytes).replace('\0', " ");
                Some(s.trim().to_string())
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            core::str::from_utf8(cstr_bytes(fallback_comm))
                .unwrap_or("unknown")
                .to_string()
        });

    if let Ok(mut guard) = cache.lock() {
        guard.insert(tgid, cmd.clone());
    }
    cmd
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
