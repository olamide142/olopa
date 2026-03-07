mod cli;
#[cfg(target_os = "linux")]
mod ebpf_runtime;
#[cfg(target_os = "linux")]
mod pathing;
#[cfg(target_os = "linux")]
mod policy;
#[cfg(target_os = "linux")]
mod response;

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use cli::Args;
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use env_logger::Env;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let ebpf_path = pathing::resolve_path(&args.ebpf);
    let cgroup_path = pathing::resolve_path(&args.cgroup);
    let policy_path = pathing::resolve_path(&args.policy);

    let mut bpf = ebpf_runtime::load_ebpf(&ebpf_path)?;
    ebpf_runtime::start_file_event_logger(&mut bpf)?;
    ebpf_runtime::attach_all_tracepoints(&mut bpf)?;
    ebpf_runtime::attach_cgroup_enforcement(&mut bpf, &cgroup_path)?;
    policy::load_policy(&mut bpf, &policy_path)?;

    println!("runtime security agent attached. press Ctrl+C to stop");
    let tick = Duration::from_secs(args.poll_interval_secs.max(1));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("agent stopping");
                break;
            }
            _ = tokio::time::sleep(tick) => {
                response::process_violations(
                    &mut bpf,
                    args.violation_threshold,
                    args.kill_on_violation,
                )?;
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This Aya eBPF runtime security agent is supported on Linux only.");
    std::process::exit(1);
}
