use std::path::PathBuf;

use clap::Parser;

/// Runtime arguments for the userspace security agent.
#[derive(Debug, Parser)]
#[command(
    name = "agent",
    about = "Aya eBPF runtime security agent with telemetry + cgroup network enforcement"
)]
pub struct Args {
    /// Path to the compiled eBPF object file.
    #[arg(long, default_value = "target/bpfel-unknown-none/release/agent-ebpf")]
    pub ebpf: PathBuf,
    /// Cgroup path for cgroup_sock_addr enforcement programs.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup: PathBuf,
    /// JSON policy file path (see README for schema).
    #[arg(long, default_value = "policy.json")]
    pub policy: PathBuf,
    /// Kill violating process when violation threshold is reached.
    #[arg(long, default_value_t = false)]
    pub kill_on_violation: bool,
    /// Violation count threshold before response action.
    #[arg(long, default_value_t = 20)]
    pub violation_threshold: u64,
    /// Violation polling interval in seconds.
    #[arg(long, default_value_t = 2)]
    pub poll_interval_secs: u64,
}

