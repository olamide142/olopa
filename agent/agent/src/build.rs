//! build.rs — runs before the agent crate compiles.
//!
//! Uses aya-build to invoke cargo for the eBPF crate (bpfel-unknown-none target)
//! and places the resulting ELF object in OUT_DIR so the agent can embed it
//! via: aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/olopa-ebpf-bin"))

//! Build script for `olopa-agent`.
//!
//! Purpose:
//! - Compile the eBPF crate (`../ebpf`) during userspace build.
//! - Place generated eBPF ELF into `OUT_DIR`.
//! - Let userspace embed that ELF via `include_bytes_aligned!`.
//!
//! This keeps deploy simple: one userspace binary already contains its
//! matching eBPF object (no external runtime object path required).

use aya_build::{Package, Toolchain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile eBPF package(s) for the configured toolchain and target.
    // Result artifact is copied to OUT_DIR with a stable name that
    // `agent.rs` expects at runtime.
    aya_build::build_ebpf(
        [Package {
            name: "olopa-ebpf",
            root_dir: "../ebpf",
            ..Default::default()
        }],
        Toolchain::default(),
    )?;

    Ok(())
}
