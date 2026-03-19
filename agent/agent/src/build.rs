//! build.rs — runs before the agent crate compiles.
//!
//! Uses aya-build to invoke cargo for the eBPF crate (bpfel-unknown-none target)
//! and places the resulting ELF object in OUT_DIR so the agent can embed it
//! via: aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/olopa-ebpf-bin"))

use aya_build::{Package, Toolchain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
