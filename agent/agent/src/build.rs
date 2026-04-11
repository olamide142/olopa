//! Build script for `olopa`.
//!
//! Purpose:
//! - Compile the eBPF crate (`../ebpf`) during userspace build.
//! - Place generated eBPF ELF into `OUT_DIR`.
//! - Let userspace embed that ELF via `include_bytes_aligned!`.
//!
//! This keeps deploy simple: one userspace binary already contains its
//! matching eBPF object (no external runtime object path required).

use aya_build::{Package, Toolchain};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const EBPF_BIN_NAME: &str = "olopa-ebpf-bin";

fn copy_prebuilt_ebpf(out_dir: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    // Optional explicit override used by CI/release pipelines.
    let explicit = env::var("OLOPA_EBPF_PREBUILT")
        .ok()
        .map(PathBuf::from);
    let default_prebuilt = PathBuf::from("../ebpf/prebuilt").join(EBPF_BIN_NAME);

    for candidate in explicit.into_iter().chain([default_prebuilt]) {
        if candidate.is_file() {
            let dst = out_dir.join(EBPF_BIN_NAME);
            fs::copy(&candidate, &dst)?;
            println!("cargo:warning=using prebuilt eBPF object: {}", candidate.display());
            return Ok(true);
        }
    }

    Ok(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../ebpf");
    println!("cargo:rerun-if-changed=../ebpf/prebuilt/olopa-ebpf-bin");
    println!("cargo:rerun-if-env-changed=OLOPA_EBPF_PREBUILT");

    let out_dir = env::var_os("OUT_DIR")
        .ok_or_else(|| io::Error::other("OUT_DIR not set"))?;
    let out_dir = PathBuf::from(out_dir);

    if copy_prebuilt_ebpf(&out_dir)? {
        return Ok(());
    }

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
