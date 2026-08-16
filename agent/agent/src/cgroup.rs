//! Cgroup-v2 identity resolver.
//!
//! eBPF supplies the stable kernfs/cgroup id. Userspace periodically indexes
//! the mounted cgroup hierarchy by inode so rules and outbound telemetry can
//! enrich that id with a path and common container-runtime identifiers.

use log::{debug, warn};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct CgroupMetadata {
    pub path: String,
    pub container_id: Option<String>,
    pub pod_uid: Option<String>,
}

static INDEX: OnceLock<RwLock<HashMap<u64, CgroupMetadata>>> = OnceLock::new();

pub fn init() {
    let root = std::env::var("OLOPA_CGROUP_ROOT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"));
    let refresh = std::env::var("OLOPA_CGROUP_REFRESH_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
        .max(1);
    let max_entries = std::env::var("OLOPA_CGROUP_MAX_ENTRIES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(65_536)
        .max(1);

    let index = INDEX.get_or_init(|| RwLock::new(HashMap::new()));
    refresh_index(index, &root, max_entries);
    if let Err(err) = std::thread::Builder::new()
        .name("olopa-cgroup-index".to_string())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(refresh));
            if let Some(index) = INDEX.get() {
                refresh_index(index, &root, max_entries);
            }
        })
    {
        warn!("failed starting cgroup metadata refresher: {}", err);
    }
}

pub fn lookup(cgroup_id: u64) -> Option<CgroupMetadata> {
    if cgroup_id == 0 {
        return None;
    }
    INDEX
        .get()
        .and_then(|index| index.read().ok())
        .and_then(|index| index.get(&cgroup_id).cloned())
}

fn refresh_index(shared: &RwLock<HashMap<u64, CgroupMetadata>>, root: &Path, max_entries: usize) {
    match scan(root, max_entries) {
        Ok(next) => {
            debug!("cgroup metadata index refreshed entries={}", next.len());
            if let Ok(mut index) = shared.write() {
                *index = next;
            }
        }
        Err(err) => warn!(
            "cgroup metadata scan failed root={}: {}",
            root.display(),
            err
        ),
    }
}

fn scan(root: &Path, max_entries: usize) -> std::io::Result<HashMap<u64, CgroupMetadata>> {
    let mut out = HashMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let rendered = format!("/{}", relative.to_string_lossy()).replace("//", "/");
            out.insert(
                metadata.ino(),
                CgroupMetadata {
                    container_id: extract_container_id(relative),
                    pod_uid: extract_pod_uid(relative),
                    path: rendered,
                },
            );
            if out.len() >= max_entries {
                break;
            }
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                        pending.push(entry.path());
                    }
                }
            }
        }
    }
    Ok(out)
}

fn extract_container_id(path: &Path) -> Option<String> {
    path.components().rev().find_map(|component| {
        let raw = component.as_os_str().to_string_lossy();
        let trimmed = raw
            .strip_suffix(".scope")
            .unwrap_or(&raw)
            .strip_prefix("docker-")
            .or_else(|| {
                raw.strip_suffix(".scope")
                    .unwrap_or(&raw)
                    .strip_prefix("cri-containerd-")
            })
            .or_else(|| {
                raw.strip_suffix(".scope")
                    .unwrap_or(&raw)
                    .strip_prefix("crio-")
            })
            .unwrap_or(raw.strip_suffix(".scope").unwrap_or(&raw));
        is_hex_id(trimmed).then(|| trimmed.to_string())
    })
}

fn extract_pod_uid(path: &Path) -> Option<String> {
    path.components().find_map(|component| {
        let raw = component.as_os_str().to_string_lossy();
        let value = raw.strip_prefix("pod")?.replace('_', "-");
        (!value.is_empty()).then_some(value)
    })
}

fn is_hex_id(value: &str) -> bool {
    value.len() >= 12 && value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_common_runtime_and_pod_identifiers() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let path = PathBuf::from(format!(
            "kubepods.slice/pod1234_abcd/cri-containerd-{id}.scope"
        ));
        assert_eq!(extract_container_id(&path).as_deref(), Some(id));
        assert_eq!(extract_pod_uid(&path).as_deref(), Some("1234-abcd"));
    }
}
