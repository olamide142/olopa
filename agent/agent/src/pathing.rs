use std::path::{Path, PathBuf};

/// Resolve a path by trying:
/// 1) as provided
/// 2) relative to executable directory (useful for packaged deployments)
pub fn resolve_path(path: &Path) -> PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }
    if !path.is_absolute() {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let candidate = parent.join(path);
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    path.to_path_buf()
}

