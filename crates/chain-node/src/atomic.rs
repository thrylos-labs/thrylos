//! Replacing a file so that a crash leaves the old one or the new one.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Writes `bytes` to `path`, atomically and durably: to a temporary file,
/// synced, renamed over `path`, and the directory synced.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    {
        let mut file = File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    sync_parent(path)
}

/// Makes the directory entry for `path` durable.
pub(crate) fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}
