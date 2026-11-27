//! Credential files are written owner-only.
//!
//! `std::fs::write` respects nothing but the umask, which on a normal host
//! leaves a token file at 0644. On a shared machine that is enough for another
//! local user to read a refresh token valid for a month, so every writer of a
//! file that holds a credential goes through here instead.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Creates `dir` (and parents) with mode 0700 when it does not exist.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("failed to create {}", dir.display()))
}

/// Writes `bytes` with mode 0600, creating the file if needed.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    harden(path)
}

/// Removes group/other permissions from an existing file.
pub fn harden(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !path.exists() {
            return Ok(());
        }
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o077 != 0 {
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions)
                .with_context(|| format!("failed to chmod {}", path.display()))?;
        }
    }
    Ok(())
}

/// The mode a file currently has, when it is readable by group or others.
pub fn permissive_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).ok()?;
        let mode = metadata.permissions().mode() & 0o777;
        (mode & 0o077 != 0).then_some(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Warns once at startup about credential files other local users can read.
pub fn warn_if_permissive(paths: &[(&str, std::path::PathBuf)]) {
    for (label, path) in paths {
        if let Some(mode) = permissive_mode(path) {
            tracing::warn!(
                file = %path.display(),
                mode = format!("{mode:o}"),
                "{label} is readable by other local users — rewriting it will set 0600"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_private_write_is_owner_only_even_when_the_file_existed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");

        // An older build left it world-readable.
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(permissive_mode(&path), Some(0o644));

        write_private(&path, b"{\"token\":\"x\"}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(permissive_mode(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("mcp");
        create_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
