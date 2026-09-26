//! Resolve a backend's `command` against `PATH` before anything tries to
//! spawn it.
//!
//! Without this the failure surfaces as the OS spawn error ("No such file or
//! directory"), which names neither the command nor the reason. That is
//! especially confusing inside a container, where a `command` backend that
//! works on the host is simply not installed.

use std::path::{Path, PathBuf};

/// Why a configured `command` cannot be executed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandUnavailable {
    /// Bare name (no path separator) that no `PATH` entry provides.
    NotInPath { command: String },
    /// Explicit path that does not exist.
    NoSuchFile { path: String },
    /// Exists, but is a directory or has no execute bit for anyone.
    NotExecutable { path: String },
}

impl std::fmt::Display for CommandUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInPath { command } => {
                write!(f, "command not found in PATH: {command}")
            }
            Self::NoSuchFile { path } => write!(f, "command does not exist: {path}"),
            Self::NotExecutable { path } => write!(f, "command is not executable: {path}"),
        }
    }
}

impl std::error::Error for CommandUnavailable {}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(md) => md.is_file() && md.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    // Windows has no execute bit; existence as a file is the best signal, and
    // the spawn itself still reports anything subtler.
    std::fs::metadata(path)
        .map(|md| md.is_file())
        .unwrap_or(false)
}

/// Extensions Windows appends when resolving a bare command name. Empty on
/// unix, where the name is used verbatim.
#[cfg(windows)]
fn path_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

#[cfg(not(windows))]
fn path_extensions() -> Vec<String> {
    Vec::new()
}

/// Resolve `command` to an executable file, the way a shell would.
///
/// A name containing a path separator is checked directly. A bare name is
/// looked up in each `PATH` entry, in order. Returns the resolved path so
/// callers can log what they are about to run.
pub fn resolve_command(command: &str) -> Result<PathBuf, CommandUnavailable> {
    if command.is_empty() {
        return Err(CommandUnavailable::NotInPath {
            command: command.to_string(),
        });
    }

    // Explicit path: check it directly, no PATH lookup.
    if command.contains(std::path::MAIN_SEPARATOR) || command.contains('/') {
        let path = Path::new(command);
        if !path.exists() {
            return Err(CommandUnavailable::NoSuchFile {
                path: command.to_string(),
            });
        }
        if !is_executable_file(path) {
            return Err(CommandUnavailable::NotExecutable {
                path: command.to_string(),
            });
        }
        return Ok(path.to_path_buf());
    }

    // No usable PATH to search. `execvp` falls back to a system default
    // (confstr _CS_PATH) and still finds the command, so refusing here would
    // reject something the spawn would have run — launchd and systemd units
    // routinely start a process with no PATH at all. This check exists to
    // improve the error message, never to add a new way to fail: when it
    // cannot know, it stays out of the way and lets the spawn decide.
    let path_var = match std::env::var_os("PATH") {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(PathBuf::from(command)),
    };

    let extensions = path_extensions();
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(command);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
        for ext in &extensions {
            let candidate = dir.join(format!("{command}{ext}"));
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(CommandUnavailable::NotInPath {
        command: command.to_string(),
    })
}

/// `resolve_command` reduced to the operator-facing reason, or `None` when the
/// command is runnable. Used by `mcp --list` to flag backends that cannot
/// start in this environment without spawning anything.
pub fn unavailable_reason(command: &str) -> Option<String> {
    resolve_command(command).err().map(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_bare_name_from_path() {
        // `sh` exists on every platform this runs CI on.
        let resolved = resolve_command("sh").expect("sh should resolve");
        assert!(resolved.is_absolute(), "got {resolved:?}");
        assert!(is_executable_file(&resolved));
    }

    #[test]
    fn reports_a_bare_name_that_is_not_installed() {
        let err = resolve_command("mcp-definitely-not-a-real-binary").unwrap_err();
        assert_eq!(
            err.to_string(),
            "command not found in PATH: mcp-definitely-not-a-real-binary"
        );
    }

    #[test]
    fn reports_an_absolute_path_that_does_not_exist() {
        // The shape of a Homebrew backend on a machine that has no Homebrew.
        let err = resolve_command("/opt/homebrew/bin/mcp-not-installed").unwrap_err();
        assert_eq!(
            err.to_string(),
            "command does not exist: /opt/homebrew/bin/mcp-not-installed"
        );
    }

    #[test]
    fn reports_a_path_that_exists_but_is_not_executable() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-executable");
        std::fs::write(&file, b"#!/bin/sh\n").unwrap();
        let path = file.to_string_lossy().to_string();

        let err = resolve_command(&path).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("command is not executable: {path}")
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_a_path_once_it_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("runnable");
        std::fs::write(&file, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resolved = resolve_command(&file.to_string_lossy()).unwrap();
        assert_eq!(resolved, file);
    }

    #[test]
    fn reports_a_directory_as_not_executable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let err = resolve_command(&path).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("command is not executable: {path}")
        );
    }

    #[test]
    fn empty_command_is_not_in_path() {
        assert_eq!(
            resolve_command("").unwrap_err(),
            CommandUnavailable::NotInPath {
                command: String::new()
            }
        );
    }

    #[test]
    fn unavailable_reason_is_none_for_a_runnable_command() {
        assert!(unavailable_reason("sh").is_none());
    }

    /// `Command::new` with no PATH in the environment still spawns, because
    /// execvp falls back to the system default path. Refusing here would be a
    /// regression for anything started by launchd, systemd or cron with a
    /// stripped environment. Serialized: these mutate process-wide env.
    #[test]
    fn absent_or_empty_path_never_blocks() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let original = std::env::var_os("PATH");

        std::env::remove_var("PATH");
        let absent = resolve_command("mcp-definitely-not-a-real-binary");

        std::env::set_var("PATH", "");
        let empty = resolve_command("mcp-definitely-not-a-real-binary");

        match original {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }

        assert!(
            absent.is_ok(),
            "no PATH must defer to the spawn, not refuse"
        );
        assert!(empty.is_ok(), "empty PATH must defer to the spawn too");
    }

    #[test]
    fn unavailable_reason_carries_the_message() {
        assert_eq!(
            unavailable_reason("mcp-definitely-not-a-real-binary").as_deref(),
            Some("command not found in PATH: mcp-definitely-not-a-real-binary")
        );
    }
}
