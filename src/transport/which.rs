//! Resolve a backend's `command` against `PATH` before anything tries to
//! spawn it.
//!
//! Without this the failure surfaces as the OS spawn error ("No such file or
//! directory"), which names neither the command nor the reason. That is
//! especially confusing inside a container, where a `command` backend that
//! works on the host is simply not installed.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;

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

/// Check that `command` is something the OS can execute, the way a shell would
/// look it up. `Ok` means the spawn is worth attempting.
///
/// A name containing a path separator is checked directly. A bare name is
/// looked up in each `PATH` entry, in order.
///
/// `env` is the backend's own environment block. A backend may set `PATH`
/// there, and `Command` resolves a bare name against the **child's** `PATH`,
/// not ours, so that entry has to win here too. Pinning `PATH` per backend is
/// the standard workaround for GUI clients that launch `mcp` with a stripped
/// environment, and reading the parent's `PATH` would refuse a config that
/// spawns perfectly well.
pub fn resolve_command(
    command: &str,
    env: &HashMap<String, String>,
) -> Result<(), CommandUnavailable> {
    let path_var = env
        .get("PATH")
        .map(OsString::from)
        .or_else(|| std::env::var_os("PATH"));
    resolve_command_in(command, path_var)
}

/// The lookup itself, with `PATH` passed in rather than read from the
/// environment. Tests drive this one: mutating `PATH` for real races with
/// every other test in the binary, since `std::env` is process-wide.
fn resolve_command_in(command: &str, path_var: Option<OsString>) -> Result<(), CommandUnavailable> {
    if command.is_empty() {
        return Err(CommandUnavailable::NotInPath {
            command: command.to_string(),
        });
    }

    // Explicit path: check it directly, no PATH lookup.
    if command.contains(std::path::MAIN_SEPARATOR) || command.contains('/') {
        let path = Path::new(command);
        if is_executable_file(path) {
            return Ok(());
        }
        // Windows appends PATHEXT to an extensionless path too, not just to a
        // bare name, so `C:\tools\server` spawns `server.exe`. Empty on unix.
        for ext in path_extensions() {
            if is_executable_file(Path::new(&format!("{command}{ext}"))) {
                return Ok(());
            }
        }
        if !path.exists() {
            return Err(CommandUnavailable::NoSuchFile {
                path: command.to_string(),
            });
        }
        return Err(CommandUnavailable::NotExecutable {
            path: command.to_string(),
        });
    }

    // No usable PATH to search. `execvp` falls back to a system default
    // (confstr _CS_PATH) and still finds the command, so refusing here would
    // reject something the spawn would have run. launchd and systemd units
    // routinely start a process with no PATH at all. This check exists to
    // improve the error message, never to add a new way to fail. When it
    // cannot know, it stays out of the way and lets the spawn decide.
    let path_var = match path_var {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(()),
    };

    let extensions = path_extensions();
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        if is_executable_file(&dir.join(command)) {
            return Ok(());
        }
        for ext in &extensions {
            if is_executable_file(&dir.join(format!("{command}{ext}"))) {
                return Ok(());
            }
        }
    }

    Err(CommandUnavailable::NotInPath {
        command: command.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MISSING: &str = "mcp-definitely-not-a-real-binary";

    /// The real `PATH`, for the cases that are about a genuinely installed
    /// command. Passed explicitly so no test has to mutate the environment.
    fn real_path() -> Option<OsString> {
        std::env::var_os("PATH")
    }

    #[test]
    fn resolves_a_bare_name_from_path() {
        // `sh` exists on every platform this runs CI on.
        assert!(resolve_command_in("sh", real_path()).is_ok());
    }

    #[test]
    fn reports_a_bare_name_that_is_not_installed() {
        let err = resolve_command_in(MISSING, real_path()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "command not found in PATH: mcp-definitely-not-a-real-binary"
        );
    }

    #[test]
    fn searches_every_path_entry_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        let file = dir.path().join("only-here");
        write_executable(&file);

        // The command sits in the second entry, so a lookup that stops at the
        // first would miss it.
        let path = std::env::join_paths([empty.path(), dir.path()]).unwrap();
        assert!(resolve_command_in("only-here", Some(path)).is_ok());
    }

    #[test]
    fn reports_an_absolute_path_that_does_not_exist() {
        // The shape of a Homebrew backend on a machine that has no Homebrew.
        let err =
            resolve_command_in("/opt/homebrew/bin/mcp-not-installed", real_path()).unwrap_err();
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

        let err = resolve_command_in(&path, real_path()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("command is not executable: {path}")
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_a_path_once_it_is_executable() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("runnable");
        write_executable(&file);

        assert!(resolve_command_in(&file.to_string_lossy(), real_path()).is_ok());
    }

    #[test]
    fn reports_a_directory_as_not_executable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let err = resolve_command_in(&path, real_path()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("command is not executable: {path}")
        );
    }

    #[test]
    fn empty_command_is_not_in_path() {
        assert_eq!(
            resolve_command_in("", real_path()).unwrap_err(),
            CommandUnavailable::NotInPath {
                command: String::new()
            }
        );
    }

    /// `Command::new` with no PATH in the environment still spawns, because
    /// execvp falls back to the system default path. Refusing here would be a
    /// regression for anything started by launchd, systemd or cron with a
    /// stripped environment.
    #[test]
    fn absent_path_never_blocks() {
        assert!(resolve_command_in(MISSING, None).is_ok());
    }

    #[test]
    fn empty_path_never_blocks() {
        assert!(resolve_command_in(MISSING, Some(OsString::new())).is_ok());
    }

    /// The public entry point reads the environment; the rest of the suite
    /// drives `resolve_command_in` directly.
    #[test]
    fn public_entry_point_reads_the_environment() {
        let empty = HashMap::new();
        assert!(resolve_command("sh", &empty).is_ok());
        assert!(resolve_command(MISSING, &empty).is_err());
    }

    /// `Command` resolves a bare name against the child's PATH, so a backend
    /// that pins `PATH` in its own `env` spawns fine and must not be refused
    /// here. This is the shape GUI clients need, since they launch `mcp` with
    /// a stripped environment.
    #[test]
    fn backend_env_path_wins_over_the_parent() {
        let dir = tempfile::tempdir().unwrap();
        write_executable(&dir.path().join("pinned-tool"));

        let mut env = HashMap::new();
        env.insert("PATH".to_string(), dir.path().to_string_lossy().to_string());

        // Not on the parent's PATH...
        assert!(
            resolve_command_in("pinned-tool", real_path()).is_err(),
            "precondition: the tool must be absent from the parent PATH"
        );
        // ...but the backend pinned a PATH that has it.
        assert!(resolve_command("pinned-tool", &env).is_ok());
    }

    /// The reverse direction: a backend whose pinned PATH does *not* have the
    /// command is still refused, so the check keeps working when it applies.
    #[test]
    fn backend_env_path_still_refuses_what_it_does_not_contain() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), dir.path().to_string_lossy().to_string());

        assert!(resolve_command(MISSING, &env).is_err());
    }

    /// Windows resolves an extensionless explicit path through PATHEXT the
    /// same way it resolves a bare name. On unix `path_extensions` is empty,
    /// so this asserts the plain case there.
    #[test]
    fn explicit_path_resolves_through_path_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tool");
        write_executable(&file);

        assert!(resolve_command_in(&file.to_string_lossy(), real_path()).is_ok());
    }

    #[cfg(unix)]
    fn write_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(not(unix))]
    fn write_executable(path: &Path) {
        std::fs::write(path, b"").unwrap();
    }
}
