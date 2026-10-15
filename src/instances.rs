//! Registry of running `mcp serve` instances.
//!
//! Each `serve` process writes `<pid>.json` under `config_dir()/instances/`
//! and holds an exclusive `flock` on that file for its whole life. The lock,
//! not the pid, is what proves liveness: the kernel releases it when the
//! process dies, however it dies, so a reader can tell a live instance from a
//! leftover file without ever trusting a pid.
//!
//! That distinction is the whole reason the lock is here. `mcp reload` signals
//! instances with SIGHUP, and SIGHUP's default disposition is terminate. A
//! stale file holding a pid the kernel has since handed to something else
//! would turn `mcp reload` into a command that kills an unrelated process of
//! the user's.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;

/// Catalog narrowing an instance was started with (`--only` / `--exclude`).
///
/// Recorded so a reload can re-apply it: an instance that was told to publish
/// a subset of the catalog must never widen it just because the config on disk
/// grew.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstanceFilter {
    pub only: Option<String>,
    pub exclude: Option<String>,
}

impl InstanceFilter {
    pub fn is_empty(&self) -> bool {
        self.only.is_none() && self.exclude.is_none()
    }
}

/// A live `serve` process, as described by its own instance file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub pid: u32,
    /// `"http"` or `"stdio"`.
    pub transport: String,
    /// Bind address, `http` only.
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub only: Option<String>,
    #[serde(default)]
    pub exclude: Option<String>,
    pub version: String,
    pub started_at: String,
}

impl InstanceRecord {
    /// Short human label for CLI output: `http 127.0.0.1:7332` or `stdio`.
    pub fn label(&self) -> String {
        match &self.addr {
            Some(addr) => format!("{} {addr}", self.transport),
            None => self.transport.clone(),
        }
    }

    pub fn filter(&self) -> InstanceFilter {
        InstanceFilter {
            only: self.only.clone(),
            exclude: self.exclude.clone(),
        }
    }
}

/// Holds an instance file and its lock. Dropping it releases the lock and
/// unlinks the file, so a clean exit leaves nothing for the next reader to
/// prune.
pub struct InstanceHandle {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl Drop for InstanceHandle {
    fn drop(&mut self) {
        // Release the lock before unlinking: the slot is then free the instant
        // the path disappears, with no window where a reader sees a locked
        // file that is already gone.
        self.file.take();
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn instances_dir() -> Result<PathBuf> {
    Ok(crate::config::config_dir()?.join("instances"))
}

fn record_path(pid: u32) -> Result<PathBuf> {
    Ok(instances_dir()?.join(format!("{pid}.json")))
}

#[cfg(unix)]
mod imp {
    use super::{record_path, InstanceFilter, InstanceHandle, InstanceRecord};
    use anyhow::{Context, Result};
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    /// Try to take the exclusive lock without blocking.
    ///
    /// `Ok(true)` means the lock was acquired, which means nobody else holds
    /// it, which means the instance that wrote this file is gone.
    fn try_lock(file: &File) -> std::io::Result<bool> {
        // SAFETY: `as_raw_fd` is valid for as long as `file` is borrowed, and
        // flock touches nothing but kernel lock state for that descriptor.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // Held by a live instance. EAGAIN and EWOULDBLOCK are the same
            // value on Linux and macOS, so one arm covers both.
            Some(libc::EWOULDBLOCK) => Ok(false),
            _ => Err(err),
        }
    }

    pub fn register(
        transport: &str,
        addr: Option<&str>,
        filter: &InstanceFilter,
    ) -> Result<InstanceHandle> {
        let dir = super::instances_dir()?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        // The directory lists what is running on this machine and the files
        // carry bind addresses; keep it to the owner.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));

        let pid = std::process::id();
        let path = record_path(pid)?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;

        if !try_lock(&file).with_context(|| format!("failed to lock {}", path.display()))? {
            // Our own pid, already locked by another live process: the pid
            // namespace would have to be lying to us.
            anyhow::bail!(
                "instance file {} is locked by another process",
                path.display()
            );
        }

        let record = InstanceRecord {
            pid,
            transport: transport.to_string(),
            addr: addr.map(|a| a.to_string()),
            only: filter.only.clone(),
            exclude: filter.exclude.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: chrono::Local::now().to_rfc3339(),
        };

        // A stale file from a recycled pid may still be here; the open above
        // deliberately did not truncate, so that the lock attempt came first.
        file.set_len(0)
            .with_context(|| format!("failed to truncate {}", path.display()))?;
        let body = serde_json::to_vec_pretty(&record)?;
        file.write_all(&body)
            .with_context(|| format!("failed to write {}", path.display()))?;
        file.flush().ok();

        tracing::info!(
            pid,
            transport,
            addr = addr.unwrap_or("-"),
            "instance registered"
        );

        Ok(InstanceHandle {
            path: Some(path),
            file: Some(file),
        })
    }

    /// Read one instance file, pruning it when no live process holds its lock.
    fn read_one(path: &Path) -> Result<Option<InstanceRecord>> {
        let file =
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        if try_lock(&file).with_context(|| format!("failed to probe {}", path.display()))? {
            drop(file);
            let _ = std::fs::remove_file(path);
            tracing::debug!(path = %path.display(), "pruned stale instance file");
            return Ok(None);
        }
        drop(file);

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let record: InstanceRecord = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(Some(record))
    }

    pub fn list_live() -> Result<Vec<InstanceRecord>> {
        let dir = super::instances_dir()?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping unreadable instance entry");
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // A single unreadable or corrupt file must not hide every other
            // running instance from `mcp reload`.
            match read_one(&path) {
                Ok(Some(rec)) => out.push(rec),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = format!("{e:#}"), "skipping instance file")
                }
            }
        }
        out.sort_by_key(|r| r.pid);
        Ok(out)
    }

    pub fn signal_reload(rec: &InstanceRecord) -> Result<()> {
        let path = record_path(rec.pid)?;
        // Re-probe immediately before signalling. Between `list_live` and here
        // the instance may have exited, and a pid the kernel has reused would
        // be terminated by the SIGHUP it never asked for.
        let file = File::open(&path)
            .with_context(|| format!("instance {} is no longer registered", rec.pid))?;
        if try_lock(&file).with_context(|| format!("failed to probe {}", path.display()))? {
            drop(file);
            let _ = std::fs::remove_file(&path);
            anyhow::bail!("instance {} is no longer running", rec.pid);
        }
        drop(file);

        // SAFETY: plain kill(2) with a pid proven live by the lock above.
        let rc = unsafe { libc::kill(rec.pid as libc::pid_t, libc::SIGHUP) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to signal instance {}", rec.pid));
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{InstanceFilter, InstanceHandle, InstanceRecord};
    use anyhow::Result;

    /// Instance tracking rides on `flock` and SIGHUP, neither of which exists
    /// here. A reload reaches a proxy on Windows over HTTP (`mcp reload
    /// --url`), so nothing is registered and nothing is discoverable.
    pub fn register(
        _transport: &str,
        _addr: Option<&str>,
        _filter: &InstanceFilter,
    ) -> Result<InstanceHandle> {
        Ok(InstanceHandle {
            path: None,
            file: None,
        })
    }

    pub fn list_live() -> Result<Vec<InstanceRecord>> {
        Ok(Vec::new())
    }

    pub fn signal_reload(_rec: &InstanceRecord) -> Result<()> {
        anyhow::bail!(
            "signal-based reload is not supported on this platform — use `mcp reload --url <url>`"
        )
    }
}

/// Register this process as a running instance. The returned handle must be
/// held for the process's lifetime: dropping it deregisters the instance.
pub fn register(
    transport: &str,
    addr: Option<&str>,
    filter: &InstanceFilter,
) -> Result<InstanceHandle> {
    imp::register(transport, addr, filter)
}

/// Every instance whose lock is still held, pruning stale files on the way.
pub fn list_live() -> Result<Vec<InstanceRecord>> {
    imp::list_live()
}

/// Ask a running instance to reload its config (SIGHUP).
pub fn signal_reload(rec: &InstanceRecord) -> Result<()> {
    imp::signal_reload(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Points `config_dir()` at a tempdir and restores the env on drop.
    struct ConfigHome {
        _dir: tempfile::TempDir,
        previous: Option<String>,
        _guard: MutexGuard<'static, ()>,
    }

    impl ConfigHome {
        fn new() -> Self {
            let guard = env_lock();
            let previous = std::env::var("MCP_CONFIG_DIR").ok();
            let dir = tempfile::tempdir().unwrap();
            std::env::set_var("MCP_CONFIG_DIR", dir.path());
            Self {
                _dir: dir,
                previous,
                _guard: guard,
            }
        }
    }

    impl Drop for ConfigHome {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var("MCP_CONFIG_DIR", v),
                None => std::env::remove_var("MCP_CONFIG_DIR"),
            }
        }
    }

    fn filter(only: Option<&str>, exclude: Option<&str>) -> InstanceFilter {
        InstanceFilter {
            only: only.map(String::from),
            exclude: exclude.map(String::from),
        }
    }

    #[test]
    #[cfg(unix)]
    fn register_then_list_sees_this_process() {
        let _home = ConfigHome::new();
        let handle = register("http", Some("127.0.0.1:7332"), &filter(None, Some("a,b"))).unwrap();

        let live = list_live().unwrap();
        assert_eq!(live.len(), 1, "the registered instance must be listed");
        let rec = &live[0];
        assert_eq!(rec.pid, std::process::id());
        assert_eq!(rec.transport, "http");
        assert_eq!(rec.addr.as_deref(), Some("127.0.0.1:7332"));
        assert_eq!(rec.exclude.as_deref(), Some("a,b"));
        assert_eq!(rec.version, env!("CARGO_PKG_VERSION"));

        drop(handle);
    }

    /// The filter has to survive the round trip, or a reload would widen the
    /// catalog an instance was started to narrow.
    #[test]
    #[cfg(unix)]
    fn filter_round_trips_through_the_record() {
        let _home = ConfigHome::new();
        let handle = register("http", None, &filter(Some("roam,grafana"), None)).unwrap();
        let live = list_live().unwrap();
        let restored = live[0].filter();
        assert_eq!(restored.only.as_deref(), Some("roam,grafana"));
        assert!(restored.exclude.is_none());
        drop(handle);
    }

    #[test]
    #[cfg(unix)]
    fn dropping_the_handle_deregisters() {
        let _home = ConfigHome::new();
        let handle = register("stdio", None, &InstanceFilter::default()).unwrap();
        let path = instances_dir()
            .unwrap()
            .join(format!("{}.json", std::process::id()));
        assert!(path.exists());

        drop(handle);

        assert!(!path.exists(), "a clean exit must leave no instance file");
        assert!(list_live().unwrap().is_empty());
    }

    /// A file whose writer died without cleaning up holds no lock, so it must
    /// be pruned rather than reported as a live instance to signal.
    #[test]
    #[cfg(unix)]
    fn stale_file_is_pruned() {
        let _home = ConfigHome::new();
        let dir = instances_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("999999.json");
        let record = InstanceRecord {
            pid: 999_999,
            transport: "http".into(),
            addr: Some("127.0.0.1:9999".into()),
            only: None,
            exclude: None,
            version: "0.0.0".into(),
            started_at: "2026-10-09T00:00:00-03:00".into(),
        };
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

        let live = list_live().unwrap();

        assert!(live.is_empty(), "an unlocked file is not a live instance");
        assert!(!path.exists(), "the stale file must be pruned");
    }

    /// Signalling a pruned instance must fail loudly instead of sending SIGHUP
    /// to whatever now owns that pid.
    #[test]
    #[cfg(unix)]
    fn signalling_a_dead_instance_is_refused() {
        let _home = ConfigHome::new();
        let dir = instances_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let record = InstanceRecord {
            pid: 999_998,
            transport: "http".into(),
            addr: None,
            only: None,
            exclude: None,
            version: "0.0.0".into(),
            started_at: "2026-10-09T00:00:00-03:00".into(),
        };
        let path = dir.join("999998.json");
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

        let err = signal_reload(&record).unwrap_err();

        assert!(
            format!("{err:#}").contains("no longer running"),
            "unexpected error: {err:#}"
        );
        assert!(!path.exists(), "the refused instance file must be pruned");
    }

    #[test]
    #[cfg(unix)]
    fn corrupt_file_does_not_hide_other_instances() {
        let _home = ConfigHome::new();
        let handle = register("http", Some("127.0.0.1:7332"), &InstanceFilter::default()).unwrap();
        let dir = instances_dir().unwrap();
        std::fs::write(dir.join("123456.json"), b"{ not json").unwrap();

        let live = list_live().unwrap();

        assert_eq!(live.len(), 1, "the healthy instance must still be listed");
        assert_eq!(live[0].pid, std::process::id());
        drop(handle);
    }

    #[test]
    fn list_live_on_a_missing_directory_is_empty() {
        let _home = ConfigHome::new();
        assert!(list_live().unwrap().is_empty());
    }

    #[test]
    fn label_reads_as_transport_and_addr() {
        let mut rec = InstanceRecord {
            pid: 1,
            transport: "http".into(),
            addr: Some("127.0.0.1:7332".into()),
            only: None,
            exclude: None,
            version: "0.0.0".into(),
            started_at: "2026-10-09T00:00:00-03:00".into(),
        };
        assert_eq!(rec.label(), "http 127.0.0.1:7332");
        rec.addr = None;
        rec.transport = "stdio".into();
        assert_eq!(rec.label(), "stdio");
    }

    #[test]
    fn empty_filter_is_reported_empty() {
        assert!(InstanceFilter::default().is_empty());
        assert!(!filter(Some("a"), None).is_empty());
        assert!(!filter(None, Some("b")).is_empty());
    }
}
