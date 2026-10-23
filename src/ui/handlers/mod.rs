//! Route handlers, one module per screen.

pub mod access;
pub mod activity;
pub mod overview;
pub mod playground;
pub mod servers;
pub mod settings;

use crate::config::ServerConfig;
use crate::config_source::ConfigSource;

/// The path shown in the chrome (or the inline pseudo-source).
pub fn source_label(source: &ConfigSource) -> String {
    source
        .path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| crate::config_source::INLINE_SOURCE.to_string())
}

/// Publishes a config change.
///
/// Inside the proxy (team mode) the config is re-applied in process; from
/// `mcp ui` the only way to reach the proxies is SIGHUP through the instance
/// registry, and the message says so.
pub async fn publish(state: &crate::ui::UiState) -> String {
    match state.reload_now().await {
        Some(Ok(message)) => message,
        Some(Err(e)) => format!("config saved, but the reload failed: {e:#}"),
        None => {
            let (signalled, tried, errors) = reload_instances(None);
            if tried == 0 {
                "config saved; no running mcp serve instance to signal".to_string()
            } else if errors.is_empty() {
                format!(
                    "config saved; signalled {signalled} of {tried} instance(s) — SIGHUP is a request, not an acknowledgement"
                )
            } else {
                format!(
                    "config saved; signalled {signalled} of {tried} instance(s); errors: {}",
                    errors.join("; ")
                )
            }
        }
    }
}

/// Sends SIGHUP to every live instance (or just `pid`), returning
/// `(signalled, tried, errors)`.
///
/// The signal has no acknowledgement: the proxy reloads from disk and keeps
/// going. The UI must say "signalled", not "applied".
pub fn reload_instances(pid: Option<u32>) -> (usize, usize, Vec<String>) {
    let records = crate::instances::list_live().unwrap_or_default();
    let targets: Vec<_> = records
        .into_iter()
        .filter(|r| pid.is_none() || Some(r.pid) == pid)
        .collect();
    let tried = targets.len();
    let mut signalled = 0;
    let mut errors = Vec::new();
    for record in targets {
        match crate::instances::signal_reload(&record) {
            Ok(()) => signalled += 1,
            Err(e) => errors.push(format!("pid {}: {e}", record.pid)),
        }
    }
    (signalled, tried, errors)
}

/// Connects to a backend the same way `mcp <server> --list` does.
pub async fn connect(server: &ServerConfig) -> anyhow::Result<crate::client::McpClient> {
    crate::client::McpClient::connect(server).await
}

/// Truncates a description for a table cell.
pub fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}
