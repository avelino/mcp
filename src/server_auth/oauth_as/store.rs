//! Disk persistence for the OAuth AS state. Mirrors the precedence
//! rules of `src/auth/store.rs` (env-var inline → env-var path →
//! default location), so operators familiar with the client store
//! get the same model server-side.
//!
//! Persistence is intentionally minimal: only registered clients and
//! refresh tokens cross restart boundaries. Authorization codes are
//! ephemeral by design (see `state::PersistedState`).

use std::path::PathBuf;
use std::sync::{Once, OnceLock, RwLock};

use anyhow::{Context, Result};

use crate::config;

use super::state::{AsState, PersistedState};

const STATE_INLINE_ENV: &str = "MCP_AUTH_SERVER_CONFIG";
const STATE_PATH_ENV: &str = "MCP_AUTH_SERVER_PATH";

fn inline_content() -> Option<String> {
    std::env::var(STATE_INLINE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn inline_cache() -> &'static RwLock<Option<PersistedState>> {
    static CACHE: OnceLock<RwLock<Option<PersistedState>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}

fn parse_inline(content: &str) -> PersistedState {
    let expanded = config::substitute_env_vars(content);
    serde_json::from_str(&expanded).unwrap_or_default()
}

pub fn state_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(STATE_PATH_ENV) {
        let path = path.trim();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    Ok(config::config_dir()?.join("auth_server.json"))
}

/// Load persisted AS state. Empty default when no source is configured
/// or content is malformed — same forgiving behavior as the client
/// store, so a corrupt file does not block proxy startup.
pub fn load() -> Result<AsState> {
    if let Some(content) = inline_content() {
        if let Some(p) = inline_cache().read().unwrap().as_ref() {
            return Ok(AsState::from_persisted(p.clone()));
        }
        let mut w = inline_cache().write().unwrap();
        if w.is_none() {
            *w = Some(parse_inline(&content));
        }
        return Ok(AsState::from_persisted(w.as_ref().unwrap().clone()));
    }

    let path = state_path()?;
    if !path.exists() {
        return Ok(AsState::default());
    }
    let content = std::fs::read_to_string(&path).context("reading auth_server.json")?;
    let parsed: PersistedState = serde_json::from_str(&content).unwrap_or_default();
    Ok(AsState::from_persisted(parsed))
}

/// Persist a snapshot. In inline mode the snapshot is held in memory
/// only — backing storage is typically a read-only Secret. Otherwise
/// we write atomically (tempfile + rename) so a crash mid-write
/// can't leave a partial JSON behind.
pub fn save(state: &AsState) -> Result<()> {
    let snap = state.snapshot_persisted();

    if inline_content().is_some() {
        *inline_cache().write().unwrap() = Some(snap);
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                env = STATE_INLINE_ENV,
                "inline AS state is read-only on disk; updates kept in memory only"
            );
        });
        return Ok(());
    }

    let path = state_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.clone();
    tmp.set_extension("json.tmp");
    let content = serde_json::to_string_pretty(&snap)?;
    std::fs::write(&tmp, content).context("writing auth_server.json.tmp")?;
    std::fs::rename(&tmp, &path).context("renaming auth_server.json.tmp into place")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_auth::oauth_as::types::{IssuedRefreshToken, RegisteredClient};

    use super::super::test_helpers::env_lock;

    struct EnvGuard {
        config: Option<String>,
        path: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                config: std::env::var(STATE_INLINE_ENV).ok(),
                path: std::env::var(STATE_PATH_ENV).ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.config {
                Some(v) => std::env::set_var(STATE_INLINE_ENV, v),
                None => std::env::remove_var(STATE_INLINE_ENV),
            }
            match &self.path {
                Some(v) => std::env::set_var(STATE_PATH_ENV, v),
                None => std::env::remove_var(STATE_PATH_ENV),
            }
            *inline_cache().write().unwrap() = None;
        }
    }

    fn reset_cache() {
        *inline_cache().write().unwrap() = None;
    }

    #[test]
    fn test_save_then_load_roundtrip_via_file() {
        let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvGuard::capture();
        reset_cache();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth_server.json");
        std::env::remove_var(STATE_INLINE_ENV);
        std::env::set_var(STATE_PATH_ENV, path.to_str().unwrap());

        let s = AsState::default();
        s.register_client(RegisteredClient {
            client_id: "abc".to_string(),
            client_name: None,
            redirect_uris: vec!["https://x.example.com/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            created_at_unix: 1_700_000_000,
        })
        .unwrap();
        s.put_refresh(IssuedRefreshToken {
            token: "rt".to_string(),
            client_id: "abc".to_string(),
            subject: "alice".to_string(),
            roles: vec!["dev".to_string()],
            expires_at_unix: 9_999_999_999,
        });
        save(&s).unwrap();

        // Atomic write must not leave a tempfile behind.
        assert!(path.exists());
        let stale = path.with_extension("json.tmp");
        assert!(!stale.exists(), "tempfile was not renamed cleanly");

        let reloaded = load().unwrap();
        assert!(reloaded.get_client("abc").is_some());
    }

    #[test]
    fn test_inline_takes_precedence_over_path() {
        let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvGuard::capture();
        reset_cache();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth_server.json");
        std::fs::write(
            &path,
            r#"{"clients":{"file-client":{"client_id":"file-client","redirect_uris":[],"grant_types":[],"created_at_unix":0}},"refresh_tokens":{}}"#,
        )
        .unwrap();
        std::env::set_var(STATE_PATH_ENV, path.to_str().unwrap());
        std::env::set_var(
            STATE_INLINE_ENV,
            r#"{"clients":{"inline-client":{"client_id":"inline-client","redirect_uris":[],"grant_types":[],"created_at_unix":0}},"refresh_tokens":{}}"#,
        );

        let s = load().unwrap();
        assert!(s.get_client("inline-client").is_some());
        assert!(
            s.get_client("file-client").is_none(),
            "file path must NOT be read when inline is set"
        );
    }

    #[test]
    fn test_inline_save_does_not_touch_disk() {
        let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvGuard::capture();
        reset_cache();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth_server.json");
        std::env::set_var(STATE_PATH_ENV, path.to_str().unwrap());
        std::env::set_var(STATE_INLINE_ENV, r#"{"clients":{},"refresh_tokens":{}}"#);

        let s = AsState::default();
        s.register_client(RegisteredClient {
            client_id: "abc".to_string(),
            client_name: None,
            redirect_uris: vec![],
            grant_types: vec![],
            created_at_unix: 0,
        })
        .unwrap();
        save(&s).unwrap();
        assert!(
            !path.exists(),
            "save must NOT write to disk in inline mode (typical k8s Secret is read-only)"
        );
    }

    #[test]
    fn test_inline_invalid_json_returns_empty_state() {
        let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvGuard::capture();
        reset_cache();

        std::env::set_var(STATE_INLINE_ENV, "{ not json }");
        std::env::remove_var(STATE_PATH_ENV);

        let s = load().unwrap();
        assert!(s.snapshot_persisted().clients.is_empty());
    }
}
