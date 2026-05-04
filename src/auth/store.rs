use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Once;

use crate::config;

/// Inline JSON content of the auth store, provided via env var.
/// Highest precedence — when set, file-based loading is skipped and writes
/// become no-ops (logged once via `tracing::warn`).
const AUTH_CONFIG_ENV: &str = "MCP_AUTH_CONFIG";

/// File path override for `auth.json`. Lower precedence than `MCP_AUTH_CONFIG`.
const AUTH_PATH_ENV: &str = "MCP_AUTH_PATH";

/// Returns inline auth content from `MCP_AUTH_CONFIG`, if set and non-empty.
fn auth_inline_content() -> Option<String> {
    std::env::var(AUTH_CONFIG_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthStore {
    #[serde(default)]
    pub clients: HashMap<String, ClientRegistration>,
    #[serde(default)]
    pub tokens: HashMap<String, StoredTokens>,
}

pub fn auth_store_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(AUTH_PATH_ENV) {
        let path = path.trim();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    Ok(config::config_dir()?.join("auth.json"))
}

pub fn load_auth_store() -> Result<AuthStore> {
    // Priority 1: inline content via MCP_AUTH_CONFIG (no file mount needed).
    // Intended for read-only deployments (k8s Secrets, Docker secrets).
    if let Some(content) = auth_inline_content() {
        return Ok(serde_json::from_str(&content).unwrap_or_default());
    }

    // Priority 2: file path (MCP_AUTH_PATH or default location).
    let path = auth_store_path()?;
    if !path.exists() {
        return Ok(AuthStore::default());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content).unwrap_or_default())
}

pub fn save_auth_store(store: &AuthStore) -> Result<()> {
    // Inline auth config is read-only by design: the source of truth is the
    // env var (typically a k8s Secret), so persisting back to disk would be
    // ineffective and confusing. Token refreshes still work in-process for
    // the lifetime of the proxy; on restart, the Secret is read again.
    if auth_inline_content().is_some() {
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                env = AUTH_CONFIG_ENV,
                "inline auth config is read-only; skipping write to auth store"
            );
        });
        return Ok(());
    }

    let path = auth_store_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(store)?;
    std::fs::write(&path, content)?;
    Ok(())
}

pub fn server_key(server_url: &str) -> String {
    server_url.trim_end_matches('/').to_string()
}

pub fn to_stored_tokens(resp: &super::oauth::TokenResponse) -> StoredTokens {
    let expires_at = resp.expires_in.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + secs
    });

    StoredTokens {
        access_token: resp.access_token.clone(),
        refresh_token: resp.refresh_token.clone(),
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_key_normalization() {
        assert_eq!(
            server_key("https://mcp.sentry.dev/"),
            "https://mcp.sentry.dev"
        );
        assert_eq!(
            server_key("https://mcp.sentry.dev"),
            "https://mcp.sentry.dev"
        );
    }

    #[test]
    fn test_to_stored_tokens() {
        let resp = super::super::oauth::TokenResponse {
            access_token: "abc".to_string(),
            refresh_token: Some("def".to_string()),
            expires_in: Some(3600),
        };
        let stored = to_stored_tokens(&resp);
        assert_eq!(stored.access_token, "abc");
        assert_eq!(stored.refresh_token.unwrap(), "def");
        assert!(stored.expires_at.unwrap() > 0);
    }

    #[test]
    fn test_to_stored_tokens_no_expiry() {
        let resp = super::super::oauth::TokenResponse {
            access_token: "abc".to_string(),
            refresh_token: None,
            expires_in: None,
        };
        let stored = to_stored_tokens(&resp);
        assert!(stored.expires_at.is_none());
        assert!(stored.refresh_token.is_none());
    }

    // --- Inline auth config tests (MCP_AUTH_CONFIG) ---

    /// Serialize env var access for tests that set/remove env vars.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Snapshot env vars touched by these tests, restore on drop.
    /// Prevents cross-test pollution when running in parallel — even with
    /// `ENV_LOCK`, a panicking test would leak its env state otherwise.
    struct EnvGuard {
        config: Option<String>,
        path: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                config: std::env::var(AUTH_CONFIG_ENV).ok(),
                path: std::env::var(AUTH_PATH_ENV).ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.config {
                Some(v) => std::env::set_var(AUTH_CONFIG_ENV, v),
                None => std::env::remove_var(AUTH_CONFIG_ENV),
            }
            match &self.path {
                Some(v) => std::env::set_var(AUTH_PATH_ENV, v),
                None => std::env::remove_var(AUTH_PATH_ENV),
            }
        }
    }

    #[test]
    fn test_load_inline_auth_config() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();

        let json = r#"{
            "clients": {
                "https://example.com": {"client_id": "cid_inline"}
            },
            "tokens": {
                "https://example.com": {
                    "access_token": "tok_inline",
                    "refresh_token": "ref_inline",
                    "expires_at": 9999999999
                }
            }
        }"#;
        std::env::set_var(AUTH_CONFIG_ENV, json);
        // Point path to a non-existent file; inline must win without touching it.
        std::env::set_var(AUTH_PATH_ENV, "/dev/null/nonexistent-auth.json");

        let store = load_auth_store().unwrap();
        assert_eq!(store.clients["https://example.com"].client_id, "cid_inline");
        assert_eq!(
            store.tokens["https://example.com"].access_token,
            "tok_inline"
        );
    }

    #[test]
    fn test_save_inline_auth_config_is_noop() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        std::env::set_var(AUTH_CONFIG_ENV, r#"{"clients":{},"tokens":{}}"#);
        std::env::set_var(AUTH_PATH_ENV, target.to_str().unwrap());

        let mut store = AuthStore::default();
        store.tokens.insert(
            "https://example.com".to_string(),
            StoredTokens {
                access_token: "fresh".to_string(),
                refresh_token: None,
                expires_at: None,
            },
        );

        // Save returns Ok(()) but must NOT create the file: inline mode is
        // read-only by design (k8s Secret is the source of truth).
        save_auth_store(&store).unwrap();
        assert!(
            !target.exists(),
            "save_auth_store must be a no-op when MCP_AUTH_CONFIG is set"
        );
    }

    #[test]
    fn test_inline_invalid_json_returns_default_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();

        std::env::set_var(AUTH_CONFIG_ENV, "{ not json }}}");
        std::env::remove_var(AUTH_PATH_ENV);

        // Mirror file-based behavior: malformed JSON degrades to empty store
        // rather than crashing the proxy on startup.
        let store = load_auth_store().unwrap();
        assert!(store.clients.is_empty());
        assert!(store.tokens.is_empty());
    }

    #[test]
    fn test_empty_inline_falls_back_to_path() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();

        let mut file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(
            file,
            r#"{{"clients":{{"https://file.com":{{"client_id":"cid_file"}}}},"tokens":{{}}}}"#
        )
        .unwrap();

        // Empty/whitespace MCP_AUTH_CONFIG must not shadow the file path.
        std::env::set_var(AUTH_CONFIG_ENV, "   ");
        std::env::set_var(AUTH_PATH_ENV, file.path().to_str().unwrap());

        let store = load_auth_store().unwrap();
        assert_eq!(store.clients["https://file.com"].client_id, "cid_file");
    }

    #[test]
    fn test_inline_takes_precedence_over_path() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();

        let mut file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(
            file,
            r#"{{"clients":{{"https://file.com":{{"client_id":"cid_file"}}}},"tokens":{{}}}}"#
        )
        .unwrap();
        std::env::set_var(AUTH_PATH_ENV, file.path().to_str().unwrap());
        std::env::set_var(
            AUTH_CONFIG_ENV,
            r#"{"clients":{"https://inline.com":{"client_id":"cid_inline"}},"tokens":{}}"#,
        );

        let store = load_auth_store().unwrap();
        assert!(store.clients.contains_key("https://inline.com"));
        assert!(!store.clients.contains_key("https://file.com"));
    }

    #[test]
    fn test_auth_store_roundtrip() {
        let mut store = AuthStore::default();
        store.clients.insert(
            "https://example.com".to_string(),
            ClientRegistration {
                client_id: "test123".to_string(),
                client_secret: None,
            },
        );
        store.tokens.insert(
            "https://example.com".to_string(),
            StoredTokens {
                access_token: "token".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: Some(9999999999),
            },
        );

        let json = serde_json::to_string(&store).unwrap();
        let loaded: AuthStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.clients["https://example.com"].client_id, "test123");
        assert_eq!(loaded.tokens["https://example.com"].access_token, "token");
    }
}
