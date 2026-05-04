use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Once, OnceLock, RwLock};

use crate::config;

/// Inline JSON content of the auth store, provided via env var.
/// Highest precedence — when set, file-based loading is skipped and writes
/// are routed to an in-memory cache instead of disk (with a single
/// `tracing::warn` on the first attempt).
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

/// In-memory auth store used when `MCP_AUTH_CONFIG` is set. Lazy-populated
/// from the env var on first `load_auth_store()` call. `save_auth_store()`
/// updates the cache so OAuth refresh / dynamic-client registration keep
/// working in-process for the lifetime of the proxy — without touching
/// the (typically read-only) underlying Secret.
fn inline_cache() -> &'static RwLock<Option<AuthStore>> {
    static CACHE: OnceLock<RwLock<Option<AuthStore>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}

/// Parse inline JSON, expanding `${VAR}` placeholders the same way
/// `MCP_SERVERS_CONFIG` does. Malformed JSON degrades to an empty store
/// rather than crashing the proxy on startup.
fn parse_inline(content: &str) -> AuthStore {
    let expanded = config::substitute_env_vars(content);
    serde_json::from_str(&expanded).unwrap_or_default()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientRegistration {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
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
    // Backed by an in-memory cache so OAuth refresh and dynamic-client
    // registrations stay coherent across calls — the env var is the seed,
    // not the source of truth at runtime.
    if let Some(content) = auth_inline_content() {
        // Fast path: cache already populated.
        if let Some(store) = inline_cache().read().unwrap().as_ref() {
            return Ok(store.clone());
        }
        // Slow path: seed cache from env. The double-check inside the write
        // lock handles the race where another thread populated it first.
        let mut write = inline_cache().write().unwrap();
        if write.is_none() {
            *write = Some(parse_inline(&content));
        }
        return Ok(write.as_ref().unwrap().clone());
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
    // Inline mode: writes are routed to the in-memory cache, not disk. The
    // source of truth on disk is whatever provisioned the env var (typically
    // a k8s Secret), so we never write back. In-process mutations (refreshed
    // tokens, new client registrations) survive until the proxy restarts.
    if auth_inline_content().is_some() {
        *inline_cache().write().unwrap() = Some(store.clone());
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                env = AUTH_CONFIG_ENV,
                "inline auth config is read-only on disk; updates kept in memory only"
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
            // Cache is process-global; reset between tests so the next one
            // starts from a clean slate (matches a fresh proxy boot).
            *inline_cache().write().unwrap() = None;
        }
    }

    fn reset_inline_cache() {
        *inline_cache().write().unwrap() = None;
    }

    #[test]
    fn test_load_inline_auth_config() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();

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
    fn test_save_inline_does_not_touch_disk() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();

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

        // Save succeeds but must NOT touch disk: in inline mode, mutations
        // live only in the in-memory cache, never on the (typically read-only)
        // backing Secret.
        save_auth_store(&store).unwrap();
        assert!(
            !target.exists(),
            "save_auth_store must not write to disk when MCP_AUTH_CONFIG is set"
        );
    }

    #[test]
    fn test_inline_save_then_load_round_trip() {
        // Regression for review feedback: in inline mode, save+load must
        // preserve mutations across calls (OAuth refresh, dynamic client
        // registration). Without the in-memory cache, the second load would
        // re-parse the env var and lose every change.
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();

        std::env::set_var(
            AUTH_CONFIG_ENV,
            r#"{"clients":{},"tokens":{"https://api.example.com":{"access_token":"old","refresh_token":"r1"}}}"#,
        );
        std::env::remove_var(AUTH_PATH_ENV);

        // Simulate an OAuth refresh: load, mutate, save.
        let mut store = load_auth_store().unwrap();
        store.tokens.insert(
            "https://api.example.com".to_string(),
            StoredTokens {
                access_token: "refreshed".to_string(),
                refresh_token: Some("r2".to_string()),
                expires_at: Some(9999999999),
            },
        );
        store.clients.insert(
            "https://new-server.example.com".to_string(),
            ClientRegistration {
                client_id: "newly-registered".to_string(),
                client_secret: None,
            },
        );
        save_auth_store(&store).unwrap();

        // Subsequent loads must see the in-memory mutations, not the
        // original env content.
        let reloaded = load_auth_store().unwrap();
        assert_eq!(
            reloaded.tokens["https://api.example.com"].access_token,
            "refreshed"
        );
        assert_eq!(
            reloaded.tokens["https://api.example.com"]
                .refresh_token
                .as_deref(),
            Some("r2")
        );
        assert_eq!(
            reloaded.clients["https://new-server.example.com"].client_id,
            "newly-registered"
        );
    }

    #[test]
    fn test_inline_substitutes_env_vars() {
        // Parity with MCP_SERVERS_CONFIG: ${VAR} placeholders inside inline
        // auth content must be expanded against the surrounding environment,
        // so secrets can be split across multiple Secret keys.
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();

        std::env::set_var("MCP_TEST_AUTH_TOKEN", "tok_from_env");
        std::env::set_var("MCP_TEST_AUTH_REFRESH", "ref_from_env");
        std::env::set_var(
            AUTH_CONFIG_ENV,
            r#"{
                "clients": {},
                "tokens": {
                    "https://api.example.com": {
                        "access_token": "${MCP_TEST_AUTH_TOKEN}",
                        "refresh_token": "${MCP_TEST_AUTH_REFRESH}"
                    }
                }
            }"#,
        );
        std::env::remove_var(AUTH_PATH_ENV);

        let store = load_auth_store().unwrap();
        let toks = &store.tokens["https://api.example.com"];
        assert_eq!(toks.access_token, "tok_from_env");
        assert_eq!(toks.refresh_token.as_deref(), Some("ref_from_env"));

        std::env::remove_var("MCP_TEST_AUTH_TOKEN");
        std::env::remove_var("MCP_TEST_AUTH_REFRESH");
    }

    #[test]
    fn test_inline_invalid_json_returns_default_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();

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
        reset_inline_cache();

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
        reset_inline_cache();

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
