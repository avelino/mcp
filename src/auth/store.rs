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
pub(crate) const AUTH_CONFIG_ENV: &str = "MCP_AUTH_CONFIG";

/// File path override for `auth.json`. Lower precedence than `MCP_AUTH_CONFIG`.
pub(crate) const AUTH_PATH_ENV: &str = "MCP_AUTH_PATH";

/// On-disk schema version of the auth store.
///
/// v1 (SEP-2352) keys `clients` by the authorization server's `issuer`
/// identifier. v0 — any store missing the `version` field, i.e. everything
/// written before this change — keyed it by MCP server URL. We cannot know
/// which issuer minted those entries, so migration parks them in
/// `legacy_clients` and `AuthStore::client_for` adopts each one the next
/// time its server is authenticated. Nobody is forced to re-register.
const AUTH_STORE_VERSION: u32 = 1;

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
    migrate(serde_json::from_str(&expanded).unwrap_or_default())
}

/// Bring a store read from disk or env up to the current schema.
///
/// SEP-2352 requires client registrations to be bound to the issuer that
/// minted them. A v0 store recorded no issuer at all, so the safe move is
/// to demote its `clients` map to `legacy_clients` rather than guess an
/// issuer for it. Lookups still find those entries by MCP server URL, so
/// an existing store keeps authenticating exactly as before.
fn migrate(mut store: AuthStore) -> AuthStore {
    if store.version < AUTH_STORE_VERSION {
        let legacy = std::mem::take(&mut store.clients);
        store.legacy_clients.extend(legacy);
        store.version = AUTH_STORE_VERSION;
    }
    store
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
    /// Schema version. `0` when the field is absent — a pre-SEP-2352 store.
    #[serde(default)]
    pub version: u32,
    /// Client registrations keyed by authorization-server `issuer`
    /// identifier (SEP-2352). Never keyed by MCP server URL: the same
    /// credential must not follow the resource server to a new AS.
    #[serde(default)]
    pub clients: HashMap<String, ClientRegistration>,
    /// Pre-SEP-2352 registrations, keyed by MCP server URL. Only ever
    /// populated by `migrate`; drained entry by entry as each server is
    /// re-authenticated. New registrations never land here.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub legacy_clients: HashMap<String, ClientRegistration>,
    /// Tokens stay keyed by MCP server URL — they are scoped to the
    /// resource server, not to the issuer. SEP-2352 only moves the client
    /// *registration*.
    #[serde(default)]
    pub tokens: HashMap<String, StoredTokens>,
}

impl AuthStore {
    /// Client registration to use with `issuer` when talking to the MCP
    /// server identified by `server_key`.
    ///
    /// The issuer-keyed map is authoritative. The fallback only ever
    /// returns the entry a pre-SEP-2352 build wrote for *this same* MCP
    /// server — never one belonging to another server, and never an
    /// issuer-keyed entry, because migration moved legacy data into its
    /// own map instead of leaving both key shapes in one namespace.
    pub fn client_for(&self, issuer: &str, server_key: &str) -> Option<&ClientRegistration> {
        self.clients
            .get(&issuer_key(issuer))
            .or_else(|| self.legacy_clients.get(server_key))
    }

    /// Record a registration under its issuer, retiring any legacy
    /// server-URL-keyed entry for the same MCP server so the credential
    /// stops being reachable by a key that ignores which AS minted it.
    pub fn set_client(&mut self, issuer: &str, server_key: &str, reg: ClientRegistration) {
        self.legacy_clients.remove(server_key);
        self.clients.insert(issuer_key(issuer), reg);
    }
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
        return Ok(migrate(AuthStore::default()));
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(migrate(serde_json::from_str(&content).unwrap_or_default()))
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

/// Normalized key for an authorization-server `issuer` identifier.
///
/// MCP 2026-07-28 constrains credential storage only to "keyed by the
/// authorization server's `issuer` identifier", with no comparison rule
/// attached, so this key absorbs a trailing slash — the one difference the
/// same AS routinely spells both ways across its metadata document and its
/// protected-resource metadata, and the one an auth.json written by an
/// earlier build may already carry. Everything else — scheme, case, port,
/// path, percent-encoding, unicode — is significant, so a difference means a
/// *different* AS and the credential must not be reused (SEP-2352).
///
/// This is NOT the rule for the RFC 9207 `iss` authorization-response
/// parameter: that one is byte-exact and normalizes nothing. See
/// `super::oauth::issuer_matches`.
pub fn issuer_key(issuer: &str) -> String {
    issuer.trim_end_matches('/').to_string()
}

/// Serializes tests that mutate the auth-store env vars. Module-level rather
/// than test-local because `super::oauth`'s tests drive the same globals.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Snapshot env vars touched by these tests, restore on drop.
/// Prevents cross-test pollution when running in parallel — even with
/// `ENV_LOCK`, a panicking test would leak its env state otherwise.
#[cfg(test)]
pub(crate) struct EnvGuard {
    config: Option<String>,
    path: Option<String>,
}

#[cfg(test)]
impl EnvGuard {
    /// Capture the current env and clear the inline cache, so the test
    /// starts from the state of a fresh process.
    pub(crate) fn capture() -> Self {
        let guard = Self {
            config: std::env::var(AUTH_CONFIG_ENV).ok(),
            path: std::env::var(AUTH_PATH_ENV).ok(),
        };
        *inline_cache().write().unwrap() = None;
        guard
    }
}

#[cfg(test)]
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

    // --- SEP-2352: client registrations keyed by issuer ---

    fn reg(id: &str) -> ClientRegistration {
        ClientRegistration {
            client_id: id.to_string(),
            client_secret: None,
        }
    }

    /// A store as written by the current build: issuer-keyed, v1.
    fn issuer_keyed(issuer: &str, client_id: &str) -> AuthStore {
        let mut s = migrate(AuthStore::default());
        s.set_client(issuer, "https://mcp.example.com", reg(client_id));
        s
    }

    #[test]
    fn test_issuer_key_absorbs_trailing_slash() {
        assert_eq!(
            issuer_key("https://as.example.com/"),
            "https://as.example.com"
        );
        assert_eq!(
            issuer_key("https://as.example.com"),
            "https://as.example.com"
        );
    }

    #[test]
    fn test_issuer_key_keeps_everything_else_significant() {
        // Anything but a trailing slash identifies a *different* AS.
        // Collapsing any of these would let one AS's credential be used
        // with another — exactly what SEP-2352 forbids.
        assert_ne!(
            issuer_key("https://as.example.com"),
            issuer_key("http://as.example.com")
        );
        assert_ne!(
            issuer_key("https://as.example.com"),
            issuer_key("https://AS.example.com")
        );
        assert_ne!(
            issuer_key("https://as.example.com"),
            issuer_key("https://as.example.com/tenant")
        );
        assert_ne!(
            issuer_key("https://as.example.com"),
            issuer_key(" https://as.example.com")
        );
        // Cyrillic "а" — visually identical, different AS.
        assert_ne!(
            issuer_key("https://as.example.com"),
            issuer_key("https://аs.example.com")
        );
        assert_ne!(
            issuer_key("https://as.example.com"),
            issuer_key("https://as.example.com.evil.test")
        );
    }

    #[test]
    fn test_client_for_returns_registration_of_its_own_issuer() {
        let store = issuer_keyed("https://as-a.example.com", "cid-a");
        assert_eq!(
            store
                .client_for("https://as-a.example.com", "https://mcp.example.com")
                .unwrap()
                .client_id,
            "cid-a"
        );
    }

    #[test]
    fn test_client_for_never_reuses_credentials_across_issuers() {
        // The core SEP-2352 guarantee: AS-A's client_id must never be
        // handed to AS-B, even for the very same MCP server.
        let store = issuer_keyed("https://as-a.example.com", "cid-a");
        assert!(store
            .client_for("https://as-b.example.com", "https://mcp.example.com")
            .is_none());
    }

    #[test]
    fn test_client_for_rejects_case_and_scheme_variants_of_the_issuer() {
        let store = issuer_keyed("https://as-a.example.com", "cid-a");
        for impostor in [
            "https://AS-A.example.com",           // host case folding
            "HTTPS://as-a.example.com",           // scheme case folding
            "http://as-a.example.com",            // downgraded scheme
            "https://as-a.example.com:443",       // default-port elision
            "https://as-a.example%2Ecom",         // percent-encoding
            "https://as-а.example.com",           // cyrillic homoglyph
            "https://as-a.exämple.com",           // unicode host
            "https://as-a.example.com/tenant",    // extra path
            "https://as-a.example.com.evil.test", // suffix
            " https://as-a.example.com",          // leading whitespace
            "",
        ] {
            assert!(
                store
                    .client_for(impostor, "https://mcp.example.com")
                    .is_none(),
                "issuer {impostor:?} must not match the recorded registration"
            );
        }
    }

    #[test]
    fn test_client_for_absorbs_only_a_trailing_slash_on_the_issuer() {
        // Deliberate, and deliberately different from the RFC 9207 `iss`
        // comparison in `oauth::issuer_matches`. The spec's storage rule is
        // "MUST associate those credentials with the specific authorization
        // server that issued them, keyed by the authorization server's
        // `issuer` identifier" — it names no comparison algorithm. The
        // MUST-NOT-normalize rule is scoped to the authorization *response*:
        // "After decoding the `iss` value from the
        // application/x-www-form-urlencoded response ... before comparison".
        //
        // Absorbing the slash here costs nothing: both spellings are the
        // same origin, which `validated_issuer` has already proved served
        // the metadata document. It buys a credential written by an earlier
        // build under either spelling still resolving instead of forcing a
        // silent re-registration.
        for recorded in ["https://as-a.example.com", "https://as-a.example.com/"] {
            let store = issuer_keyed(recorded, "cid-a");
            for lookup in ["https://as-a.example.com", "https://as-a.example.com/"] {
                assert_eq!(
                    store
                        .client_for(lookup, "https://mcp.example.com")
                        .unwrap_or_else(|| panic!("{lookup:?} must resolve against {recorded:?}"))
                        .client_id,
                    "cid-a"
                );
            }
        }
    }

    #[test]
    fn test_issuer_keyed_entry_is_not_reachable_as_a_server_key() {
        // Without the v0/v1 split an issuer key and a server key would
        // share one namespace: authenticating to MCP server
        // `https://as-a.example.com` (whose AS is somewhere else) would
        // pick up AS-A's credential. The separate legacy map prevents it.
        let store = issuer_keyed("https://as-a.example.com", "cid-a");
        assert!(store
            .client_for("https://as-b.example.com", "https://as-a.example.com")
            .is_none());
    }

    #[test]
    fn test_migrate_moves_legacy_clients_out_of_the_issuer_map() {
        let legacy: AuthStore = serde_json::from_str(
            r#"{"clients":{"https://mcp.example.com":{"client_id":"cid-legacy"}},"tokens":{}}"#,
        )
        .unwrap();
        assert_eq!(legacy.version, 0);

        let migrated = migrate(legacy);
        assert_eq!(migrated.version, AUTH_STORE_VERSION);
        assert!(migrated.clients.is_empty());
        assert_eq!(
            migrated.legacy_clients["https://mcp.example.com"].client_id,
            "cid-legacy"
        );
    }

    #[test]
    fn test_legacy_store_still_authenticates_its_own_server() {
        // Backwards compat: users have auth.json on disk today. Reading it
        // must keep returning the credential, whatever issuer discovery
        // reports now — no silent re-registration.
        let migrated = migrate(
            serde_json::from_str(
                r#"{"clients":{"https://mcp.example.com":{"client_id":"cid-legacy"}},"tokens":{}}"#,
            )
            .unwrap(),
        );
        assert_eq!(
            migrated
                .client_for("https://as-a.example.com", "https://mcp.example.com")
                .unwrap()
                .client_id,
            "cid-legacy"
        );
    }

    #[test]
    fn test_legacy_fallback_does_not_leak_between_servers() {
        // The legacy map is keyed by MCP server URL — server B must never
        // receive server A's credential just because both predate SEP-2352.
        let migrated = migrate(
            serde_json::from_str(
                r#"{"clients":{"https://a.example.com":{"client_id":"cid-a"}},"tokens":{}}"#,
            )
            .unwrap(),
        );
        assert!(migrated
            .client_for("https://as.example.com", "https://b.example.com")
            .is_none());
    }

    #[test]
    fn test_migrate_is_idempotent_on_a_v1_store() {
        let store = issuer_keyed("https://as-a.example.com", "cid-a");
        let again = migrate(store.clone());
        assert_eq!(
            again.clients["https://as-a.example.com"].client_id,
            store.clients["https://as-a.example.com"].client_id
        );
        assert!(again.legacy_clients.is_empty());
    }

    #[test]
    fn test_set_client_retires_the_legacy_entry() {
        let mut store = migrate(
            serde_json::from_str(
                r#"{"clients":{"https://mcp.example.com":{"client_id":"cid-legacy"}},"tokens":{}}"#,
            )
            .unwrap(),
        );
        store.set_client(
            "https://as-a.example.com",
            "https://mcp.example.com",
            reg("cid-legacy"),
        );

        assert!(store.legacy_clients.is_empty());
        // Now bound to AS-A, so a switch to AS-B forces re-registration.
        assert!(store
            .client_for("https://as-b.example.com", "https://mcp.example.com")
            .is_none());
    }

    #[test]
    fn test_on_disk_v1_store_still_authenticates_after_the_iss_tightening() {
        // Tightening the RFC 9207 `iss` comparison must not reach the store:
        // an auth.json already on disk keeps resolving, under either
        // spelling of the issuer the metadata document happens to declare
        // on the next run.
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();
        std::env::remove_var(AUTH_CONFIG_ENV);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(
            &path,
            r#"{"version":1,
                "clients":{"https://as-a.example.com":{"client_id":"cid-a"}},
                "tokens":{"https://mcp.example.com":{"access_token":"tok"}}}"#,
        )
        .unwrap();
        std::env::set_var(AUTH_PATH_ENV, path.to_str().unwrap());

        let store = load_auth_store().unwrap();
        for issuer in ["https://as-a.example.com", "https://as-a.example.com/"] {
            assert_eq!(
                store
                    .client_for(issuer, "https://mcp.example.com")
                    .unwrap_or_else(|| panic!("issuer {issuer:?} must resolve"))
                    .client_id,
                "cid-a"
            );
        }
        assert_eq!(store.tokens["https://mcp.example.com"].access_token, "tok");
        // Still no leak to a different AS.
        assert!(store
            .client_for("https://as-b.example.com", "https://mcp.example.com")
            .is_none());
    }

    #[test]
    fn test_legacy_store_round_trips_through_disk_as_v1() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        reset_inline_cache();
        std::env::remove_var(AUTH_CONFIG_ENV);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(
            &path,
            r#"{"clients":{"https://mcp.example.com":{"client_id":"cid-legacy"}},
                "tokens":{"https://mcp.example.com":{"access_token":"tok-legacy"}}}"#,
        )
        .unwrap();
        std::env::set_var(AUTH_PATH_ENV, path.to_str().unwrap());

        // Read: legacy credential AND legacy token both still usable.
        let mut store = load_auth_store().unwrap();
        assert_eq!(
            store
                .client_for("https://as-a.example.com", "https://mcp.example.com")
                .unwrap()
                .client_id,
            "cid-legacy"
        );
        assert_eq!(
            store.tokens["https://mcp.example.com"].access_token,
            "tok-legacy"
        );

        // Adopt under the discovered issuer and persist.
        store.set_client(
            "https://as-a.example.com",
            "https://mcp.example.com",
            reg("cid-legacy"),
        );
        save_auth_store(&store).unwrap();

        let reloaded = load_auth_store().unwrap();
        assert_eq!(reloaded.version, AUTH_STORE_VERSION);
        assert!(reloaded.legacy_clients.is_empty());
        assert_eq!(
            reloaded.clients["https://as-a.example.com"].client_id,
            "cid-legacy"
        );
        // Tokens are resource-scoped; SEP-2352 does not touch them.
        assert_eq!(
            reloaded.tokens["https://mcp.example.com"].access_token,
            "tok-legacy"
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
        // Inline content carries no `version`, so it is a v0 store: the
        // registration lands in the legacy map and stays reachable by
        // MCP server URL.
        assert_eq!(
            store
                .client_for("https://as.example.com", "https://example.com")
                .unwrap()
                .client_id,
            "cid_inline"
        );
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
        assert_eq!(
            store.legacy_clients["https://file.com"].client_id,
            "cid_file"
        );
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
        assert!(store.legacy_clients.contains_key("https://inline.com"));
        assert!(!store.legacy_clients.contains_key("https://file.com"));
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
