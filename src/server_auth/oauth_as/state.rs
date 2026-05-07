//! Runtime state for the OAuth AS — registered clients (persisted),
//! authorization codes (in-memory only), and refresh tokens (persisted).
//!
//! All mutation goes through `&self` plus interior mutability so the
//! state can be shared via `Arc<AsState>` across axum handlers without
//! a per-request lock dance. Persistence is opt-in: handlers call
//! [`AsState::persist_with`] after mutations that should survive a
//! restart.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};

use super::types::{AuthorizationCode, IssuedRefreshToken, RegisteredClient};

/// Hard cap on registered clients to keep `/register` from filling
/// disk via DCR amplification. Operators that legitimately exceed
/// this should be rotating clients out, not raising the cap.
pub const MAX_REGISTERED_CLIENTS: usize = 1000;

#[derive(Default)]
pub struct AsState {
    inner: RwLock<AsStateInner>,
}

#[derive(Default)]
struct AsStateInner {
    /// Persisted: clients registered via DCR. Survives restart.
    clients: HashMap<String, RegisteredClient>,
    /// In-memory only: short-lived authorization codes (TTL ~60s).
    codes: HashMap<String, AuthorizationCode>,
    /// Persisted: refresh tokens (TTL ~30d).
    refresh_tokens: HashMap<String, IssuedRefreshToken>,
}

/// Snapshot view used by the persistent store.
#[derive(Default, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub clients: HashMap<String, RegisteredClient>,
    #[serde(default)]
    pub refresh_tokens: HashMap<String, IssuedRefreshToken>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl AsState {
    pub fn from_persisted(p: PersistedState) -> Self {
        Self {
            inner: RwLock::new(AsStateInner {
                clients: p.clients,
                refresh_tokens: p.refresh_tokens,
                codes: HashMap::new(),
            }),
        }
    }

    /// Snapshot the persisted parts of the state — clients and refresh
    /// tokens. Codes are never persisted by design.
    pub fn snapshot_persisted(&self) -> PersistedState {
        let g = self.inner.read().unwrap();
        PersistedState {
            clients: g.clients.clone(),
            refresh_tokens: g.refresh_tokens.clone(),
        }
    }

    // ---- clients (DCR) -----------------------------------------------------

    pub fn register_client(&self, client: RegisteredClient) -> Result<()> {
        let mut g = self.inner.write().unwrap();
        if g.clients.len() >= MAX_REGISTERED_CLIENTS && !g.clients.contains_key(&client.client_id) {
            bail!(
                "registered client limit reached ({}); refusing new registrations",
                MAX_REGISTERED_CLIENTS
            );
        }
        g.clients.insert(client.client_id.clone(), client);
        Ok(())
    }

    pub fn get_client(&self, client_id: &str) -> Option<RegisteredClient> {
        self.inner.read().unwrap().clients.get(client_id).cloned()
    }

    // ---- authorization codes (one-shot, in-memory) -------------------------

    pub fn put_code(&self, code: AuthorizationCode) {
        self.inner
            .write()
            .unwrap()
            .codes
            .insert(code.code.clone(), code);
    }

    /// Consume a code — single-use, removes it from state. Returns
    /// `None` if the code is unknown, already used, or expired.
    pub fn consume_code(&self, code: &str) -> Option<AuthorizationCode> {
        let mut g = self.inner.write().unwrap();
        let entry = g.codes.remove(code)?;
        if entry.expires_at_unix <= now_unix() {
            // Expired — drop it without returning.
            return None;
        }
        Some(entry)
    }

    // ---- refresh tokens ----------------------------------------------------

    pub fn put_refresh(&self, token: IssuedRefreshToken) {
        self.inner
            .write()
            .unwrap()
            .refresh_tokens
            .insert(token.token.clone(), token);
    }

    /// Atomically consume the old refresh token and replace it with a
    /// new one (rotation). Returns the consumed entry on success.
    /// Refusal modes: unknown token, expired token, `client_id`
    /// mismatch (cross-client replay attempt).
    pub fn rotate_refresh(
        &self,
        old_token: &str,
        client_id: &str,
        new: IssuedRefreshToken,
    ) -> Result<IssuedRefreshToken> {
        let mut g = self.inner.write().unwrap();
        let prev = match g.refresh_tokens.remove(old_token) {
            Some(p) => p,
            None => bail!("unknown refresh token"),
        };
        if prev.expires_at_unix <= now_unix() {
            bail!("refresh token expired");
        }
        if prev.client_id != client_id {
            // Privilege escalation guard: the token does not belong to
            // the client presenting it.
            bail!("refresh token does not match client_id");
        }
        g.refresh_tokens.insert(new.token.clone(), new);
        Ok(prev)
    }

    // ---- garbage collection ------------------------------------------------

    /// Remove expired codes and refresh tokens. Returns the number of
    /// entries removed total. Caller is responsible for triggering
    /// persistence afterward when a refresh-token entry was dropped.
    pub fn gc_expired(&self) -> usize {
        let cutoff = now_unix();
        let mut g = self.inner.write().unwrap();
        let before_codes = g.codes.len();
        g.codes.retain(|_, c| c.expires_at_unix > cutoff);
        let before_refresh = g.refresh_tokens.len();
        g.refresh_tokens.retain(|_, t| t.expires_at_unix > cutoff);
        (before_codes - g.codes.len()) + (before_refresh - g.refresh_tokens.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client(id: &str) -> RegisteredClient {
        RegisteredClient {
            client_id: id.to_string(),
            client_name: Some("test".to_string()),
            redirect_uris: vec!["https://example.com/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            created_at_unix: now_unix(),
        }
    }

    fn make_code(code: &str, ttl_s: u64) -> AuthorizationCode {
        AuthorizationCode {
            code: code.to_string(),
            client_id: "client-A".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            code_challenge: "challenge".to_string(),
            scope: None,
            subject: "alice".to_string(),
            roles: vec![],
            expires_at_unix: now_unix() + ttl_s,
        }
    }

    fn make_refresh(token: &str, client_id: &str, ttl_s: u64) -> IssuedRefreshToken {
        IssuedRefreshToken {
            token: token.to_string(),
            client_id: client_id.to_string(),
            subject: "alice".to_string(),
            roles: vec![],
            expires_at_unix: now_unix() + ttl_s,
        }
    }

    #[test]
    fn test_register_then_get_client() {
        let s = AsState::default();
        s.register_client(make_client("c1")).unwrap();
        assert_eq!(s.get_client("c1").unwrap().client_id, "c1");
    }

    #[test]
    fn test_client_limit_blocks_new_but_allows_overwrite() {
        let s = AsState::default();
        for i in 0..MAX_REGISTERED_CLIENTS {
            s.register_client(make_client(&format!("c{i}"))).unwrap();
        }
        // Overwriting an existing client must still succeed (DCR
        // allows re-registering with the same id during retries).
        s.register_client(make_client("c0")).unwrap();
        // New ids beyond the cap must fail.
        assert!(s.register_client(make_client("c999999")).is_err());
    }

    #[test]
    fn test_consume_code_is_one_shot() {
        let s = AsState::default();
        s.put_code(make_code("the-code", 60));
        assert!(s.consume_code("the-code").is_some());
        // Replay must fail.
        assert!(s.consume_code("the-code").is_none());
    }

    #[test]
    fn test_consume_expired_code_returns_none() {
        let s = AsState::default();
        let mut c = make_code("stale", 60);
        c.expires_at_unix = 0; // far past
        s.put_code(c);
        assert!(s.consume_code("stale").is_none());
    }

    #[test]
    fn test_rotate_refresh_succeeds_for_matching_client() {
        let s = AsState::default();
        s.put_refresh(make_refresh("old", "client-A", 3600));
        let new = make_refresh("new", "client-A", 3600);
        let prev = s.rotate_refresh("old", "client-A", new).unwrap();
        assert_eq!(prev.client_id, "client-A");
    }

    #[test]
    fn test_rotate_refresh_rejects_cross_client_replay() {
        // Privilege escalation guard: presenting client-A's refresh
        // token under client-B credentials must NOT mint a new token
        // for client-B.
        let s = AsState::default();
        s.put_refresh(make_refresh("old", "client-A", 3600));
        let new = make_refresh("new", "client-B", 3600);
        let err = s.rotate_refresh("old", "client-B", new).unwrap_err();
        assert!(err.to_string().contains("client_id"));
    }

    #[test]
    fn test_rotate_refresh_rejects_expired() {
        let s = AsState::default();
        let mut old = make_refresh("old", "client-A", 3600);
        old.expires_at_unix = 0;
        s.put_refresh(old);
        let new = make_refresh("new", "client-A", 3600);
        assert!(s.rotate_refresh("old", "client-A", new).is_err());
    }

    #[test]
    fn test_rotate_refresh_rejects_unknown_token() {
        let s = AsState::default();
        let new = make_refresh("new", "client-A", 3600);
        assert!(s.rotate_refresh("never-issued", "client-A", new).is_err());
    }

    #[test]
    fn test_gc_drops_expired_only() {
        let s = AsState::default();
        s.put_code(make_code("alive", 60));
        let mut dead = make_code("dead", 60);
        dead.expires_at_unix = 0;
        s.put_code(dead);
        let removed = s.gc_expired();
        assert_eq!(removed, 1);
        assert!(s.consume_code("alive").is_some());
    }

    #[test]
    fn test_snapshot_omits_in_memory_codes() {
        // Codes must NEVER be serialized: a captured snapshot of an
        // ongoing flow on disk would let an attacker resume it.
        let s = AsState::default();
        s.register_client(make_client("c1")).unwrap();
        s.put_code(make_code("the-code", 60));
        s.put_refresh(make_refresh("rt", "c1", 3600));
        let snap = s.snapshot_persisted();
        assert!(snap.clients.contains_key("c1"));
        assert!(snap.refresh_tokens.contains_key("rt"));
        // PersistedState struct doesn't even have a `codes` field —
        // this is enforced at the type level, not just at runtime.
    }
}
