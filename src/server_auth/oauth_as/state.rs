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

/// Hard cap on remembered `jti`, for the same reason as
/// [`MAX_REGISTERED_CLIENTS`]: a map that grows with request traffic and is
/// reclaimed only by time needs a ceiling.
///
/// Reaching it takes valid assertions, not anonymous requests — the `jti`
/// is remembered last, after every signature and time check. The size is
/// still generous, because an entry lives until the assertion's own `exp`
/// and the validator accepts one up to an hour out: the steady state is an
/// hour of exchanges, not a minute of them. On the order of 10 MB of keys
/// at the cap, which is enough headroom that reaching it means a flood
/// rather than a workload.
pub const MAX_SEEN_JTI: usize = 100_000;

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
    /// In-memory only: clients declared in config. Kept apart from
    /// `clients` so removing one from config never leaves an orphan on disk.
    static_clients: HashMap<String, RegisteredClient>,
    /// In-memory only: `(issuer, jti)` of assertions already redeemed, with
    /// their expiry.
    ///
    /// A restart therefore reopens replay for every assertion still inside
    /// its own `exp` — under a minute for Claude's, up to an hour for
    /// whatever the validator's ceiling allows. That window is only this
    /// short if the deployment runs **one** replica and replaces it with
    /// `strategy: Recreate`: two replicas, or a rolling update, and the two
    /// processes never share the map at all. That is a precondition on the
    /// deploy, not something the code enforces — `deploy/kubernetes/`
    /// ships `Recreate` commented out, offered there for the PVC rather
    /// than for this.
    ///
    /// Namespaced by issuer because RFC 7519 §4.1.7 only promises a `jti` is
    /// unique per issuer: shared, two trusted IdPs that happen to pick the
    /// same one would lock out each other's users.
    seen_jti: HashMap<(String, String), u64>,
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
                static_clients: HashMap::new(),
                seen_jti: HashMap::new(),
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

    /// Replace the configured clients wholesale, so a reload drops the
    /// ones removed from config.
    pub fn set_static_clients(&self, clients: Vec<RegisteredClient>) {
        self.inner.write().unwrap().static_clients = clients
            .into_iter()
            .map(|c| (c.client_id.clone(), c))
            .collect();
    }

    /// DCR clients win over configured ones with the same id.
    pub fn get_client(&self, client_id: &str) -> Option<RegisteredClient> {
        let g = self.inner.read().unwrap();
        g.clients
            .get(client_id)
            .or_else(|| g.static_clients.get(client_id))
            .cloned()
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

    // ---- assertion replay --------------------------------------------------

    /// Record a `jti` as used within `issuer`'s namespace. Errors when that
    /// pair was already seen and has not yet expired.
    ///
    /// `issuer` must come from the trusted entry resolved off the *signed*
    /// payload: taken from an unverified claim it would let a caller choose
    /// which namespace to burn, and replay a real assertion under another.
    ///
    /// Test-and-set under one write guard. Split into a read then a write,
    /// two concurrent redemptions of the same assertion both see it unused.
    pub fn remember_jti(
        &self,
        issuer: &str,
        jti: &str,
        expires_at_unix: u64,
    ) -> std::result::Result<(), JtiRefusal> {
        let key = (issuer.to_string(), jti.to_string());
        let mut g = self.inner.write().unwrap();
        if g.seen_jti.get(&key).is_some_and(|exp| *exp > now_unix()) {
            return Err(JtiRefusal::AlreadyUsed);
        }
        // Checked after the replay check, so the cap can never be the reason
        // a replay gets through: a key already in the map takes the branch
        // above or overwrites its own expired entry, and only a genuinely
        // new one can be refused here.
        if g.seen_jti.len() >= MAX_SEEN_JTI && !g.seen_jti.contains_key(&key) {
            // Swept here rather than left to the GC pass: an entry is dead
            // weight the moment its assertion expires, and waiting for the
            // next tick would refuse valid exchanges for up to a minute
            // after a burst had logically drained. Still the one guard, so
            // the test-and-set above stays atomic.
            //
            // O(n), and a sustained flood of *live* entries pays it on
            // every refused request. That is the trade: the alternative
            // spends the same time turning away exchanges that should have
            // been let through.
            let cutoff = now_unix();
            g.seen_jti.retain(|_, exp| *exp > cutoff);
            if g.seen_jti.len() >= MAX_SEEN_JTI {
                return Err(JtiRefusal::CacheFull);
            }
        }
        g.seen_jti.insert(key, expires_at_unix);
        Ok(())
    }

    // ---- garbage collection ------------------------------------------------

    /// Remove expired codes, refresh tokens and seen `jti`.
    ///
    /// The two counts are reported apart because only one of them is a
    /// reason to write to disk: codes and seen `jti` never reach
    /// [`PersistedState`], so saving after one of those expires rewrites
    /// the file with identical bytes.
    pub fn gc_expired(&self) -> GcReport {
        let cutoff = now_unix();
        let mut g = self.inner.write().unwrap();
        let before_codes = g.codes.len();
        g.codes.retain(|_, c| c.expires_at_unix > cutoff);
        let before_refresh = g.refresh_tokens.len();
        g.refresh_tokens.retain(|_, t| t.expires_at_unix > cutoff);
        let before_jti = g.seen_jti.len();
        g.seen_jti.retain(|_, exp| *exp > cutoff);
        GcReport {
            persisted: before_refresh - g.refresh_tokens.len(),
            in_memory: (before_codes - g.codes.len()) + (before_jti - g.seen_jti.len()),
            seen_jti: g.seen_jti.len(),
        }
    }
}

/// Why [`AsState::remember_jti`] turned an assertion away.
///
/// Two variants rather than one message, because the two mean opposite
/// things to whoever is on call. A replayed `jti` is ordinary client
/// behaviour — a `/token` POST retried after a timeout presents the same
/// assertion twice — while a full cache is the one an operator has to act
/// on. The caller logs them at different levels, and picking the level by
/// matching on a message would break the next time someone rewords one.
///
/// It stays out of the client's view either way: both become the same
/// refusal string, or the wording is an oracle for the cache's state.
#[derive(Debug, PartialEq, Eq)]
pub enum JtiRefusal {
    /// This `(issuer, jti)` was redeemed already and has not yet expired.
    AlreadyUsed,
    /// The cache holds [`MAX_SEEN_JTI`] live entries, with nothing expired
    /// left to reclaim.
    CacheFull,
}

impl std::fmt::Display for JtiRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyUsed => f.write_str("assertion jti already used"),
            Self::CacheFull => write!(
                f,
                "assertion replay cache is full ({MAX_SEEN_JTI}); refusing the exchange"
            ),
        }
    }
}

/// What a [`AsState::gc_expired`] pass dropped.
pub struct GcReport {
    /// Entries that were on disk. Non-zero means the persisted state is
    /// now stale and the caller should save.
    pub persisted: usize,
    /// Entries that only ever lived in memory. Never a reason to save.
    pub in_memory: usize,
    /// `jti` still remembered once the pass finished — a level, not a
    /// removal count. Reported so the GC tick can warn as [`MAX_SEEN_JTI`]
    /// is approached rather than only once exchanges are being refused;
    /// how far ahead of the refusals such a warning lands depends on the
    /// ramp, which the tick works through at its own call site.
    pub seen_jti: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://idp.example.com";

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
        assert_eq!(removed.in_memory, 1);
        assert!(s.consume_code("alive").is_some());
    }

    #[test]
    fn test_gc_only_reports_persisted_removals_as_persisted() {
        // The caller saves when `persisted` is non-zero, and the saved
        // file holds neither codes nor `jti`. Counting those would make a
        // GC tick rewrite the PVC with identical bytes once a minute for
        // as long as assertions keep arriving.
        let s = AsState::default();
        let mut dead_code = make_code("dead", 60);
        dead_code.expires_at_unix = 0;
        s.put_code(dead_code);
        s.remember_jti(ISSUER, "dead-jti", 0).unwrap();
        let mut dead_refresh = make_refresh("dead-rt", "client-A", 3600);
        dead_refresh.expires_at_unix = 0;
        s.put_refresh(dead_refresh);

        let removed = s.gc_expired();
        assert_eq!(removed.persisted, 1);
        assert_eq!(removed.in_memory, 2);
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

    #[test]
    fn test_static_clients_are_visible_to_get_client() {
        let s = AsState::default();
        s.set_static_clients(vec![make_client("ema-client")]);
        assert_eq!(s.get_client("ema-client").unwrap().client_id, "ema-client");
    }

    #[test]
    fn test_static_clients_never_reach_the_persisted_snapshot() {
        // A client removed from config must not leave an orphan on the PVC.
        let s = AsState::default();
        s.set_static_clients(vec![make_client("ema-client")]);
        assert!(!s.snapshot_persisted().clients.contains_key("ema-client"));
    }

    #[test]
    fn test_dcr_client_wins_over_static_with_same_id() {
        let s = AsState::default();
        let mut dcr = make_client("shared");
        dcr.client_name = Some("from-dcr".to_string());
        s.register_client(dcr).unwrap();
        let mut fixed = make_client("shared");
        fixed.client_name = Some("from-config".to_string());
        s.set_static_clients(vec![fixed]);
        assert_eq!(
            s.get_client("shared").unwrap().client_name.as_deref(),
            Some("from-dcr")
        );
    }

    #[test]
    fn test_set_static_clients_replaces_previous_set() {
        // Reload must drop clients that were removed from config.
        let s = AsState::default();
        s.set_static_clients(vec![make_client("old")]);
        s.set_static_clients(vec![make_client("new")]);
        assert!(s.get_client("old").is_none());
        assert!(s.get_client("new").is_some());
    }

    #[test]
    fn test_remember_jti_rejects_the_second_use() {
        let s = AsState::default();
        let exp = now_unix() + 60;
        assert!(s.remember_jti(ISSUER, "jti-1", exp).is_ok());
        assert!(s.remember_jti(ISSUER, "jti-1", exp).is_err());
        assert!(s.remember_jti(ISSUER, "jti-2", exp).is_ok());
        // Another issuer's namespace is untouched by either of those.
        assert!(s
            .remember_jti("https://other.example.com", "jti-1", exp)
            .is_ok());
    }

    #[test]
    fn test_expired_jti_is_collected() {
        let s = AsState::default();
        s.remember_jti(ISSUER, "old", 0).unwrap();
        assert_eq!(s.gc_expired().in_memory, 1);
        assert!(s.remember_jti(ISSUER, "old", now_unix() + 60).is_ok());
    }

    #[test]
    fn test_live_jti_survives_gc() {
        let s = AsState::default();
        s.remember_jti(ISSUER, "live", now_unix() + 60).unwrap();
        assert_eq!(s.gc_expired().in_memory, 0);
        assert!(s.remember_jti(ISSUER, "live", now_unix() + 60).is_err());
    }

    #[test]
    fn test_seen_jti_refuses_past_the_cap() {
        // The same trade `register_client` makes: a refused exchange beats a
        // map that grows until the process dies.
        let s = AsState::default();
        let exp = now_unix() + 60;
        for i in 0..MAX_SEEN_JTI {
            s.remember_jti(ISSUER, &format!("jti-{i}"), exp).unwrap();
        }
        // The variant, not just that it refused: the call site picks a log
        // level off it, so which one it is *is* the behaviour.
        assert_eq!(
            s.remember_jti(ISSUER, "one-too-many", exp),
            Err(JtiRefusal::CacheFull)
        );
        // And a `jti` already in the map is still refused as a replay, not
        // as a full cache — the cap must not become a way to get one past,
        // and an ordinary replay must not be what wakes an operator.
        assert_eq!(
            s.remember_jti(ISSUER, "jti-0", exp),
            Err(JtiRefusal::AlreadyUsed)
        );
    }

    #[test]
    fn test_gc_frees_room_in_the_jti_cache() {
        // The cap is a ceiling on live entries, not a lifetime budget. A
        // map full of expired entries must not refuse an exchange at all —
        // not even for the up to 60s until the next GC pass — so the cap
        // branch sweeps before it refuses.
        let s = AsState::default();
        for i in 0..MAX_SEEN_JTI {
            s.remember_jti(ISSUER, &format!("jti-{i}"), 0).unwrap();
        }
        let exp = now_unix() + 60;
        s.remember_jti(ISSUER, "fresh", exp).unwrap();
        // The room came from dropping the dead entries, not from growing
        // past the cap: one entry left, and the GC pass finds nothing to do.
        let pass = s.gc_expired();
        assert_eq!(pass.seen_jti, 1);
        assert_eq!(pass.in_memory, 0);

        // Live entries are the flood case, and those do close the exchange.
        for i in 0..MAX_SEEN_JTI - 1 {
            s.remember_jti(ISSUER, &format!("live-{i}"), exp).unwrap();
        }
        assert!(s.remember_jti(ISSUER, "one-too-many", exp).is_err());
    }

    #[test]
    fn test_jti_cache_never_reaches_the_persisted_snapshot() {
        // `/data/auth_server.json` lives on a PVC and must keep
        // deserializing across deploys, so the on-disk shape stays exactly
        // what it was before this cache existed.
        let s = AsState::default();
        s.remember_jti(ISSUER, "burned-jti", now_unix() + 60)
            .unwrap();
        let on_disk = serde_json::to_string(&s.snapshot_persisted()).unwrap();
        assert!(!on_disk.contains("burned-jti"), "leaked into {on_disk}");
    }
}
