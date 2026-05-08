use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use super::{AuthIdentity, AuthProvider, BearerToken, Credentials};

/// No authentication — always returns anonymous identity.
/// Default for development and stdio mode.
pub struct NoAuth;

#[async_trait]
impl AuthProvider for NoAuth {
    async fn authenticate(&self, _creds: &Credentials) -> Result<AuthIdentity> {
        Ok(AuthIdentity::anonymous())
    }
}

/// Validates static bearer tokens from config.
/// Maps token -> BearerToken (legacy string subject or extended {subject, roles}).
pub struct BearerTokenAuth {
    tokens: HashMap<String, BearerToken>,
}

impl BearerTokenAuth {
    pub fn new(tokens: HashMap<String, BearerToken>) -> Self {
        Self { tokens }
    }
}

#[async_trait]
impl AuthProvider for BearerTokenAuth {
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity> {
        let header = creds
            .get("authorization")
            .ok_or_else(|| anyhow::anyhow!("missing Authorization header"))?;

        // RFC 7235: auth scheme is case-insensitive
        if header.len() < 7 || !header[..7].eq_ignore_ascii_case("bearer ") {
            bail!("Authorization header must use Bearer scheme");
        }
        let token = &header[7..];

        match self.tokens.get(token) {
            Some(BearerToken::Subject(subject)) => Ok(AuthIdentity::new(subject.clone(), vec![])),
            Some(BearerToken::Extended { subject, roles }) => {
                Ok(AuthIdentity::new(subject.clone(), roles.clone()))
            }
            None => bail!("invalid bearer token"),
        }
    }
}

/// Composite provider: tries each inner provider in order and returns
/// the first successful identity. Designed for the case where one
/// `mcp serve` instance must accept *both* static bearer tokens (used
/// by local CLI / dev tools) **and** OAuth-issued JWTs (used by
/// Claude.ai / ChatGPT / Cursor) on the same `/mcp` endpoint.
///
/// Ordering note: providers are tried in array order. Cheaper checks
/// (static map lookup) belong first; HMAC verification belongs last.
/// Ordering is a performance choice, not a correctness one — every
/// configured provider gets a fair shot until one accepts.
///
/// Oracle defense: when *all* providers reject, the chain returns the
/// error of the **first** configured provider, never something
/// derived from which provider got further. Otherwise an attacker
/// could probe the chain to learn which token format is in use.
pub struct ProviderChain {
    providers: Vec<Arc<dyn AuthProvider>>,
}

impl ProviderChain {
    pub fn new(providers: Vec<Arc<dyn AuthProvider>>) -> Self {
        Self { providers }
    }
}

#[async_trait]
impl AuthProvider for ProviderChain {
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity> {
        // Empty chain is equivalent to NoAuth — degenerate but valid.
        if self.providers.is_empty() {
            return NoAuth.authenticate(creds).await;
        }

        let mut first_error: Option<anyhow::Error> = None;
        for (idx, provider) in self.providers.iter().enumerate() {
            match provider.authenticate(creds).await {
                Ok(identity) => {
                    // Debug-only: never log at info level — that would leak
                    // which provider format the request used to anyone with
                    // access to logs.
                    tracing::debug!(provider_index = idx, "auth chain matched provider");
                    return Ok(identity);
                }
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        // Unwrap is safe: providers is non-empty, so at least one error
        // was recorded.
        Err(first_error.unwrap())
    }
}

/// Trusts a reverse proxy header (e.g. X-Forwarded-User).
/// Only use behind a trusted proxy that sets this header.
///
/// Optionally reads a groups header (default `x-forwarded-groups`, oauth2-proxy
/// convention) to populate roles. Value is parsed as a comma-separated list:
/// each entry is trimmed and empty entries are dropped. Missing header yields
/// empty roles (not an error).
pub struct ForwardedUserAuth {
    header: String,
    groups_header: String,
}

impl ForwardedUserAuth {
    pub fn new(header: String, groups_header: String) -> Self {
        Self {
            header: header.to_lowercase(),
            groups_header: groups_header.to_lowercase(),
        }
    }
}

/// Parse a comma-separated groups header into a list of role names.
/// Trims each entry and drops empty ones. Case is preserved (role matching
/// is case-sensitive).
pub(crate) fn parse_groups(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Extract the trusted user identity from request credentials, using
/// the same shape `ForwardedUserAuth` does. Returned `(subject, roles)`
/// is suitable for both per-request authentication (the existing
/// provider) and for OAuth `/authorize` where the AS reads the
/// reverse-proxy-set headers to identify the human before issuing a
/// code.
///
/// Header names are matched case-insensitively (HTTP convention) and
/// roles default to an empty vec when the groups header is absent.
/// Returns `None` when the user header is missing or empty.
pub(crate) fn read_trusted_user(
    creds: &Credentials,
    user_header: &str,
    groups_header: &str,
) -> Option<(String, Vec<String>)> {
    let user = creds.get(&user_header.to_lowercase())?;
    if user.is_empty() {
        return None;
    }
    let roles = creds
        .get(&groups_header.to_lowercase())
        .map(|raw| parse_groups(raw))
        .unwrap_or_default();
    Some((user.clone(), roles))
}

#[async_trait]
impl AuthProvider for ForwardedUserAuth {
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity> {
        match read_trusted_user(creds, &self.header, &self.groups_header) {
            Some((subject, roles)) => Ok(AuthIdentity::new(subject, roles)),
            // Mirror the case-insensitive lookup `read_trusted_user`
            // performs on the header name. The constructor already
            // lowercases `self.header`, but redoing it here keeps the
            // error branch correct even if a future change relaxes
            // that invariant.
            None => match creds.get(&self.header.to_lowercase()) {
                Some(_) => bail!("{} header is empty", self.header),
                None => bail!("missing {} header", self.header),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_no_auth_returns_anonymous() {
        let provider = NoAuth;
        let identity = provider.authenticate(&Credentials::new()).await.unwrap();
        assert_eq!(identity.subject, "anonymous");
        assert!(identity.roles.is_empty());
    }

    #[tokio::test]
    async fn test_bearer_valid_token() {
        let mut tokens = HashMap::new();
        tokens.insert(
            "secret-abc".to_string(),
            BearerToken::Subject("alice".to_string()),
        );
        tokens.insert(
            "secret-def".to_string(),
            BearerToken::Subject("bob".to_string()),
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer secret-abc".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
    }

    #[tokio::test]
    async fn test_bearer_case_insensitive_scheme() {
        let mut tokens = HashMap::new();
        tokens.insert(
            "secret-abc".to_string(),
            BearerToken::Subject("alice".to_string()),
        );
        let provider = BearerTokenAuth::new(tokens);

        for scheme in &["bearer", "BEARER", "Bearer", "bEaReR"] {
            let mut creds = Credentials::new();
            creds.insert("authorization".to_string(), format!("{scheme} secret-abc"));
            let identity = provider.authenticate(&creds).await.unwrap();
            assert_eq!(identity.subject, "alice", "failed for scheme: {scheme}");
        }
    }

    #[tokio::test]
    async fn test_bearer_invalid_token() {
        let mut tokens = HashMap::new();
        tokens.insert(
            "secret-abc".to_string(),
            BearerToken::Subject("alice".to_string()),
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert(
            "authorization".to_string(),
            "Bearer wrong-token".to_string(),
        );
        assert!(provider.authenticate(&creds).await.is_err());
    }

    #[tokio::test]
    async fn test_bearer_missing_header() {
        let provider = BearerTokenAuth::new(HashMap::new());
        assert!(provider.authenticate(&Credentials::new()).await.is_err());
    }

    #[tokio::test]
    async fn test_bearer_wrong_scheme() {
        let provider = BearerTokenAuth::new(HashMap::new());
        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Basic abc123".to_string());
        let err = provider.authenticate(&creds).await.unwrap_err();
        assert!(err.to_string().contains("Bearer scheme"));
    }

    #[tokio::test]
    async fn test_forwarded_valid_user() {
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "charlie".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "charlie");
    }

    #[tokio::test]
    async fn test_forwarded_missing_header() {
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        assert!(provider.authenticate(&Credentials::new()).await.is_err());
    }

    #[tokio::test]
    async fn test_forwarded_empty_header() {
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), String::new());
        assert!(provider.authenticate(&creds).await.is_err());
    }

    #[tokio::test]
    async fn test_forwarded_custom_header() {
        let provider = ForwardedUserAuth::new(
            "X-Remote-User".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-remote-user".to_string(), "dave".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "dave");
    }

    // ---------------------------------------------------------------------
    // Bearer — roles population
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_bearer_legacy_form_has_empty_roles() {
        // Backwards-compat: string form must produce exactly roles=[].
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-alice".to_string(),
            BearerToken::Subject("alice".to_string()),
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer tok-alice".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
        assert!(
            identity.roles.is_empty(),
            "legacy form must never populate roles"
        );
    }

    #[tokio::test]
    async fn test_bearer_extended_form_populates_roles() {
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-bob".to_string(),
            BearerToken::Extended {
                subject: "bob".to_string(),
                roles: vec!["dev".to_string(), "oncall".to_string()],
            },
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer tok-bob".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "bob");
        assert_eq!(
            identity.roles,
            vec!["dev".to_string(), "oncall".to_string()]
        );
    }

    #[tokio::test]
    async fn test_bearer_extended_form_with_empty_roles() {
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-carol".to_string(),
            BearerToken::Extended {
                subject: "carol".to_string(),
                roles: vec![],
            },
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer tok-carol".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "carol");
        assert!(identity.roles.is_empty());
    }

    #[tokio::test]
    async fn test_bearer_mixed_forms_coexist() {
        // Legacy and extended tokens in the same provider must both work.
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-legacy".to_string(),
            BearerToken::Subject("alice".to_string()),
        );
        tokens.insert(
            "tok-ext".to_string(),
            BearerToken::Extended {
                subject: "bob".to_string(),
                roles: vec!["admin".to_string()],
            },
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut c1 = Credentials::new();
        c1.insert("authorization".to_string(), "Bearer tok-legacy".to_string());
        let id1 = provider.authenticate(&c1).await.unwrap();
        assert_eq!(id1.subject, "alice");
        assert!(id1.roles.is_empty());

        let mut c2 = Credentials::new();
        c2.insert("authorization".to_string(), "Bearer tok-ext".to_string());
        let id2 = provider.authenticate(&c2).await.unwrap();
        assert_eq!(id2.subject, "bob");
        assert_eq!(id2.roles, vec!["admin".to_string()]);
    }

    #[tokio::test]
    async fn test_bearer_roles_do_not_leak_between_tokens() {
        // Privilege escalation guard: authenticating with a legacy token must
        // never return roles from a different extended token in the map.
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-admin".to_string(),
            BearerToken::Extended {
                subject: "admin".to_string(),
                roles: vec!["admin".to_string(), "superuser".to_string()],
            },
        );
        tokens.insert(
            "tok-guest".to_string(),
            BearerToken::Subject("guest".to_string()),
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer tok-guest".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "guest");
        assert!(
            identity.roles.is_empty(),
            "guest must never inherit admin roles"
        );
        assert!(!identity.roles.contains(&"admin".to_string()));
        assert!(!identity.roles.contains(&"superuser".to_string()));
    }

    #[tokio::test]
    async fn test_bearer_invalid_token_with_extended_tokens_present() {
        // Bypass guard: invalid token must fail even when extended tokens exist.
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-real".to_string(),
            BearerToken::Extended {
                subject: "alice".to_string(),
                roles: vec!["admin".to_string()],
            },
        );
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer tok-fake".to_string());
        assert!(provider.authenticate(&creds).await.is_err());
    }

    // ---------------------------------------------------------------------
    // Forwarded — groups header parsing
    // ---------------------------------------------------------------------

    #[test]
    fn test_parse_groups_basic() {
        assert_eq!(parse_groups("dev,oncall"), vec!["dev", "oncall"]);
    }

    #[test]
    fn test_parse_groups_trims_whitespace() {
        assert_eq!(
            parse_groups(" dev , oncall ,  admin"),
            vec!["dev", "oncall", "admin"]
        );
    }

    #[test]
    fn test_parse_groups_drops_empty_entries() {
        assert_eq!(
            parse_groups("dev,,oncall, ,admin"),
            vec!["dev", "oncall", "admin"]
        );
    }

    #[test]
    fn test_parse_groups_only_separators() {
        assert!(parse_groups(",,,").is_empty());
        assert!(parse_groups(" , , ").is_empty());
    }

    #[test]
    fn test_parse_groups_empty_string() {
        assert!(parse_groups("").is_empty());
    }

    #[test]
    fn test_parse_groups_single_value() {
        assert_eq!(parse_groups("admin"), vec!["admin"]);
    }

    #[test]
    fn test_parse_groups_preserves_case() {
        // Role matching is case-sensitive — parser must not normalize.
        assert_eq!(
            parse_groups("Admin,DEV,oncall"),
            vec!["Admin", "DEV", "oncall"]
        );
    }

    #[test]
    fn test_parse_groups_preserves_duplicates() {
        // If the upstream header has duplicates, we keep them (don't silently dedupe).
        assert_eq!(parse_groups("dev,dev,admin"), vec!["dev", "dev", "admin"]);
    }

    #[test]
    fn test_parse_groups_unicode() {
        assert_eq!(
            parse_groups("développeur, 管理员"),
            vec!["développeur", "管理员"]
        );
    }

    #[tokio::test]
    async fn test_forwarded_groups_header_populates_roles() {
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        creds.insert(
            "x-forwarded-groups".to_string(),
            "dev, oncall, ,admin".to_string(),
        );
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
        assert_eq!(
            identity.roles,
            vec!["dev".to_string(), "oncall".to_string(), "admin".to_string()]
        );
    }

    #[tokio::test]
    async fn test_forwarded_missing_groups_header_yields_empty_roles() {
        // Missing groups header is NOT an error — just no roles.
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
        assert!(identity.roles.is_empty());
    }

    #[tokio::test]
    async fn test_forwarded_empty_groups_header_yields_empty_roles() {
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        creds.insert("x-forwarded-groups".to_string(), String::new());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert!(identity.roles.is_empty());
    }

    #[tokio::test]
    async fn test_forwarded_custom_groups_header_name() {
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "X-Remote-Groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        creds.insert("x-remote-groups".to_string(), "dev,admin".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.roles, vec!["dev".to_string(), "admin".to_string()]);
    }

    #[tokio::test]
    async fn test_forwarded_default_groups_header_ignored_when_custom_set() {
        // Privilege escalation guard: if operator configures a custom groups
        // header, the default `x-forwarded-groups` must NOT be read — otherwise
        // an attacker who can set one but not the other could inject roles.
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-remote-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        creds.insert(
            "x-forwarded-groups".to_string(),
            "admin,superuser".to_string(),
        );
        let identity = provider.authenticate(&creds).await.unwrap();
        assert!(
            identity.roles.is_empty(),
            "default groups header must be ignored when a custom one is configured"
        );
    }

    #[tokio::test]
    async fn test_forwarded_missing_user_still_errors_even_with_groups() {
        // Bypass guard: groups header alone must not authenticate anyone.
        let provider = ForwardedUserAuth::new(
            "x-forwarded-user".to_string(),
            "x-forwarded-groups".to_string(),
        );
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-groups".to_string(), "admin".to_string());
        assert!(provider.authenticate(&creds).await.is_err());
    }

    // ---------------------------------------------------------------------
    // ProviderChain — composite provider running multiple auth backends
    // in parallel on the same /mcp endpoint. Models the issue #90 use case:
    // dev local with static bearer + Claude.ai web with OAuth JWT, both on
    // the same instance, no config swap.
    // ---------------------------------------------------------------------

    /// Test-only provider that mimics a JWT validator: accepts a single
    /// bearer value mapped to an identity. Lets us exercise chain
    /// behavior without pulling in real JWT crypto.
    struct StubBearerOnly {
        token: String,
        identity: AuthIdentity,
    }

    #[async_trait]
    impl AuthProvider for StubBearerOnly {
        async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity> {
            let header = creds
                .get("authorization")
                .ok_or_else(|| anyhow::anyhow!("missing Authorization header"))?;
            if header.len() < 7 || !header[..7].eq_ignore_ascii_case("bearer ") {
                bail!("Authorization header must use Bearer scheme");
            }
            if header[7..] == self.token {
                Ok(self.identity.clone())
            } else {
                bail!("invalid token (stub)")
            }
        }
    }

    fn local_dev_provider() -> Arc<dyn AuthProvider> {
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-local-dev".to_string(),
            BearerToken::Extended {
                subject: "avelino".to_string(),
                roles: vec!["admin".to_string()],
            },
        );
        Arc::new(BearerTokenAuth::new(tokens))
    }

    fn jwt_like_provider() -> Arc<dyn AuthProvider> {
        Arc::new(StubBearerOnly {
            token: "fake.jwt.token".to_string(),
            identity: AuthIdentity::new(
                "alice@example.com",
                vec!["dev".to_string(), "oauth-user".to_string()],
            ),
        })
    }

    fn auth_creds(token: &str) -> Credentials {
        let mut c = Credentials::new();
        c.insert("authorization".to_string(), format!("Bearer {token}"));
        c
    }

    #[tokio::test]
    async fn test_chain_static_bearer_authenticates_local_dev() {
        // First provider in chain accepts → second provider never runs.
        let chain = ProviderChain::new(vec![local_dev_provider(), jwt_like_provider()]);
        let id = chain
            .authenticate(&auth_creds("tok-local-dev"))
            .await
            .unwrap();
        assert_eq!(id.subject, "avelino");
        assert_eq!(id.roles, vec!["admin".to_string()]);
    }

    #[tokio::test]
    async fn test_chain_jwt_authenticates_when_static_fails() {
        // Static rejects, JWT-like accepts → chain returns JWT identity.
        // This is the cross-provider case that the briefing required.
        let chain = ProviderChain::new(vec![local_dev_provider(), jwt_like_provider()]);
        let id = chain
            .authenticate(&auth_creds("fake.jwt.token"))
            .await
            .unwrap();
        assert_eq!(id.subject, "alice@example.com");
        assert!(id.roles.contains(&"oauth-user".to_string()));
    }

    #[tokio::test]
    async fn test_chain_returns_first_provider_error_when_all_fail() {
        // Oracle defense: must not leak which provider got further.
        // The error returned must come from the FIRST configured provider,
        // not the most informative one.
        let chain = ProviderChain::new(vec![local_dev_provider(), jwt_like_provider()]);
        let err = chain.authenticate(&auth_creds("nope")).await.unwrap_err();
        // BearerTokenAuth's error is "invalid bearer token"; StubBearerOnly's
        // is "invalid token (stub)". The first must win.
        assert!(
            err.to_string().contains("invalid bearer token"),
            "expected first provider's error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_chain_does_not_leak_jwt_role_to_static_user() {
        // Privilege isolation: JWT identity has role `oauth-user` but a
        // static-bearer auth must never inherit it. Ensures providers
        // remain isolated state-wise.
        let chain = ProviderChain::new(vec![local_dev_provider(), jwt_like_provider()]);
        let id = chain
            .authenticate(&auth_creds("tok-local-dev"))
            .await
            .unwrap();
        assert!(
            !id.roles.contains(&"oauth-user".to_string()),
            "static bearer must not inherit OAuth role"
        );
    }

    #[tokio::test]
    async fn test_chain_empty_acts_as_no_auth() {
        // Degenerate but valid: empty chain == anonymous identity.
        let chain = ProviderChain::new(vec![]);
        let id = chain.authenticate(&Credentials::new()).await.unwrap();
        assert_eq!(id.subject, "anonymous");
        assert!(id.roles.is_empty());
    }

    #[tokio::test]
    async fn test_chain_short_circuits_on_first_success() {
        // Performance contract: provider 2 must NOT be called when
        // provider 1 already accepted. Wired with a counting stub.
        struct CountingAccept(std::sync::Arc<std::sync::atomic::AtomicUsize>);

        #[async_trait]
        impl AuthProvider for CountingAccept {
            async fn authenticate(&self, _: &Credentials) -> Result<AuthIdentity> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(AuthIdentity::new("counted", vec![]))
            }
        }

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let chain = ProviderChain::new(vec![
            local_dev_provider(),
            Arc::new(CountingAccept(counter.clone())),
        ]);
        chain
            .authenticate(&auth_creds("tok-local-dev"))
            .await
            .unwrap();
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "second provider must not be invoked when first accepts"
        );
    }

    #[tokio::test]
    async fn test_chain_order_does_not_change_correctness() {
        // Reversing provider order must still accept the same tokens.
        let normal = ProviderChain::new(vec![local_dev_provider(), jwt_like_provider()]);
        let reversed = ProviderChain::new(vec![jwt_like_provider(), local_dev_provider()]);

        for tok in ["tok-local-dev", "fake.jwt.token"] {
            let a = normal.authenticate(&auth_creds(tok)).await;
            let b = reversed.authenticate(&auth_creds(tok)).await;
            assert!(a.is_ok(), "normal order rejected token {tok}");
            assert!(b.is_ok(), "reversed order rejected token {tok}");
            assert_eq!(a.unwrap().subject, b.unwrap().subject);
        }
    }

    #[tokio::test]
    async fn test_chain_rejects_bypass_via_missing_header() {
        // No Authorization header → every provider in the chain rejects.
        let chain = ProviderChain::new(vec![local_dev_provider(), jwt_like_provider()]);
        assert!(chain.authenticate(&Credentials::new()).await.is_err());
    }

    // ---------------------------------------------------------------------
    // read_trusted_user — extracted helper, reused by ForwardedUserAuth and
    // by the OAuth AS /authorize handler (issue #90).
    // ---------------------------------------------------------------------

    #[test]
    fn test_read_trusted_user_present() {
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        creds.insert("x-forwarded-groups".to_string(), "dev,admin".to_string());
        let (subject, roles) =
            read_trusted_user(&creds, "x-forwarded-user", "x-forwarded-groups").unwrap();
        assert_eq!(subject, "alice");
        assert_eq!(roles, vec!["dev".to_string(), "admin".to_string()]);
    }

    #[test]
    fn test_read_trusted_user_case_insensitive_header_lookup() {
        // Operator may declare headers with any casing in config; lookup
        // must still find the lowercased credentials map entry.
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "bob".to_string());
        let (subject, _) =
            read_trusted_user(&creds, "X-Forwarded-User", "X-Forwarded-Groups").unwrap();
        assert_eq!(subject, "bob");
    }

    #[test]
    fn test_read_trusted_user_missing_returns_none() {
        let creds = Credentials::new();
        assert!(read_trusted_user(&creds, "x-forwarded-user", "x-forwarded-groups").is_none());
    }

    #[test]
    fn test_read_trusted_user_empty_returns_none() {
        // Empty user header is treated as "no identity" — never as an
        // anonymous one. Important for the AS: an empty header must
        // refuse to issue a code, not issue a code for "" subject.
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), String::new());
        assert!(read_trusted_user(&creds, "x-forwarded-user", "x-forwarded-groups").is_none());
    }

    #[test]
    fn test_read_trusted_user_no_groups_header_yields_empty_roles() {
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "alice".to_string());
        let (_, roles) =
            read_trusted_user(&creds, "x-forwarded-user", "x-forwarded-groups").unwrap();
        assert!(roles.is_empty());
    }
}
