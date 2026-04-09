use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::HashMap;

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
fn parse_groups(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[async_trait]
impl AuthProvider for ForwardedUserAuth {
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity> {
        let user = creds
            .get(&self.header)
            .ok_or_else(|| anyhow::anyhow!("missing {} header", self.header))?;

        if user.is_empty() {
            bail!("{} header is empty", self.header);
        }

        let roles = creds
            .get(&self.groups_header)
            .map(|raw| parse_groups(raw))
            .unwrap_or_default();

        Ok(AuthIdentity::new(user.clone(), roles))
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
}
