use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::HashMap;

use super::{AuthIdentity, AuthProvider, Credentials};

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
/// Maps token -> subject.
pub struct BearerTokenAuth {
    tokens: HashMap<String, String>,
}

impl BearerTokenAuth {
    pub fn new(tokens: HashMap<String, String>) -> Self {
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
            Some(subject) => Ok(AuthIdentity::new(subject.clone(), vec![])),
            None => bail!("invalid bearer token"),
        }
    }
}

/// Trusts a reverse proxy header (e.g. X-Forwarded-User).
/// Only use behind a trusted proxy that sets this header.
pub struct ForwardedUserAuth {
    header: String,
}

impl ForwardedUserAuth {
    pub fn new(header: String) -> Self {
        Self {
            header: header.to_lowercase(),
        }
    }
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

        Ok(AuthIdentity::new(user.clone(), vec![]))
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
        tokens.insert("secret-abc".to_string(), "alice".to_string());
        tokens.insert("secret-def".to_string(), "bob".to_string());
        let provider = BearerTokenAuth::new(tokens);

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer secret-abc".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
    }

    #[tokio::test]
    async fn test_bearer_case_insensitive_scheme() {
        let mut tokens = HashMap::new();
        tokens.insert("secret-abc".to_string(), "alice".to_string());
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
        tokens.insert("secret-abc".to_string(), "alice".to_string());
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
        let provider = ForwardedUserAuth::new("x-forwarded-user".to_string());
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "charlie".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "charlie");
    }

    #[tokio::test]
    async fn test_forwarded_missing_header() {
        let provider = ForwardedUserAuth::new("x-forwarded-user".to_string());
        assert!(provider.authenticate(&Credentials::new()).await.is_err());
    }

    #[tokio::test]
    async fn test_forwarded_empty_header() {
        let provider = ForwardedUserAuth::new("x-forwarded-user".to_string());
        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), String::new());
        assert!(provider.authenticate(&creds).await.is_err());
    }

    #[tokio::test]
    async fn test_forwarded_custom_header() {
        let provider = ForwardedUserAuth::new("X-Remote-User".to_string());
        let mut creds = Credentials::new();
        creds.insert("x-remote-user".to_string(), "dave".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "dave");
    }
}
