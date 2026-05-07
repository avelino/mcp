//! `OAuthAsAuth` — the [`AuthProvider`] backed by JWTs that this AS
//! issued. Plugs into the same `Authorization: Bearer …` extraction
//! the static-bearer provider uses, so the `/mcp` request handler
//! doesn't need to know which provider validated the token.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use super::jwt;
use super::{AsState, OAuthAsConfig};
use crate::server_auth::{AuthIdentity, AuthProvider, Credentials};

pub struct OAuthAsAuth {
    config: Arc<OAuthAsConfig>,
    state: Arc<AsState>,
}

impl OAuthAsAuth {
    pub fn new(config: Arc<OAuthAsConfig>, state: Arc<AsState>) -> Self {
        Self { config, state }
    }
}

#[async_trait]
impl AuthProvider for OAuthAsAuth {
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity> {
        let header = creds
            .get("authorization")
            .context("missing Authorization header")?;
        if header.len() < 7 || !header[..7].eq_ignore_ascii_case("bearer ") {
            bail!("Authorization header must use Bearer scheme");
        }
        let token = &header[7..];

        // Heuristic: a JWT has exactly two dots. Anything else is
        // certainly not for us — fail fast with a stable error so the
        // composite chain can move on without burning HMAC verify.
        if token.matches('.').count() != 2 {
            bail!("token is not a JWT");
        }

        // We don't know which client_id this token was issued for
        // until we decode the (untrusted) payload. Peek at it
        // unsafely first to learn the audience, then call the proper
        // `verify` with that audience pinned. This keeps audience
        // enforcement strict without having to disable it during
        // decode.
        let aud = peek_audience(token).context("could not extract audience claim")?;

        // Check the audience refers to a registered client. If the
        // client was deregistered (or never existed), reject — even
        // a signature-valid token must not bypass client revocation.
        if self.state.get_client(&aud).is_none() {
            bail!("token audience does not refer to a registered client");
        }

        let issuer = self.config.issuer_url.trim_end_matches('/');
        let claims = jwt::verify(token, self.config.jwt_secret.as_bytes(), issuer, &aud)?;

        if claims.sub.is_empty() {
            bail!("JWT subject claim is empty");
        }

        Ok(AuthIdentity::new(claims.sub, claims.groups))
    }
}

/// Decode the JWT payload (without verifying the signature) just to
/// read the `aud` claim. This is the standard pattern for issuers
/// that require audience-aware verification.
fn peek_audience(token: &str) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut parts = token.splitn(3, '.');
    let _header = parts.next();
    let payload = parts.next().context("JWT missing payload segment")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("JWT payload not base64url")?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).context("JWT payload not JSON")?;
    let aud = v
        .get("aud")
        .and_then(|x| x.as_str())
        .context("aud claim missing or not a string")?;
    Ok(aud.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oauth_primitives::generate_random_string;
    use crate::server_auth::oauth_as::types::{JwtClaims, RegisteredClient};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn cfg() -> Arc<OAuthAsConfig> {
        Arc::new(OAuthAsConfig {
            issuer_url: "https://mcp.example.com".to_string(),
            jwt_secret: "k".repeat(32),
            trusted_user_header: "x-forwarded-user".to_string(),
            trusted_groups_header: "x-forwarded-groups".to_string(),
            trusted_source_cidrs: vec!["127.0.0.1/32".to_string()],
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 2_592_000,
            authorization_code_ttl_seconds: 60,
            scopes_supported: vec!["mcp".to_string()],
            redirect_uri_allowlist: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
            injected_roles: vec!["oauth-user".to_string()],
        })
    }

    fn state_with_client(client_id: &str) -> Arc<AsState> {
        let s = Arc::new(AsState::default());
        s.register_client(RegisteredClient {
            client_id: client_id.to_string(),
            client_name: None,
            redirect_uris: vec![],
            grant_types: vec![],
            created_at_unix: 0,
        })
        .unwrap();
        s
    }

    fn fresh_jwt(secret: &[u8], issuer: &str, aud: &str, sub: &str, groups: Vec<String>) -> String {
        let n = now();
        let claims = JwtClaims {
            iss: issuer.to_string(),
            aud: aud.to_string(),
            sub: sub.to_string(),
            groups,
            iat: n,
            nbf: n,
            exp: n + 3600,
            jti: generate_random_string(8),
        };
        jwt::sign(&claims, secret).unwrap()
    }

    fn auth_header(token: &str) -> Credentials {
        let mut c = Credentials::new();
        c.insert("authorization".to_string(), format!("Bearer {token}"));
        c
    }

    #[tokio::test]
    async fn test_provider_accepts_valid_jwt() {
        let cfg = cfg();
        let state = state_with_client("client-A");
        let token = fresh_jwt(
            cfg.jwt_secret.as_bytes(),
            "https://mcp.example.com",
            "client-A",
            "alice",
            vec!["dev".to_string()],
        );
        let p = OAuthAsAuth::new(cfg, state);
        let id = p.authenticate(&auth_header(&token)).await.unwrap();
        assert_eq!(id.subject, "alice");
        assert_eq!(id.roles, vec!["dev".to_string()]);
    }

    #[tokio::test]
    async fn test_provider_rejects_jwt_signed_by_other_secret() {
        let cfg = cfg();
        let state = state_with_client("client-A");
        let token = fresh_jwt(
            b"q".repeat(32).as_slice(),
            "https://mcp.example.com",
            "client-A",
            "alice",
            vec![],
        );
        let p = OAuthAsAuth::new(cfg, state);
        assert!(p.authenticate(&auth_header(&token)).await.is_err());
    }

    #[tokio::test]
    async fn test_provider_rejects_jwt_with_wrong_issuer() {
        let cfg = cfg();
        let state = state_with_client("client-A");
        let token = fresh_jwt(
            cfg.jwt_secret.as_bytes(),
            "https://attacker.example.com",
            "client-A",
            "alice",
            vec![],
        );
        let p = OAuthAsAuth::new(cfg, state);
        assert!(p.authenticate(&auth_header(&token)).await.is_err());
    }

    #[tokio::test]
    async fn test_provider_rejects_jwt_for_revoked_client() {
        // The signature is valid and issuer matches, but the client
        // referenced by `aud` was removed from the registry — must
        // be rejected. This is how operators revoke OAuth access.
        let cfg = cfg();
        let state = Arc::new(AsState::default()); // no clients
        let token = fresh_jwt(
            cfg.jwt_secret.as_bytes(),
            "https://mcp.example.com",
            "ghost-client",
            "alice",
            vec![],
        );
        let p = OAuthAsAuth::new(cfg, state);
        assert!(p.authenticate(&auth_header(&token)).await.is_err());
    }

    #[tokio::test]
    async fn test_provider_rejects_non_jwt_string() {
        let p = OAuthAsAuth::new(cfg(), state_with_client("c"));
        assert!(p
            .authenticate(&auth_header("opaque-static-token"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_provider_rejects_missing_authorization() {
        let p = OAuthAsAuth::new(cfg(), state_with_client("c"));
        assert!(p.authenticate(&Credentials::new()).await.is_err());
    }

    #[tokio::test]
    async fn test_provider_rejects_non_bearer_scheme() {
        let mut c = Credentials::new();
        c.insert("authorization".to_string(), "Basic abc".to_string());
        let p = OAuthAsAuth::new(cfg(), state_with_client("c"));
        assert!(p.authenticate(&c).await.is_err());
    }

    #[tokio::test]
    async fn test_provider_populates_subject_and_roles() {
        let cfg = cfg();
        let state = state_with_client("client-A");
        let token = fresh_jwt(
            cfg.jwt_secret.as_bytes(),
            "https://mcp.example.com",
            "client-A",
            "user@example.com",
            vec!["oauth-user".to_string(), "dev".to_string()],
        );
        let p = OAuthAsAuth::new(cfg, state);
        let id = p.authenticate(&auth_header(&token)).await.unwrap();
        assert_eq!(id.subject, "user@example.com");
        assert!(id.roles.contains(&"oauth-user".to_string()));
        assert!(id.roles.contains(&"dev".to_string()));
    }
}
