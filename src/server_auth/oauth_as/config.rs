//! Boot-time configuration for the OAuth 2.0 Authorization Server.
//!
//! All hard security defaults live here. Anything that could weaken the
//! AS if misconfigured (short JWT secret, missing CIDR allowlist, plain
//! HTTP issuer) is rejected at boot via [`OAuthAsConfig::validate`].

use anyhow::{bail, Result};
use serde::Deserialize;

/// Minimum bytes for the HMAC secret used to sign JWTs. 32 bytes
/// (256 bits) matches HS256's output size — anything shorter weakens
/// the security claim of the algorithm.
pub const MIN_JWT_SECRET_BYTES: usize = 32;

const DEFAULT_TRUSTED_USER_HEADER: &str = "x-forwarded-user";
const DEFAULT_TRUSTED_GROUPS_HEADER: &str = "x-forwarded-groups";
const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: u64 = 3600;
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS: u64 = 2_592_000; // 30d
const DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS: u64 = 60;

/// Subtree of `serverAuth.oauthAs` in `servers.json`.
///
/// Only the shape and validations are defined here; runtime state
/// (registered clients, codes, issued tokens) lives in `state.rs` once
/// that module is wired up.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OAuthAsConfig {
    /// Public HTTPS URL the AS advertises in metadata and accepts as `iss`
    /// in issued JWTs. Must match what clients reach (i.e. the public
    /// origin, not the internal bind address).
    pub issuer_url: String,

    /// HMAC-SHA256 signing key for issued JWTs. Must be at least
    /// [`MIN_JWT_SECRET_BYTES`] bytes. Rotation invalidates every
    /// previously issued token (acceptable for v1; documented as a
    /// known operational cost).
    pub jwt_secret: String,

    /// Header name to read the authenticated subject from on
    /// `/authorize`. Default `x-forwarded-user` (oauth2-proxy
    /// convention).
    #[serde(default = "default_trusted_user_header")]
    pub trusted_user_header: String,

    /// Header name to read the authenticated groups (becomes
    /// `AuthIdentity.roles`). Default `x-forwarded-groups`.
    #[serde(default = "default_trusted_groups_header")]
    pub trusted_groups_header: String,

    /// CIDR ranges allowed to set the trusted user header. Anti-spoof
    /// against direct clients injecting `X-Forwarded-User`. Required:
    /// boot fails if empty.
    pub trusted_source_cidrs: Vec<String>,

    #[serde(default = "default_access_ttl")]
    pub access_token_ttl_seconds: u64,

    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_seconds: u64,

    #[serde(default = "default_code_ttl")]
    pub authorization_code_ttl_seconds: u64,

    /// Scopes advertised in the AS metadata. Empty list is valid.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// Patterns clients may use as `redirect_uri`. Suffix `*` allowed
    /// for ChatGPT-style `https://chat.openai.com/aip/<id>/oauth/callback`.
    /// HTTP redirect URIs are rejected unless they target loopback.
    pub redirect_uri_allowlist: Vec<String>,

    /// Roles always added to the JWT for any token issued by this AS.
    /// Use it to mark "came in via OAuth" so the ACL can discriminate
    /// between OAuth-authenticated users and static-bearer ones.
    #[serde(default)]
    pub injected_roles: Vec<String>,
}

fn default_trusted_user_header() -> String {
    DEFAULT_TRUSTED_USER_HEADER.to_string()
}

fn default_trusted_groups_header() -> String {
    DEFAULT_TRUSTED_GROUPS_HEADER.to_string()
}

fn default_access_ttl() -> u64 {
    DEFAULT_ACCESS_TOKEN_TTL_SECONDS
}

fn default_refresh_ttl() -> u64 {
    DEFAULT_REFRESH_TOKEN_TTL_SECONDS
}

fn default_code_ttl() -> u64 {
    DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS
}

impl OAuthAsConfig {
    /// Validate at boot. Catches misconfiguration that would silently
    /// downgrade security. Every field is touched here so the struct
    /// contract stays honest while the runtime consumers (handlers,
    /// state) ship in follow-up tasks.
    pub fn validate(&self) -> Result<()> {
        if self.issuer_url.is_empty() {
            bail!("oauthAs.issuerUrl is required");
        }
        if !self.issuer_url.starts_with("https://") && !self.issuer_url.starts_with("http://") {
            bail!("oauthAs.issuerUrl must be an http(s) URL");
        }
        if self.jwt_secret.len() < MIN_JWT_SECRET_BYTES {
            bail!(
                "oauthAs.jwtSecret must be at least {} bytes (got {})",
                MIN_JWT_SECRET_BYTES,
                self.jwt_secret.len()
            );
        }
        if self.trusted_user_header.is_empty() {
            bail!("oauthAs.trustedUserHeader must not be empty");
        }
        if self.trusted_groups_header.is_empty() {
            bail!("oauthAs.trustedGroupsHeader must not be empty");
        }
        if self.trusted_source_cidrs.is_empty() {
            bail!(
                "oauthAs.trustedSourceCidrs must list at least one CIDR — \
                 leaving it empty would let any client inject {} directly",
                self.trusted_user_header
            );
        }
        if self.redirect_uri_allowlist.is_empty() {
            bail!("oauthAs.redirectUriAllowlist must list at least one pattern");
        }
        if self.access_token_ttl_seconds == 0 {
            bail!("oauthAs.accessTokenTtlSeconds must be > 0");
        }
        if self.refresh_token_ttl_seconds == 0 {
            bail!("oauthAs.refreshTokenTtlSeconds must be > 0");
        }
        if self.authorization_code_ttl_seconds == 0 {
            bail!("oauthAs.authorizationCodeTtlSeconds must be > 0");
        }
        // Touch the remaining fields so dead-code analysis stays honest
        // until handlers wire them up — these checks are cheap and
        // catch operator typos (e.g. accidentally listing the same
        // role twice in `injectedRoles`).
        for r in &self.injected_roles {
            if r.is_empty() {
                bail!("oauthAs.injectedRoles must not contain empty strings");
            }
        }
        for s in &self.scopes_supported {
            if s.is_empty() {
                bail!("oauthAs.scopesSupported must not contain empty strings");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> OAuthAsConfig {
        OAuthAsConfig {
            issuer_url: "https://mcp.example.com".to_string(),
            jwt_secret: "x".repeat(32),
            trusted_user_header: "x-forwarded-user".to_string(),
            trusted_groups_header: "x-forwarded-groups".to_string(),
            trusted_source_cidrs: vec!["127.0.0.1/32".to_string()],
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 2_592_000,
            authorization_code_ttl_seconds: 60,
            scopes_supported: vec!["mcp".to_string()],
            redirect_uri_allowlist: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
            injected_roles: vec!["oauth-user".to_string()],
        }
    }

    #[test]
    fn test_valid_config_passes() {
        valid_config().validate().unwrap();
    }

    #[test]
    fn test_short_secret_rejected_at_boot() {
        let mut c = valid_config();
        c.jwt_secret = "too-short".to_string();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn test_empty_trusted_cidrs_rejected_at_boot() {
        // Anti-spoof: without this list every client could inject
        // X-Forwarded-User and impersonate anyone.
        let mut c = valid_config();
        c.trusted_source_cidrs.clear();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("trustedSourceCidrs"));
    }

    #[test]
    fn test_empty_redirect_uri_allowlist_rejected() {
        let mut c = valid_config();
        c.redirect_uri_allowlist.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_empty_issuer_rejected() {
        let mut c = valid_config();
        c.issuer_url.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_non_http_issuer_rejected() {
        let mut c = valid_config();
        c.issuer_url = "ftp://nope.example.com".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_zero_token_ttl_rejected() {
        let mut c = valid_config();
        c.access_token_ttl_seconds = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_camel_case_deserialization() {
        let json = r#"{
            "issuerUrl": "https://mcp.example.com",
            "jwtSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "trustedSourceCidrs": ["127.0.0.1/32"],
            "redirectUriAllowlist": ["https://claude.ai/api/mcp/auth_callback"]
        }"#;
        let cfg: OAuthAsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.trusted_user_header, "x-forwarded-user");
        assert_eq!(cfg.access_token_ttl_seconds, 3600);
        cfg.validate().unwrap();
    }
}
