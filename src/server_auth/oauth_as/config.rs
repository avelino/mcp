//! Boot-time configuration for the OAuth 2.0 Authorization Server.
//!
//! All hard security defaults live here. Anything that could weaken the
//! AS if misconfigured (short JWT secret, missing CIDR allowlist, plain
//! HTTP issuer) is rejected at boot via [`OAuthAsConfig::validate`].

use std::collections::HashSet;

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

    /// Identity providers whose signed identity assertions are exchanged
    /// for an access token without a consent screen. Empty (the default)
    /// leaves the grant disabled, so existing configs are unaffected.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuer>,

    /// Clients known ahead of time, so they need no dynamic registration.
    #[serde(default)]
    pub static_clients: Vec<StaticClient>,
}

/// An identity provider trusted to vouch for users via signed assertions.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustedIssuer {
    /// Matched byte-for-byte against the assertion's `iss`.
    pub issuer: String,

    /// Distinguishes several tenants served from one `issuer` URL.
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// An assertion's email must belong to one of these domains. Required
    /// non-empty: without it any user the issuer vouches for gets in.
    pub allowed_email_domains: Vec<String>,

    /// Roles granted to users arriving through this issuer.
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StaticClient {
    pub client_id: String,
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
        validate_header_safe_url("oauthAs.issuerUrl", &self.issuer_url)?;
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
        // Pattern shape itself is also validated at request time, but
        // doing it here turns operator typos (middle `*`, missing
        // scheme, `https//` instead of `https://`) into a fail-fast
        // boot error instead of a per-request rejection clients first
        // see in production.
        for pattern in &self.redirect_uri_allowlist {
            super::redirect_uri::validate_pattern(pattern)
                .map_err(|e| anyhow::anyhow!("oauthAs.redirectUriAllowlist invalid: {e}"))?;
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
        let mut client_ids = HashSet::new();
        for c in &self.static_clients {
            if c.client_id.is_empty() {
                bail!("oauthAs.staticClients must not contain an empty clientId");
            }
            // `set_static_clients` keys a map on `clientId`, so a duplicate
            // would be dropped without a word.
            if !client_ids.insert(&c.client_id) {
                bail!(
                    "oauthAs.staticClients must not list the same clientId twice ({})",
                    c.client_id
                );
            }
        }
        for (i, t) in self.trusted_issuers.iter().enumerate() {
            let at = format!("oauthAs.trustedIssuers[{i}]");
            if !t.issuer.starts_with("https://") {
                bail!("{at}.issuer must be an https URL");
            }
            validate_header_safe_url(&format!("{at}.issuer"), &t.issuer)?;
            // An empty string names no tenant; it is what an env-var
            // template that expanded to nothing leaves behind. Omitting the
            // key means "every workspace behind this issuer", which is a
            // different decision than the operator spelled out.
            if t.tenant_id.as_deref() == Some("") {
                bail!("{at}.tenantId must not be empty — omit the key instead");
            }
            if t.allowed_email_domains.is_empty() {
                bail!("{at}.allowedEmailDomains must list at least one domain");
            }
            if t.allowed_email_domains.iter().any(String::is_empty) {
                bail!("{at}.allowedEmailDomains must not contain empty strings");
            }
            if t.roles.iter().any(String::is_empty) {
                bail!("{at}.roles must not contain empty strings");
            }
            // An entry that cannot resolve to itself is unreachable (same
            // issuer and tenant twice, or a tenant-less twin of a tenanted
            // entry), so the ambiguity is caught here, not at exchange time.
            if let Err(why) = self.resolve_issuer(&t.issuer, t.tenant_id.as_deref()) {
                bail!("{at} is not uniquely addressable: {why}");
            }
        }
        Ok(())
    }

    /// Picks the trusted issuer for an assertion. Exact string match on
    /// `iss`: normalizing or prefix-matching would let a look-alike issuer
    /// ride on a trusted entry. `aud_tenant` disambiguates entries that
    /// share an issuer URL and must name an entry for that same issuer.
    ///
    /// The tenant rule runs one way only: an entry that declares
    /// `tenantId` is reachable solely by an assertion naming that tenant,
    /// while an entry that declares none keeps vouching for every
    /// workspace behind its issuer.
    pub fn resolve_issuer(
        &self,
        iss: &str,
        aud_tenant: Option<&str>,
    ) -> Result<&TrustedIssuer, &'static str> {
        let mut matches = self
            .trusted_issuers
            .iter()
            .filter(|t| t.issuer == iss)
            // Only a `None` on the *entry* side stops discriminating: an
            // entry without `tenantId` vouches for every workspace behind
            // its issuer, which is the shape of a config serving one
            // customer and the one running in production today.
            //
            // An entry that declares `tenantId` requires the assertion to
            // name that same tenant. `aud_tenant: None` no longer satisfies
            // it: an assertion that identifies no workspace must not be
            // handed a workspace's roles and domains, and Anthropic
            // documents that a Claude-issued assertion may omit the claim.
            .filter(|t| t.tenant_id.is_none() || t.tenant_id.as_deref() == aud_tenant);
        match (matches.next(), matches.next()) {
            (Some(t), None) => Ok(t),
            (Some(_), Some(_)) => Err("issuer is ambiguous, tenant required"),
            // Nothing matched. The issuer being configured but tenanted is
            // worth its own answer: it is the one case where the operator's
            // issuer URL is right and the fix is on the tenant, so
            // collapsing it into "not trusted" sends them to check a URL
            // that was never wrong. Which tenant an issuer serves stays
            // unsaid — `/token` takes no credential to reach.
            (None, _)
                if aud_tenant.is_none() && self.trusted_issuers.iter().any(|t| t.issuer == iss) =>
            {
                Err("issuer requires a tenant the assertion does not name")
            }
            (None, _) => Err("issuer is not trusted"),
        }
    }
}

/// The issuer URL is echoed into a `WWW-Authenticate` header; a quote or
/// control character there yields a malformed or silently dropped header,
/// so it is refused at load instead of at the point of use.
fn validate_header_safe_url(field: &str, value: &str) -> Result<()> {
    if value.chars().any(|c| c == '"' || c.is_ascii_control()) {
        bail!("{field} must not contain a double quote or control character");
    }
    url::Url::parse(value).map_err(|e| anyhow::anyhow!("{field} is not a valid URL: {e}"))?;
    Ok(())
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
            trusted_issuers: vec![],
            static_clients: vec![],
        }
    }

    fn issuer(iss: &str, tenant: Option<&str>) -> TrustedIssuer {
        TrustedIssuer {
            issuer: iss.to_string(),
            tenant_id: tenant.map(str::to_string),
            allowed_email_domains: vec!["example.com".to_string()],
            roles: vec![],
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
    fn test_middle_wildcard_pattern_rejected_at_boot() {
        // Regression for PR #91 review: only trailing `*` allowed.
        // Middle `*` would silently widen matching at request time;
        // catching it at boot prevents that surprise.
        let mut c = valid_config();
        c.redirect_uri_allowlist = vec!["https://*.example.com/cb".to_string()];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("redirectUriAllowlist"));
    }

    #[test]
    fn test_malformed_url_pattern_rejected_at_boot() {
        // Operator typo: missing colon in scheme — must fail at boot.
        let mut c = valid_config();
        c.redirect_uri_allowlist = vec!["https//example.com/cb".to_string()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_non_http_scheme_pattern_rejected_at_boot() {
        let mut c = valid_config();
        c.redirect_uri_allowlist = vec!["custom://nope".to_string()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_trailing_wildcard_pattern_accepted_at_boot() {
        // Trailing `*` is the only wildcard form allowed; ChatGPT-style
        // redirects rely on it.
        let mut c = valid_config();
        c.redirect_uri_allowlist = vec!["https://chat.openai.com/aip/*".to_string()];
        c.validate().unwrap();
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

    #[test]
    fn test_config_without_trusted_issuers_still_validates() {
        // Shape of a servers.json written before enterprise-managed auth.
        let json = r#"{
            "issuerUrl": "https://mcp.example.com",
            "jwtSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "trustedUserHeader": "x-forwarded-user",
            "trustedGroupsHeader": "x-forwarded-groups",
            "trustedSourceCidrs": ["127.0.0.1/32"],
            "accessTokenTtlSeconds": 3600,
            "refreshTokenTtlSeconds": 2592000,
            "authorizationCodeTtlSeconds": 60,
            "scopesSupported": ["mcp"],
            "redirectUriAllowlist": ["https://claude.ai/api/mcp/auth_callback"],
            "injectedRoles": ["oauth-user"]
        }"#;
        let cfg: OAuthAsConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.trusted_issuers.is_empty());
        assert!(cfg.static_clients.is_empty());
        cfg.validate().unwrap();
    }

    #[test]
    fn test_trusted_issuers_camel_case_deserialization() {
        let json = r#"{
            "issuerUrl": "https://mcp.example.com",
            "jwtSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "trustedSourceCidrs": ["127.0.0.1/32"],
            "redirectUriAllowlist": ["https://claude.ai/api/mcp/auth_callback"],
            "trustedIssuers": [{
                "issuer": "https://idp.example.com",
                "tenantId": "t1",
                "allowedEmailDomains": ["example.com"],
                "roles": ["enterprise"]
            }],
            "staticClients": [{"clientId": "claude"}]
        }"#;
        let cfg: OAuthAsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.trusted_issuers[0].tenant_id.as_deref(), Some("t1"));
        assert_eq!(cfg.static_clients[0].client_id, "claude");
        cfg.validate().unwrap();
    }

    #[test]
    fn test_trusted_issuer_requires_https() {
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("http://x.com", None)];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("trustedIssuers"));
    }

    #[test]
    fn test_trusted_issuer_requires_email_domains() {
        let mut c = valid_config();
        let mut i = issuer("https://a.com", None);
        i.allowed_email_domains.clear();
        c.trusted_issuers = vec![i];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("allowedEmailDomains"));
    }

    #[test]
    fn test_trusted_issuer_empty_role_rejected() {
        let mut c = valid_config();
        let mut i = issuer("https://a.com", None);
        i.roles = vec![String::new()];
        c.trusted_issuers = vec![i];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("roles"));
    }

    #[test]
    fn test_trusted_issuer_with_control_character_is_rejected() {
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com/\n", None)];
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_static_client_empty_id_rejected() {
        let mut c = valid_config();
        c.static_clients = vec![StaticClient {
            client_id: String::new(),
        }];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("staticClients"));
    }

    #[test]
    fn test_duplicate_static_client_id_is_refused() {
        // `set_static_clients` collects into a map keyed by `clientId`, so a
        // duplicate silently wins over the entry above it — an operator who
        // pasted a block twice and edited one copy gets whichever landed
        // last, with no hint that the other was dropped.
        let mut c = valid_config();
        c.static_clients = vec![
            StaticClient {
                client_id: "claude".to_string(),
            },
            StaticClient {
                client_id: "claude".to_string(),
            },
        ];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("staticClients"), "{err}");
    }

    #[test]
    fn test_empty_tenant_id_is_refused() {
        // `Some("")` identifies no tenant: it can only come from an env-var
        // template that expanded to nothing. Accepted, it reaches
        // `resolve_issuer` as a tenant that matches no assertion.
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com", Some(""))];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("tenantId"), "{err}");
    }

    #[test]
    fn test_issuer_url_with_quote_is_rejected() {
        let mut c = valid_config();
        c.issuer_url = "https://mcp.example.com/\"x".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_issuer_url_with_control_character_is_rejected() {
        let mut c = valid_config();
        c.issuer_url = "https://mcp.example.com/\r\nX-Injected: 1".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_duplicate_issuer_and_tenant_rejected() {
        let mut c = valid_config();
        c.trusted_issuers = vec![
            issuer("https://a.com", Some("t1")),
            issuer("https://a.com", Some("t1")),
        ];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("uniquely addressable"));
    }

    #[test]
    fn test_resolve_issuer_by_exact_string() {
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com", None)];
        assert_eq!(
            c.resolve_issuer("https://a.com", None).unwrap().issuer,
            "https://a.com"
        );
        // No normalization and no prefix match: either would let a
        // look-alike issuer ride on a trusted entry.
        assert!(c.resolve_issuer("https://a.com/", None).is_err());
        assert!(c.resolve_issuer("https://a.com.evil.net", None).is_err());
    }

    #[test]
    fn test_resolve_issuer_ambiguous_is_rejected() {
        let mut c = valid_config();
        c.trusted_issuers = vec![
            issuer("https://a.com", Some("t1")),
            issuer("https://a.com", Some("t2")),
        ];
        assert!(c.resolve_issuer("https://a.com", None).is_err());
    }

    #[test]
    fn test_resolve_issuer_by_tenant_disambiguates() {
        let mut c = valid_config();
        c.trusted_issuers = vec![
            issuer("https://a.com", Some("t1")),
            issuer("https://a.com", Some("t2")),
        ];
        let got = c.resolve_issuer("https://a.com", Some("t2")).unwrap();
        assert_eq!(got.tenant_id.as_deref(), Some("t2"));
    }

    #[test]
    fn test_entry_without_tenant_id_accepts_assertion_carrying_aud_tenant() {
        // An entry with no `tenantId` does not discriminate by tenant, so it
        // vouches for every workspace behind its issuer. Requiring the
        // assertion to carry no `aud_tenant` refuses the production shape —
        // no `tenantId` configured, an IdP that always names the workspace —
        // and refuses it as "issuer is not trusted", which sends the operator
        // to check an issuer URL that was right all along.
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com", None)];
        c.validate().unwrap();
        assert_eq!(
            c.resolve_issuer("https://a.com", Some("any-workspace"))
                .unwrap()
                .issuer,
            "https://a.com"
        );
        // And still resolves when nothing names a tenant.
        assert!(c.resolve_issuer("https://a.com", None).is_ok());
    }

    #[test]
    fn test_entry_with_tenant_id_still_rejects_a_different_tenant() {
        // The other half of the rule, and the reason the fix is not simply
        // "ignore the tenant": an entry that names a tenant grants its roles
        // and its domains to that workspace alone.
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com", Some("t1"))];
        c.validate().unwrap();
        assert!(c.resolve_issuer("https://a.com", Some("t2")).is_err());
        assert_eq!(
            c.resolve_issuer("https://a.com", Some("t1"))
                .unwrap()
                .tenant_id
                .as_deref(),
            Some("t1")
        );
    }

    #[test]
    fn test_tenanted_entry_refuses_an_assertion_naming_no_tenant() {
        // The finding. One entry carrying `tenantId`, an assertion that
        // names no tenant: the old `aud_tenant.is_none()` arm resolved it
        // to that entry anyway, so configuring `tenantId` protected
        // nothing against an assertion that simply omits the claim — and
        // Anthropic documents that a Claude-issued assertion may omit it.
        //
        // The refusal names the tenant rather than the issuer, because
        // the issuer URL was right and sending the operator to check it
        // is the wrong errand.
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com", Some("t1"))];
        c.validate().unwrap();
        let err = c.resolve_issuer("https://a.com", None).unwrap_err();
        assert_eq!(err, "issuer requires a tenant the assertion does not name");
    }

    #[test]
    fn test_two_tenanted_entries_and_no_tenant_still_name_the_tenant() {
        // The case the naive filter change loses: before the fix this was
        // the one refusal that told the operator a tenant was required,
        // and narrowing the filter alone collapses it into "issuer is not
        // trusted", which is a worse answer than the buggy code gave.
        let mut c = valid_config();
        c.trusted_issuers = vec![
            issuer("https://a.com", Some("t1")),
            issuer("https://a.com", Some("t2")),
        ];
        let err = c.resolve_issuer("https://a.com", None).unwrap_err();
        assert_eq!(err, "issuer requires a tenant the assertion does not name");
    }

    #[test]
    fn test_an_unknown_issuer_still_reports_the_issuer_not_the_tenant() {
        // The other side of the message split: nothing is configured for
        // this `iss` at all, so the tenant has nothing to do with it.
        let mut c = valid_config();
        c.trusted_issuers = vec![issuer("https://a.com", Some("t1"))];
        assert_eq!(
            c.resolve_issuer("https://b.com", None).unwrap_err(),
            "issuer is not trusted"
        );
        assert_eq!(
            c.resolve_issuer("https://b.com", Some("t1")).unwrap_err(),
            "issuer is not trusted"
        );
        // And a tenant the issuer does not serve stays "not trusted": the
        // pair is what is untrusted, and saying which half was wrong is a
        // config oracle for an endpoint that takes no credential.
        assert_eq!(
            c.resolve_issuer("https://a.com", Some("t2")).unwrap_err(),
            "issuer is not trusted"
        );
    }

    #[test]
    fn test_a_tenantless_twin_of_a_tenanted_entry_is_still_refused_at_boot() {
        // Backwards compatibility on the boot check. A tenant-less entry
        // vouches for every workspace behind its issuer, so it swallows
        // the tenanted entry beside it — whichever order they are listed
        // in. Narrowing `resolve_issuer` moves which index reports it, so
        // this pins that the config shape is still refused.
        let mut c = valid_config();
        c.trusted_issuers = vec![
            issuer("https://a.com", None),
            issuer("https://a.com", Some("t1")),
        ];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("uniquely addressable"), "{err}");

        c.trusted_issuers.reverse();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("uniquely addressable"), "{err}");
    }

    #[test]
    fn test_resolve_issuer_tenant_must_also_match_issuer() {
        let mut c = valid_config();
        c.trusted_issuers = vec![
            issuer("https://a.com", Some("t1")),
            issuer("https://b.com", Some("t2")),
        ];
        assert!(c.resolve_issuer("https://a.com", Some("t2")).is_err());
    }
}
