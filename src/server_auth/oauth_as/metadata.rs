//! Discovery endpoints — RFC 8414 (Authorization Server Metadata)
//! and RFC 9728 (Protected Resource Metadata, used by the MCP
//! authorization spec from 2025-06-18).
//!
//! These responses are what Claude.ai / ChatGPT / Cursor probe first
//! when an operator registers `https://mcp.example.com/mcp` as a
//! Custom Connector. Returning the wrong shape here makes every
//! downstream step fail with cryptic client-side errors.

use std::sync::Arc;

use axum::{extract::State, response::Json};
use serde::Serialize;

use super::token::JWT_BEARER_GRANT;
use super::OAuthAsConfig;

/// Grant profile identifier of the Identity Assertion JWT Authorization
/// Grant, from section 7.2 of
/// `draft-ietf-oauth-identity-assertion-authz-grant`. The MCP
/// Enterprise-Managed Authorization extension has clients look for this
/// exact string to decide whether the server speaks the profile.
const ID_JAG_GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";

#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    /// Absent — not empty — on deployments without Enterprise-Managed
    /// Authorization: an empty array would still claim the server
    /// processes grant profiles.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_grant_profiles_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
}

pub async fn protected_resource(
    State(cfg): State<Arc<OAuthAsConfig>>,
) -> Json<ProtectedResourceMetadata> {
    let issuer = cfg.issuer_url.trim_end_matches('/').to_string();
    Json(ProtectedResourceMetadata {
        resource: issuer.clone(),
        authorization_servers: vec![issuer],
    })
}

pub async fn authorization_server(
    State(cfg): State<Arc<OAuthAsConfig>>,
) -> Json<AuthorizationServerMetadata> {
    let issuer = cfg.issuer_url.trim_end_matches('/').to_string();

    // Both EMA fields hang off `trustedIssuers`. Announcing the grant
    // where no issuer is trusted would only turn a silent non-feature
    // into a token endpoint that refuses every assertion it is sent.
    let mut grant_types_supported = vec!["authorization_code", "refresh_token"];
    let mut authorization_grant_profiles_supported = Vec::new();
    if !cfg.trusted_issuers.is_empty() {
        // Section 7.2: a server advertising the id-jag profile MUST also
        // list jwt-bearer in `grant_types_supported`.
        grant_types_supported.push(JWT_BEARER_GRANT);
        authorization_grant_profiles_supported.push(ID_JAG_GRANT_PROFILE);
    }

    Json(AuthorizationServerMetadata {
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        registration_endpoint: format!("{issuer}/register"),
        scopes_supported: cfg.scopes_supported.clone(),
        // PKCE S256 only — `plain` is intentionally absent. OAuth 2.1
        // mandates this and so does the MCP authorization spec.
        code_challenge_methods_supported: vec!["S256"],
        response_types_supported: vec!["code"],
        grant_types_supported,
        authorization_grant_profiles_supported,
        // PKCE replaces client authentication for public clients —
        // Claude.ai and other MCP-aware clients are public clients.
        token_endpoint_auth_methods_supported: vec!["none"],
        issuer,
    })
}

#[cfg(test)]
mod tests {
    use super::super::config::TrustedIssuer;
    use super::*;

    fn cfg() -> Arc<OAuthAsConfig> {
        Arc::new(OAuthAsConfig {
            issuer_url: "https://mcp.example.com/".to_string(),
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
        })
    }

    #[tokio::test]
    async fn test_protected_resource_metadata_shape() {
        let Json(m) = protected_resource(State(cfg())).await;
        assert_eq!(m.resource, "https://mcp.example.com");
        assert_eq!(m.authorization_servers, vec!["https://mcp.example.com"]);
    }

    #[tokio::test]
    async fn test_authorization_server_metadata_shape() {
        let Json(m) = authorization_server(State(cfg())).await;
        assert_eq!(m.issuer, "https://mcp.example.com");
        assert_eq!(
            m.authorization_endpoint,
            "https://mcp.example.com/authorize"
        );
        assert_eq!(m.token_endpoint, "https://mcp.example.com/token");
        assert_eq!(m.registration_endpoint, "https://mcp.example.com/register");
        assert_eq!(
            m.grant_types_supported,
            vec!["authorization_code", "refresh_token"]
        );
    }

    #[tokio::test]
    async fn test_metadata_advertises_only_s256_pkce() {
        // Security regression: PKCE `plain` must NEVER appear in
        // advertised metadata, otherwise compliant clients may pick it.
        let Json(m) = authorization_server(State(cfg())).await;
        assert_eq!(m.code_challenge_methods_supported, vec!["S256"]);
        assert!(!m
            .code_challenge_methods_supported
            .iter()
            .any(|m| m.eq_ignore_ascii_case("plain")));
    }

    #[tokio::test]
    async fn test_metadata_token_endpoint_auth_method_is_none() {
        // PKCE replaces client_secret for public clients.
        let Json(m) = authorization_server(State(cfg())).await;
        assert_eq!(m.token_endpoint_auth_methods_supported, vec!["none"]);
    }

    fn cfg_with_issuer() -> Arc<OAuthAsConfig> {
        let mut c = (*cfg()).clone();
        c.trusted_issuers = vec![TrustedIssuer {
            issuer: "https://idp.example.com".to_string(),
            tenant_id: None,
            allowed_email_domains: vec!["example.com".to_string()],
            roles: vec![],
        }];
        Arc::new(c)
    }

    #[tokio::test]
    async fn test_metadata_advertises_jwt_bearer_when_issuers_configured() {
        // Claude only sends an assertion to an AS whose metadata lists
        // the grant, so a working `/token` that nobody announces is dead.
        let Json(m) = authorization_server(State(cfg_with_issuer())).await;
        assert!(
            m.grant_types_supported.contains(&JWT_BEARER_GRANT),
            "grant_types_supported must carry the jwt-bearer grant: {:?}",
            m.grant_types_supported
        );
    }

    #[tokio::test]
    async fn test_metadata_omits_jwt_bearer_without_issuers() {
        // A deployment with no trusted issuer refuses the grant at
        // `/token`; advertising it there would only produce errors.
        let Json(m) = authorization_server(State(cfg())).await;
        assert_eq!(
            m.grant_types_supported,
            vec!["authorization_code", "refresh_token"]
        );
    }

    #[tokio::test]
    async fn test_metadata_advertises_id_jag_grant_profile() {
        // Section 7.2 of the ID-JAG draft: this is the field an MCP
        // client reads to decide the server speaks the EMA profile.
        let Json(m) = authorization_server(State(cfg_with_issuer())).await;
        assert_eq!(
            m.authorization_grant_profiles_supported,
            vec![ID_JAG_GRANT_PROFILE]
        );
        let v = serde_json::to_value(&m).expect("metadata serializes");
        assert_eq!(
            v["authorization_grant_profiles_supported"],
            serde_json::json!(["urn:ietf:params:oauth:grant-profile:id-jag"])
        );
    }

    #[tokio::test]
    async fn test_metadata_omits_grant_profiles_field_without_issuers() {
        // Absent, not an empty array: an empty list would still claim
        // the server speaks grant profiles.
        let Json(m) = authorization_server(State(cfg())).await;
        let v = serde_json::to_value(&m).expect("metadata serializes");
        assert!(
            v.get("authorization_grant_profiles_supported").is_none(),
            "field must be absent without trusted issuers: {v}"
        );
    }
}
