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

use super::OAuthAsConfig;

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
    Json(AuthorizationServerMetadata {
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        registration_endpoint: format!("{issuer}/register"),
        scopes_supported: cfg.scopes_supported.clone(),
        // PKCE S256 only — `plain` is intentionally absent. OAuth 2.1
        // mandates this and so does the MCP authorization spec.
        code_challenge_methods_supported: vec!["S256"],
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        // PKCE replaces client authentication for public clients —
        // Claude.ai and other MCP-aware clients are public clients.
        token_endpoint_auth_methods_supported: vec!["none"],
        issuer,
    })
}

#[cfg(test)]
mod tests {
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
}
