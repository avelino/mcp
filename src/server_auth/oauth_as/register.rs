//! POST /register — Dynamic Client Registration (RFC 7591).
//!
//! A public client (Claude.ai, ChatGPT, Cursor) calls this once to
//! get a `client_id`. We do not issue `client_secret` because PKCE
//! replaces it for public clients.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};

use crate::auth::oauth_primitives::generate_random_string;

use super::redirect_uri;
use super::types::RegisteredClient;
use super::{AsState, OAuthAsConfig};

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    pub client_id_issued_at: u64,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RegistrationError {
    pub error: &'static str,
    pub error_description: String,
}

pub struct AppCtx {
    pub config: Arc<OAuthAsConfig>,
    pub state: Arc<AsState>,
}

pub async fn register(
    State(ctx): State<Arc<AppCtx>>,
    Json(req): Json<RegistrationRequest>,
) -> Result<Json<RegistrationResponse>, (StatusCode, Json<RegistrationError>)> {
    if req.redirect_uris.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(RegistrationError {
                error: "invalid_redirect_uri",
                error_description: "redirect_uris must not be empty".to_string(),
            }),
        ));
    }

    for uri in &req.redirect_uris {
        if let Err(e) = redirect_uri::validate(uri, &ctx.config.redirect_uri_allowlist) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(RegistrationError {
                    error: "invalid_redirect_uri",
                    error_description: e.to_string(),
                }),
            ));
        }
    }

    let grant_types = req.grant_types.unwrap_or_else(|| {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    });

    // We only ever support these two grants. Reject unknown values
    // explicitly rather than silently accepting them — clients that
    // expect e.g. `client_credentials` should fail at registration,
    // not at first /token call.
    for g in &grant_types {
        if g != "authorization_code" && g != "refresh_token" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(RegistrationError {
                    error: "invalid_client_metadata",
                    error_description: format!("unsupported grant_type: {g}"),
                }),
            ));
        }
    }

    // RFC 7591 metadata fields we honor by validating against our
    // single supported value. Anything else is operator-visible
    // misconfiguration in the client, not something to silently
    // accept.
    if let Some(response_types) = &req.response_types {
        for r in response_types {
            if r != "code" {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(RegistrationError {
                        error: "invalid_client_metadata",
                        error_description: format!("unsupported response_type: {r}"),
                    }),
                ));
            }
        }
    }
    if let Some(method) = &req.token_endpoint_auth_method {
        if method != "none" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(RegistrationError {
                    error: "invalid_client_metadata",
                    error_description: format!(
                        "token_endpoint_auth_method must be 'none' (PKCE-only public clients): got {method}"
                    ),
                }),
            ));
        }
    }

    let client_id = format!("mcp_{}", generate_random_string(32));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let registered = RegisteredClient {
        client_id: client_id.clone(),
        client_name: req.client_name,
        redirect_uris: req.redirect_uris.clone(),
        grant_types: grant_types.clone(),
        created_at_unix: now,
    };

    if let Err(e) = ctx.state.register_client(registered) {
        // Capacity error from the AS state — surface as a 503 so the
        // client backs off rather than retrying immediately.
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(RegistrationError {
                error: "server_error",
                error_description: e.to_string(),
            }),
        ));
    }

    // Persist the new registration. A failure here logs but doesn't
    // refuse the registration: the client is already in memory and
    // the operator can recover later.
    if let Err(e) = super::store::save(&ctx.state) {
        tracing::warn!(
            error = format!("{e:#}"),
            "failed to persist AS state after register"
        );
    }

    Ok(Json(RegistrationResponse {
        client_id,
        client_id_issued_at: now,
        redirect_uris: req.redirect_uris,
        grant_types,
        token_endpoint_auth_method: "none",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(allowlist: Vec<String>) -> Arc<AppCtx> {
        Arc::new(AppCtx {
            config: Arc::new(OAuthAsConfig {
                issuer_url: "https://mcp.example.com".to_string(),
                jwt_secret: "x".repeat(32),
                trusted_user_header: "x-forwarded-user".to_string(),
                trusted_groups_header: "x-forwarded-groups".to_string(),
                trusted_source_cidrs: vec!["127.0.0.1/32".to_string()],
                access_token_ttl_seconds: 3600,
                refresh_token_ttl_seconds: 2_592_000,
                authorization_code_ttl_seconds: 60,
                scopes_supported: vec![],
                redirect_uri_allowlist: allowlist,
                injected_roles: vec![],
            }),
            state: Arc::new(AsState::default()),
        })
    }

    use super::super::test_helpers::InlineSaveGuard;

    #[tokio::test]
    async fn test_register_emits_client_id() {
        let _g = InlineSaveGuard::acquire();
        let ctx = ctx_with(vec!["https://claude.ai/api/mcp/auth_callback".to_string()]);
        let res = register(
            State(ctx),
            Json(RegistrationRequest {
                client_name: Some("Claude".to_string()),
                redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
                grant_types: None,
                response_types: None,
                token_endpoint_auth_method: None,
            }),
        )
        .await
        .unwrap();
        assert!(res.client_id.starts_with("mcp_"));
        assert_eq!(res.token_endpoint_auth_method, "none");
    }

    #[tokio::test]
    async fn test_register_rejects_uri_outside_allowlist() {
        let _g = InlineSaveGuard::acquire();
        let ctx = ctx_with(vec!["https://claude.ai/api/mcp/auth_callback".to_string()]);
        let err = register(
            State(ctx),
            Json(RegistrationRequest {
                client_name: None,
                redirect_uris: vec!["https://attacker.example.com/cb".to_string()],
                grant_types: None,
                response_types: None,
                token_endpoint_auth_method: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "invalid_redirect_uri");
    }

    #[tokio::test]
    async fn test_register_rejects_empty_redirect_uris() {
        let _g = InlineSaveGuard::acquire();
        let ctx = ctx_with(vec!["https://claude.ai/api/mcp/auth_callback".to_string()]);
        let err = register(
            State(ctx),
            Json(RegistrationRequest {
                client_name: None,
                redirect_uris: vec![],
                grant_types: None,
                response_types: None,
                token_endpoint_auth_method: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_rejects_unsupported_grant_type() {
        let _g = InlineSaveGuard::acquire();
        let ctx = ctx_with(vec!["https://claude.ai/api/mcp/auth_callback".to_string()]);
        let err = register(
            State(ctx),
            Json(RegistrationRequest {
                client_name: None,
                redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
                grant_types: Some(vec!["client_credentials".to_string()]),
                response_types: None,
                token_endpoint_auth_method: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "invalid_client_metadata");
    }

    #[tokio::test]
    async fn test_register_isolates_clients() {
        // Two separate registrations must produce distinct client_ids
        // and independent redirect_uri lists, so a flow started with
        // client A cannot be redirected through B's URIs.
        let _g = InlineSaveGuard::acquire();
        let ctx = ctx_with(vec![
            "https://claude.ai/api/mcp/auth_callback".to_string(),
            "https://chat.openai.com/aip/*".to_string(),
        ]);
        let a = register(
            State(ctx.clone()),
            Json(RegistrationRequest {
                client_name: Some("A".to_string()),
                redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
                grant_types: None,
                response_types: None,
                token_endpoint_auth_method: None,
            }),
        )
        .await
        .unwrap();
        let b = register(
            State(ctx.clone()),
            Json(RegistrationRequest {
                client_name: Some("B".to_string()),
                redirect_uris: vec!["https://chat.openai.com/aip/g-xyz/oauth/callback".to_string()],
                grant_types: None,
                response_types: None,
                token_endpoint_auth_method: None,
            }),
        )
        .await
        .unwrap();
        assert_ne!(a.client_id, b.client_id);
        let stored_a = ctx.state.get_client(&a.client_id).unwrap();
        let stored_b = ctx.state.get_client(&b.client_id).unwrap();
        assert!(stored_a
            .redirect_uris
            .iter()
            .all(|u| u.starts_with("https://claude.ai")));
        assert!(stored_b
            .redirect_uris
            .iter()
            .all(|u| u.starts_with("https://chat.openai.com")));
    }
}
