//! POST /token — exchanges authorization codes (and refresh tokens)
//! for JWT access tokens. Validates PKCE S256 against the verifier,
//! issues fresh refresh tokens with rotation, and signs JWTs with
//! claims that the matching `OAuthAsAuth` provider knows how to
//! verify.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::Json, Form};
use serde::{Deserialize, Serialize};

use crate::auth::oauth_primitives::{generate_random_string, s256_challenge};

use super::jwt;
use super::register::AppCtx;
use super::types::{IssuedRefreshToken, JwtClaims};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenError {
    pub error: &'static str,
    pub error_description: String,
}

fn err(
    code: StatusCode,
    kind: &'static str,
    msg: impl Into<String>,
) -> (StatusCode, Json<TokenError>) {
    (
        code,
        Json(TokenError {
            error: kind,
            error_description: msg.into(),
        }),
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn merge_roles(roles: &[String], injected: &[String]) -> Vec<String> {
    let mut out = roles.to_vec();
    for r in injected {
        if !out.contains(r) {
            out.push(r.clone());
        }
    }
    out
}

fn issue_jwt(
    ctx: &AppCtx,
    client_id: &str,
    subject: &str,
    roles: &[String],
) -> Result<(String, String, u64), (StatusCode, Json<TokenError>)> {
    let now_ts = now();
    let access_exp = now_ts + ctx.config.access_token_ttl_seconds;

    let claims = JwtClaims {
        iss: ctx.config.issuer_url.trim_end_matches('/').to_string(),
        aud: client_id.to_string(),
        sub: subject.to_string(),
        groups: merge_roles(roles, &ctx.config.injected_roles),
        iat: now_ts,
        nbf: now_ts,
        exp: access_exp,
        jti: generate_random_string(16),
    };

    let access_token = jwt::sign(&claims, ctx.config.jwt_secret.as_bytes()).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            e.to_string(),
        )
    })?;

    let refresh_token = generate_random_string(48);
    ctx.state.put_refresh(IssuedRefreshToken {
        token: refresh_token.clone(),
        client_id: client_id.to_string(),
        subject: subject.to_string(),
        roles: roles.to_vec(),
        expires_at_unix: now_ts + ctx.config.refresh_token_ttl_seconds,
    });

    Ok((
        access_token,
        refresh_token,
        ctx.config.access_token_ttl_seconds,
    ))
}

pub async fn token(
    State(ctx): State<Arc<AppCtx>>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<TokenError>)> {
    match req.grant_type.as_str() {
        "authorization_code" => handle_code(&ctx, req).await,
        "refresh_token" => handle_refresh(&ctx, req).await,
        other => Err(err(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("grant_type {other} is not supported"),
        )),
    }
}

async fn handle_code(
    ctx: &AppCtx,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<TokenError>)> {
    let code = req.code.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required",
        )
    })?;
    let redirect_uri = req.redirect_uri.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        )
    })?;
    let client_id = req.client_id.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        )
    })?;
    let verifier = req.code_verifier.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier is required (PKCE S256)",
        )
    })?;

    let entry = ctx.state.consume_code(&code).ok_or_else(|| {
        // Same response shape for unknown / used / expired — a
        // distinguishable error would let an attacker tell which
        // case they hit.
        err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code is invalid, expired, or already used".to_string(),
        )
    })?;

    if entry.client_id != client_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match authorization code".to_string(),
        ));
    }
    if entry.redirect_uri != redirect_uri {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match authorization code".to_string(),
        ));
    }

    // Recompute S256(verifier) and compare against the stored
    // challenge. Constant-time comparison is overkill for non-secret
    // identifiers, but cheap to do via `subtle` if we ever add it.
    let computed = s256_challenge(&verifier);
    if computed != entry.code_challenge {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verifier does not match challenge".to_string(),
        ));
    }

    let (access, refresh, expires_in) = issue_jwt(ctx, &client_id, &entry.subject, &entry.roles)?;

    if let Err(e) = super::store::save(&ctx.state) {
        tracing::warn!(
            error = format!("{e:#}"),
            "failed to persist AS state after token issuance"
        );
    }

    Ok(Json(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in,
        refresh_token: refresh,
        scope: entry.scope,
    }))
}

async fn handle_refresh(
    ctx: &AppCtx,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<TokenError>)> {
    let old = req.refresh_token.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        )
    })?;
    let client_id = req.client_id.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        )
    })?;

    // Snapshot subject + roles BEFORE rotating, so the new JWT carries
    // the same identity. We bind to client_id to detect cross-client
    // replay.
    let prev_view = match ctx
        .state
        .snapshot_persisted()
        .refresh_tokens
        .get(&old)
        .cloned()
    {
        Some(t) => t,
        None => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token is invalid".to_string(),
            ));
        }
    };
    if prev_view.client_id != client_id {
        // Privilege escalation guard: refresh tokens are bound to
        // the client that received them. Same generic error to avoid
        // probing.
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token is invalid".to_string(),
        ));
    }

    let new_token = generate_random_string(48);
    let new_entry = IssuedRefreshToken {
        token: new_token.clone(),
        client_id: client_id.clone(),
        subject: prev_view.subject.clone(),
        roles: prev_view.roles.clone(),
        expires_at_unix: now() + ctx.config.refresh_token_ttl_seconds,
    };

    if let Err(_e) = ctx.state.rotate_refresh(&old, &client_id, new_entry) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token is invalid".to_string(),
        ));
    }

    // Mint the JWT after rotation succeeded.
    let now_ts = now();
    let claims = JwtClaims {
        iss: ctx.config.issuer_url.trim_end_matches('/').to_string(),
        aud: client_id.clone(),
        sub: prev_view.subject.clone(),
        groups: merge_roles(&prev_view.roles, &ctx.config.injected_roles),
        iat: now_ts,
        nbf: now_ts,
        exp: now_ts + ctx.config.access_token_ttl_seconds,
        jti: generate_random_string(16),
    };
    let access = jwt::sign(&claims, ctx.config.jwt_secret.as_bytes()).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            e.to_string(),
        )
    })?;

    if let Err(e) = super::store::save(&ctx.state) {
        tracing::warn!(
            error = format!("{e:#}"),
            "failed to persist AS state after refresh"
        );
    }

    Ok(Json(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ctx.config.access_token_ttl_seconds,
        refresh_token: new_token,
        scope: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oauth_primitives::generate_pkce;
    use crate::server_auth::oauth_as::types::{AuthorizationCode, RegisteredClient};

    fn save_disabled() -> impl Drop {
        struct G;
        std::env::set_var(
            "MCP_AUTH_SERVER_CONFIG",
            r#"{"clients":{},"refresh_tokens":{}}"#,
        );
        impl Drop for G {
            fn drop(&mut self) {
                std::env::remove_var("MCP_AUTH_SERVER_CONFIG");
            }
        }
        G
    }

    fn ctx_with_code(code: &str, challenge: &str) -> Arc<AppCtx> {
        let config = Arc::new(super::super::OAuthAsConfig {
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
        });
        let state = Arc::new(super::super::AsState::default());
        state
            .register_client(RegisteredClient {
                client_id: "client-A".to_string(),
                client_name: None,
                redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                created_at_unix: 0,
            })
            .unwrap();
        state.put_code(AuthorizationCode {
            code: code.to_string(),
            client_id: "client-A".to_string(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".to_string(),
            code_challenge: challenge.to_string(),
            scope: Some("mcp".to_string()),
            subject: "alice".to_string(),
            roles: vec!["dev".to_string()],
            expires_at_unix: now() + 60,
        });
        Arc::new(AppCtx { config, state })
    }

    #[tokio::test]
    async fn test_authorization_code_grant_happy_path() {
        let _g = save_disabled();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let resp = token(
            State(ctx.clone()),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
                client_id: Some("client-A".to_string()),
                code_verifier: Some(verifier),
                refresh_token: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(!resp.access_token.is_empty());
        assert!(!resp.refresh_token.is_empty());

        // Issued JWT must verify with the AS's secret and carry the
        // injected role.
        let claims = jwt::verify(
            &resp.access_token,
            ctx.config.jwt_secret.as_bytes(),
            "https://mcp.example.com",
            "client-A",
        )
        .unwrap();
        assert_eq!(claims.sub, "alice");
        assert!(claims.groups.contains(&"oauth-user".to_string()));
        assert!(claims.groups.contains(&"dev".to_string()));
    }

    #[tokio::test]
    async fn test_pkce_verifier_mismatch_rejected() {
        // Critical bypass guard: wrong verifier must fail.
        let _g = save_disabled();
        let (_, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let err = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
                client_id: Some("client-A".to_string()),
                code_verifier: Some("wrong-verifier".to_string()),
                refresh_token: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_code_replay_rejected() {
        let _g = save_disabled();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let req = || TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("the-code".to_string()),
            redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
            client_id: Some("client-A".to_string()),
            code_verifier: Some(verifier.clone()),
            refresh_token: None,
        };
        // First use succeeds.
        let _ = token(State(ctx.clone()), Form(req())).await.unwrap();
        // Replay must fail.
        let err = token(State(ctx), Form(req())).await.unwrap_err();
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_redirect_uri_mismatch_rejected() {
        let _g = save_disabled();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let err = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://attacker.example.com/cb".to_string()),
                client_id: Some("client-A".to_string()),
                code_verifier: Some(verifier),
                refresh_token: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_client_id_mismatch_rejected() {
        // Token confusion guard: code was issued for client-A,
        // presenting it as client-B must fail.
        let _g = save_disabled();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let err = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
                client_id: Some("client-B".to_string()),
                code_verifier: Some(verifier),
                refresh_token: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_grant_rotates_token() {
        let _g = save_disabled();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        // First, an authorization_code grant to seed a refresh token.
        let initial = token(
            State(ctx.clone()),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
                client_id: Some("client-A".to_string()),
                code_verifier: Some(verifier),
                refresh_token: None,
            }),
        )
        .await
        .unwrap();
        let first_refresh = initial.refresh_token.clone();

        // Then the refresh grant.
        let refreshed = token(
            State(ctx.clone()),
            Form(TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: Some("client-A".to_string()),
                code_verifier: None,
                refresh_token: Some(first_refresh.clone()),
            }),
        )
        .await
        .unwrap();

        assert_ne!(
            refreshed.refresh_token, first_refresh,
            "refresh token must rotate on every refresh"
        );
        // Old refresh token must be invalidated.
        let replay = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: Some("client-A".to_string()),
                code_verifier: None,
                refresh_token: Some(first_refresh),
            }),
        )
        .await;
        assert!(replay.is_err());
    }

    #[tokio::test]
    async fn test_refresh_grant_rejects_cross_client_replay() {
        // Privilege escalation: refresh token from client-A must NOT
        // mint a token under client-B credentials.
        let _g = save_disabled();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let initial = token(
            State(ctx.clone()),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
                client_id: Some("client-A".to_string()),
                code_verifier: Some(verifier),
                refresh_token: None,
            }),
        )
        .await
        .unwrap();

        let attempt = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: Some("client-B".to_string()),
                code_verifier: None,
                refresh_token: Some(initial.refresh_token.clone()),
            }),
        )
        .await;
        assert!(attempt.is_err());
    }

    #[tokio::test]
    async fn test_unsupported_grant_type_rejected() {
        let _g = save_disabled();
        let ctx = ctx_with_code("the-code", "ignored");
        let err = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "client_credentials".to_string(),
                code: None,
                redirect_uri: None,
                client_id: None,
                code_verifier: None,
                refresh_token: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "unsupported_grant_type");
    }
}
