//! POST /token — exchanges authorization codes (and refresh tokens)
//! for JWT access tokens. Validates PKCE S256 against the verifier,
//! issues fresh refresh tokens with rotation, and signs JWTs with
//! claims that the matching `OAuthAsAuth` provider knows how to
//! verify.
//!
//! It also serves the `jwt-bearer` grant of Enterprise Managed
//! Authorization, where an identity assertion from a trusted identity
//! provider takes the place of the whole interactive flow. That arm issues
//! no refresh token: Claude presents a new assertion instead.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::Json, Form};
use serde::{Deserialize, Serialize};

use crate::auth::oauth_primitives::{generate_random_string, s256_challenge};

use super::jwt;
use super::register::AppCtx;
use super::types::{IssuedRefreshToken, JwtClaims};

/// The ID-JAG grant of Enterprise Managed Authorization (RFC 7523,
/// draft-ietf-oauth-identity-assertion-authz-grant).
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

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
    /// The identity assertion of the `jwt-bearer` grant.
    #[serde(default)]
    pub assertion: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8707. Claude always sends it; an identity provider forwards it
    /// only when it supports doing so, so it is optional here.
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    /// Absent for the `jwt-bearer` grant, which Claude never refreshes —
    /// it presents a new assertion instead. Skipped rather than null so
    /// the interactive flow's JSON stays byte-for-byte what it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
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

/// Sign an access token for `subject`. `aud` is the client, which is what
/// `OAuthAsAuth` pins when the token comes back on `/mcp`.
fn mint_access_token(
    ctx: &AppCtx,
    client_id: &str,
    subject: &str,
    roles: &[String],
) -> Result<String, (StatusCode, Json<TokenError>)> {
    let now_ts = now();
    let claims = JwtClaims {
        iss: ctx.config.issuer_url.trim_end_matches('/').to_string(),
        aud: client_id.to_string(),
        sub: subject.to_string(),
        groups: merge_roles(roles, &ctx.config.injected_roles),
        iat: now_ts,
        nbf: now_ts,
        exp: now_ts + ctx.config.access_token_ttl_seconds,
        jti: generate_random_string(16),
    };

    jwt::sign(&claims, ctx.config.jwt_secret.as_bytes()).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            e.to_string(),
        )
    })
}

fn issue_jwt(
    ctx: &AppCtx,
    client_id: &str,
    subject: &str,
    roles: &[String],
) -> Result<(String, String, u64), (StatusCode, Json<TokenError>)> {
    let access_token = mint_access_token(ctx, client_id, subject, roles)?;

    let now_ts = now();
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
        JWT_BEARER_GRANT => handle_jwt_bearer(&ctx, req).await,
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
        refresh_token: Some(refresh),
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
        refresh_token: Some(new_token),
        scope: None,
    }))
}

/// The `jwt-bearer` grant of Enterprise Managed Authorization: an identity
/// assertion signed by a trusted identity provider, exchanged for an access
/// token with no consent screen in the way.
///
/// Answered here, at the `token_endpoint` URL itself — Claude does not
/// follow redirects on this request.
async fn handle_jwt_bearer(
    ctx: &AppCtx,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<TokenError>)> {
    let client_id = req.client_id.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        )
    })?;
    let assertion = req.assertion.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "assertion is required",
        )
    })?;

    // Before the assertion is touched, because check 6 inside `validate`
    // only compares the assertion's `client_id` claim with the one on this
    // request — both supplied by the caller, so that equality on its own
    // says nothing about who is asking. This lookup is what makes the
    // client real; it also covers an empty `client_id`, which would
    // otherwise match an empty claim.
    //
    // Deliberately not checked against the client's `grant_types`: a client
    // from `staticClients` is registered with that list empty, and no
    // request-time path reads it, so gating here would refuse every
    // enterprise client there is.
    if ctx.state.get_client(&client_id).is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id is not a registered client".to_string(),
        ));
    }

    // RFC 8707. Absent is ordinary — Claude always sends it, an identity
    // provider forwards it only when it supports doing so — so its absence
    // is not a refusal. Present, it has to name this server: a token asked
    // for on behalf of someone else's resource is not ours to hand out.
    // Trimmed on both sides, like every other comparison against the issuer
    // URL, because the metadata publishes the trimmed form.
    if let Some(resource) = req.resource.as_deref().filter(|r| !r.is_empty()) {
        if resource.trim_end_matches('/') != ctx.config.issuer_url.trim_end_matches('/') {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "resource does not name this authorization server".to_string(),
            ));
        }
    }

    // Every refusal from here is `invalid_grant`, per RFC 7523 §3. The
    // description is the validator's own, which is already written for a
    // client: it never says which key, which issuer, or what the replay
    // cache holds.
    let validated =
        super::assertion::validate(&assertion, &client_id, &ctx.config, &ctx.jwks, &ctx.state)
            .await
            .map_err(|why| err(StatusCode::BAD_REQUEST, "invalid_grant", why))?;

    let access_token = mint_access_token(ctx, &client_id, &validated.subject, &validated.roles)?;

    // No `store::save`: this grant writes nothing persisted. The redeemed
    // `jti` lives in memory by design, and no refresh token was minted.
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        // Claude reads this to know when to exchange a fresh assertion, and
        // it is the whole offboarding window: a user removed from the
        // customer's organization stops getting assertions, but a token
        // already issued stays valid until it expires.
        expires_in: ctx.config.access_token_ttl_seconds,
        // Claude does not use a refresh token from this grant, so none is
        // issued. The interactive flow keeps issuing them.
        refresh_token: None,
        scope: req.scope,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oauth_primitives::generate_pkce;
    use crate::server_auth::oauth_as::types::{AuthorizationCode, RegisteredClient};

    use super::super::test_helpers::InlineSaveGuard;

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
            trusted_issuers: vec![],
            static_clients: vec![],
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
        Arc::new(AppCtx {
            config,
            state,
            jwks: Arc::new(JwksCache::new(reqwest::Client::new())),
        })
    }

    #[tokio::test]
    async fn test_authorization_code_grant_happy_path() {
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(!resp.access_token.is_empty());
        assert!(resp.refresh_token.as_deref().is_some_and(|t| !t.is_empty()));

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
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_code_replay_rejected() {
        let _g = InlineSaveGuard::acquire();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let req = || TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("the-code".to_string()),
            redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
            client_id: Some("client-A".to_string()),
            code_verifier: Some(verifier.clone()),
            refresh_token: None,
            assertion: None,
            scope: None,
            resource: None,
        };
        // First use succeeds.
        let _ = token(State(ctx.clone()), Form(req())).await.unwrap();
        // Replay must fail.
        let err = token(State(ctx), Form(req())).await.unwrap_err();
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_redirect_uri_mismatch_rejected() {
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
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
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_grant_rotates_token() {
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap();
        let first_refresh = initial.refresh_token.clone().unwrap();

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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap();

        assert_ne!(
            refreshed.refresh_token.as_deref(),
            Some(first_refresh.as_str()),
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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await;
        assert!(replay.is_err());
    }

    #[tokio::test]
    async fn test_refresh_grant_rejects_cross_client_replay() {
        // Privilege escalation: refresh token from client-A must NOT
        // mint a token under client-B credentials.
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
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
                refresh_token: initial.refresh_token.clone(),
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await;
        assert!(attempt.is_err());
    }

    #[tokio::test]
    async fn test_unsupported_grant_type_rejected() {
        let _g = InlineSaveGuard::acquire();
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
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "unsupported_grant_type");
    }

    // ---- jwt-bearer (ID-JAG) grant ---------------------------------------

    use super::super::assertion::ID_JAG_TYP;
    use super::super::config::{StaticClient, TrustedIssuer};
    use super::super::jwks::JwksCache;
    use super::super::test_helpers::{
        ec_encoding_key, ec_public_jwk, start_fake_issuer, FakeIssuer, TEST_EC_PKCS8_B64,
    };

    use jsonwebtoken::{encode, get_current_timestamp, Algorithm, Header};
    use serde_json::json;

    const EMA_CLIENT: &str = "claude-enterprise";

    /// An AS that trusts a live fake issuer and knows `EMA_CLIENT` from
    /// config — the shape `serverAuth.oauthAs.staticClients` produces at
    /// boot, both of its lists empty on purpose.
    async fn ema_ctx() -> (FakeIssuer, Arc<AppCtx>) {
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
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
            trusted_issuers: vec![TrustedIssuer {
                issuer: fake.base.clone(),
                tenant_id: None,
                allowed_email_domains: vec!["example.com".to_string()],
                roles: vec!["ema-user".to_string()],
            }],
            static_clients: vec![StaticClient {
                client_id: EMA_CLIENT.to_string(),
            }],
        });
        let state = Arc::new(super::super::AsState::default());
        state.set_static_clients(vec![RegisteredClient {
            client_id: EMA_CLIENT.to_string(),
            client_name: None,
            redirect_uris: vec![],
            grant_types: vec![],
            created_at_unix: 0,
        }]);
        let ctx = Arc::new(AppCtx {
            config,
            state,
            jwks: Arc::new(JwksCache::new(reqwest::Client::new())),
        });
        (fake, ctx)
    }

    /// A well-formed ID-JAG payload. `groups` is in it on purpose: another
    /// party's idea of a user's privileges must never reach the token.
    fn ema_claims(issuer: &str) -> serde_json::Value {
        let now = get_current_timestamp();
        json!({
            "iss": issuer,
            "aud": "https://mcp.example.com",
            "sub": "opaque-idp-subject",
            "client_id": EMA_CLIENT,
            "email": "Alice@Example.com",
            // Fresh per assertion, so a test can exchange more than once.
            "jti": generate_random_string(16),
            "iat": now,
            "exp": now + 300,
            "groups": ["admins"],
        })
    }

    fn sign_assertion(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(ID_JAG_TYP.to_string());
        header.kid = Some("k1".to_string());
        encode(&header, claims, &ec_encoding_key(TEST_EC_PKCS8_B64)).unwrap()
    }

    fn ema_request(assertion: String, client_id: &str) -> TokenRequest {
        TokenRequest {
            grant_type: JWT_BEARER_GRANT.to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some(client_id.to_string()),
            code_verifier: None,
            refresh_token: None,
            assertion: Some(assertion),
            scope: None,
            resource: None,
        }
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_issues_access_token_without_refresh_token() {
        let (fake, ctx) = ema_ctx().await;
        let mut req = ema_request(sign_assertion(&ema_claims(&fake.base)), EMA_CLIENT);
        req.scope = Some("mcp".to_string());

        let resp = token(State(ctx), Form(req)).await.unwrap();

        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(!resp.access_token.is_empty());
        assert_eq!(resp.scope.as_deref(), Some("mcp"));

        // The wire shape is the contract. Claude reads `expires_in` to know
        // when to exchange again, and the documentation says it never uses a
        // refresh token from this grant — so none is minted, which also
        // keeps this path off the persisted refresh-token map entirely.
        let body = serde_json::to_value(&resp.0).unwrap();
        assert_eq!(body["expires_in"], 3600);
        assert!(
            body.get("refresh_token").is_none(),
            "the jwt-bearer grant must not put a refresh token on the wire: {body}"
        );
    }

    #[tokio::test]
    async fn test_jwt_bearer_token_carries_config_roles_and_email_subject() {
        let (fake, ctx) = ema_ctx().await;
        let resp = token(
            State(ctx.clone()),
            Form(ema_request(
                sign_assertion(&ema_claims(&fake.base)),
                EMA_CLIENT,
            )),
        )
        .await
        .unwrap();

        let claims = jwt::verify(
            &resp.access_token,
            ctx.config.jwt_secret.as_bytes(),
            "https://mcp.example.com",
            EMA_CLIENT,
        )
        .unwrap();

        // Identity is the email, lowercased: the assertion's `sub` is opaque
        // under each issuer and resolves against nothing on this side.
        assert_eq!(claims.sub, "alice@example.com");
        // Roles are the issuer entry's, plus whatever this operator injects.
        assert!(claims.groups.contains(&"ema-user".to_string()));
        assert!(claims.groups.contains(&"oauth-user".to_string()));
        assert!(
            !claims.groups.contains(&"admins".to_string()),
            "a group claim minted by someone else's IdP became a role: {:?}",
            claims.groups
        );
    }

    #[tokio::test]
    async fn test_jwt_bearer_rejects_unknown_client_id() {
        // The assertion names the same unregistered client, so check 6 of
        // the assertion validation would pass: both sides of that equality
        // come from the caller. Only the registration lookup refuses this.
        let (fake, ctx) = ema_ctx().await;
        let mut claims = ema_claims(&fake.base);
        claims["client_id"] = json!("never-registered");

        let e = token(
            State(ctx),
            Form(ema_request(sign_assertion(&claims), "never-registered")),
        )
        .await
        .unwrap_err();

        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(e.1.error, "invalid_grant");
        // And refused before any key fetch, so an unregistered caller cannot
        // make this AS reach out to an issuer on its behalf.
        assert_eq!(fake.discovery_hits(), 0);
    }

    #[tokio::test]
    async fn test_jwt_bearer_failure_is_invalid_grant() {
        // One case per class of refusal the validation produces, so the
        // mapping cannot be right for one and wrong for the rest. RFC 7523
        // §3 wants `invalid_grant` for every one of them.
        let (fake, ctx) = ema_ctx().await;
        let now = get_current_timestamp();

        let expired = {
            let mut c = ema_claims(&fake.base);
            c["iat"] = json!(now - 600);
            c["exp"] = json!(now - 120);
            sign_assertion(&c)
        };
        let wrong_audience = {
            let mut c = ema_claims(&fake.base);
            c["aud"] = json!("https://other-mcp.example.com");
            sign_assertion(&c)
        };
        let wrong_email_domain = {
            let mut c = ema_claims(&fake.base);
            c["email"] = json!("alice@notexample.com");
            sign_assertion(&c)
        };
        let wrong_typ = {
            let mut header = Header::new(Algorithm::ES256);
            header.typ = Some("JWT".to_string());
            header.kid = Some("k1".to_string());
            encode(
                &header,
                &ema_claims(&fake.base),
                &ec_encoding_key(TEST_EC_PKCS8_B64),
            )
            .unwrap()
        };
        let untrusted_issuer = sign_assertion(&ema_claims("https://elsewhere.example.com"));
        let malformed = "not-a-jwt".to_string();

        for assertion in [
            expired,
            wrong_audience,
            wrong_email_domain,
            wrong_typ,
            untrusted_issuer,
            malformed,
        ] {
            let e = token(State(ctx.clone()), Form(ema_request(assertion, EMA_CLIENT)))
                .await
                .unwrap_err();
            assert_eq!(e.0, StatusCode::BAD_REQUEST);
            assert_eq!(e.1.error, "invalid_grant", "{}", e.1.error_description);
        }
    }

    #[tokio::test]
    async fn test_jwt_bearer_replay_is_refused() {
        // The same assertion twice: the second exchange has to lose. This is
        // the one place the replay cache is reachable through a handler.
        let (fake, ctx) = ema_ctx().await;
        let assertion = sign_assertion(&ema_claims(&fake.base));

        let _ = token(
            State(ctx.clone()),
            Form(ema_request(assertion.clone(), EMA_CLIENT)),
        )
        .await
        .unwrap();
        let e = token(State(ctx), Form(ema_request(assertion, EMA_CLIENT)))
            .await
            .unwrap_err();
        assert_eq!(e.1.error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_jwt_bearer_without_an_assertion_is_a_bad_request() {
        let (_fake, ctx) = ema_ctx().await;
        let mut req = ema_request(String::new(), EMA_CLIENT);
        req.assertion = None;

        let e = token(State(ctx), Form(req)).await.unwrap_err();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(e.1.error, "invalid_request");
    }

    #[tokio::test]
    async fn test_jwt_bearer_accepts_the_request_with_or_without_resource() {
        // RFC 8707. Claude always sends it; an identity provider forwards it
        // only when it can, so both shapes reach this endpoint in the field
        // and refusing either would break a whole class of deploys.
        let (fake, ctx) = ema_ctx().await;

        let absent = ema_request(sign_assertion(&ema_claims(&fake.base)), EMA_CLIENT);
        assert!(token(State(ctx.clone()), Form(absent)).await.is_ok());

        let mut present = ema_request(sign_assertion(&ema_claims(&fake.base)), EMA_CLIENT);
        present.resource = Some("https://mcp.example.com".to_string());
        assert!(token(State(ctx.clone()), Form(present)).await.is_ok());

        // The metadata publishes the trimmed form, so a caller that adds a
        // slash is not naming a different server — same trimming as the
        // `aud` check and the metadata that produced the value.
        let mut trailing = ema_request(sign_assertion(&ema_claims(&fake.base)), EMA_CLIENT);
        trailing.resource = Some("https://mcp.example.com/".to_string());
        assert!(token(State(ctx), Form(trailing)).await.is_ok());
    }

    #[tokio::test]
    async fn test_jwt_bearer_refuses_a_resource_naming_another_server() {
        // Audience binding: a token asked for on behalf of a different
        // resource server is not one this AS gets to hand out.
        let (fake, ctx) = ema_ctx().await;
        let mut req = ema_request(sign_assertion(&ema_claims(&fake.base)), EMA_CLIENT);
        req.resource = Some("https://other-mcp.example.com".to_string());

        let e = token(State(ctx), Form(req)).await.unwrap_err();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(e.1.error, "invalid_grant");
        // Settled before the assertion is validated, so a request that was
        // never going to be honoured does not burn the assertion's `jti`.
        assert_eq!(fake.discovery_hits(), 0);
    }

    #[tokio::test]
    async fn test_jwt_bearer_refuses_an_assertion_bound_to_another_resource() {
        // The signed `resource` claim and the `resource` form parameter
        // answer the same question, so both are compared against one
        // identifier: this server's, the value
        // `/.well-known/oauth-protected-resource` publishes. That is what
        // makes the two disagreeing unredeemable without a third
        // comparison between them — whichever of the pair is not this
        // server is the one refused.
        let (fake, ctx) = ema_ctx().await;

        // Signed for someone else, asked for on behalf of this server.
        let mut claims = ema_claims(&fake.base);
        claims["resource"] = json!("https://other-mcp.example.com");
        let mut req = ema_request(sign_assertion(&claims), EMA_CLIENT);
        req.resource = Some("https://mcp.example.com".to_string());
        let e = token(State(ctx.clone()), Form(req)).await.unwrap_err();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(e.1.error, "invalid_grant");
        assert_eq!(
            e.1.error_description,
            "assertion resource is not this protected resource"
        );

        // Signed for this server, asked for on behalf of someone else.
        // Refused by the form-parameter check, which is ahead of the
        // assertion and so never reaches the issuer.
        let mut claims = ema_claims(&fake.base);
        claims["resource"] = json!("https://mcp.example.com");
        let mut req = ema_request(sign_assertion(&claims), EMA_CLIENT);
        req.resource = Some("https://other-mcp.example.com".to_string());
        let e = token(State(ctx.clone()), Form(req)).await.unwrap_err();
        assert_eq!(e.1.error, "invalid_grant");

        // Both naming this server is the ordinary case and still works.
        let mut claims = ema_claims(&fake.base);
        claims["resource"] = json!("https://mcp.example.com");
        let mut req = ema_request(sign_assertion(&claims), EMA_CLIENT);
        req.resource = Some("https://mcp.example.com".to_string());
        assert!(token(State(ctx), Form(req)).await.is_ok());
    }

    #[tokio::test]
    async fn test_token_form_accepts_resource_and_ignores_unknown_fields() {
        // Claude's POST carries `resource`, and a parser strict about an
        // unrecognised parameter would turn any future extra field into a
        // failed exchange. Driven through the real extractor, because that
        // is where strictness would live.
        use axum::extract::FromRequest;

        let body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
                    &assertion=a.b.c&client_id=claude-enterprise&scope=mcp\
                    &resource=https%3A%2F%2Fmcp.example.com&something_unforeseen=1";
        let request = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .unwrap();

        let Form(parsed) = Form::<TokenRequest>::from_request(request, &())
            .await
            .unwrap();
        assert_eq!(parsed.grant_type, JWT_BEARER_GRANT);
        assert_eq!(parsed.assertion.as_deref(), Some("a.b.c"));
        assert_eq!(parsed.scope.as_deref(), Some("mcp"));
        assert_eq!(parsed.resource.as_deref(), Some("https://mcp.example.com"));
    }

    #[tokio::test]
    async fn test_authorization_code_flow_is_unchanged() {
        // Making `refresh_token` optional is only safe if the interactive
        // flow's JSON is what Claude.ai already receives: same keys, same
        // count, refresh token still there.
        let _g = InlineSaveGuard::acquire();
        let (verifier, challenge) = generate_pkce();
        let ctx = ctx_with_code("the-code", &challenge);
        let resp = token(
            State(ctx),
            Form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("the-code".to_string()),
                redirect_uri: Some("https://claude.ai/api/mcp/auth_callback".to_string()),
                client_id: Some("client-A".to_string()),
                code_verifier: Some(verifier),
                refresh_token: None,
                assertion: None,
                scope: None,
                resource: None,
            }),
        )
        .await
        .unwrap();

        let body = serde_json::to_value(&resp.0).unwrap();
        assert!(body["access_token"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
        assert_eq!(body["scope"], "mcp");
        assert!(
            body["refresh_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "the interactive flow still issues refresh tokens: {body}"
        );
        assert_eq!(
            body.as_object().unwrap().len(),
            5,
            "the interactive flow's JSON gained or lost a field: {body}"
        );
    }
}
