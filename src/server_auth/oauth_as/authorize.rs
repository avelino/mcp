//! GET /authorize — entry point of the OAuth flow.
//!
//! The user has already authenticated through the upstream reverse
//! proxy (oauth2-proxy / Cloudflare Access / Pomerium), which sets
//! `X-Forwarded-User` (and optionally `X-Forwarded-Groups`). We
//! verify the request originates from the configured trusted CIDR
//! ranges, extract subject + roles, validate the OAuth params
//! (PKCE S256 mandatory), emit a one-shot authorization code, and
//! redirect to the client's `redirect_uri`.
//!
//! No HTML consent screen in v1. The user already consented at the
//! IdP step in front of `mcp serve`. Adding a second consent here is
//! noise without a security gain — that decision is documented in
//! the issue #90 plan.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};

use crate::auth::oauth_primitives::generate_random_string;
use crate::server_auth::providers::read_trusted_user;

use super::cidr::{ip_in_any, parse_all};
use super::redirect_uri;
use super::register::AppCtx;
use super::types::AuthorizationCode;

#[derive(Debug, serde::Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    #[serde(default)]
    pub scope: Option<String>,
}

fn err_response(code: StatusCode, message: &str) -> Response {
    (code, message.to_string()).into_response()
}

/// Build the redirect URI that carries the authorization code back to
/// the client, preserving the supplied `state` parameter as RFC 6749 §4.1.2 demands.
fn build_redirect(redirect_uri: &str, code: &str, state: &str) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!(
        "{redirect_uri}{separator}code={}&state={}",
        url_encode(code),
        url_encode(state)
    )
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Extract credentials from request headers — same shape as
/// `serve/http.rs::extract_credentials` so handler code reuses
/// `read_trusted_user` without new plumbing.
fn extract_creds(headers: &HeaderMap) -> crate::server_auth::Credentials {
    let mut c = crate::server_auth::Credentials::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            c.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    c
}

pub async fn authorize(
    State(ctx): State<Arc<AppCtx>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
    // 1. Anti-spoof: must come from a trusted source CIDR.
    let cidrs = match parse_all(&ctx.config.trusted_source_cidrs) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "invalid CIDR in oauthAs.trustedSourceCidrs");
            return err_response(StatusCode::INTERNAL_SERVER_ERROR, "AS misconfigured");
        }
    };
    if !ip_in_any(peer.ip(), &cidrs) {
        tracing::warn!(peer = %peer.ip(), "rejecting /authorize from untrusted source");
        return err_response(
            StatusCode::FORBIDDEN,
            "/authorize must originate from a trusted reverse proxy",
        );
    }

    // 2. PKCE method: S256 only. Never `plain`.
    if q.code_challenge_method != "S256" {
        return err_response(
            StatusCode::BAD_REQUEST,
            "code_challenge_method must be S256",
        );
    }
    if q.code_challenge.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "code_challenge is required");
    }
    if q.response_type != "code" {
        return err_response(StatusCode::BAD_REQUEST, "response_type must be 'code'");
    }

    // 3. Client must have been registered via DCR.
    let client = match ctx.state.get_client(&q.client_id) {
        Some(c) => c,
        None => return err_response(StatusCode::BAD_REQUEST, "unknown client_id"),
    };

    // 4. redirect_uri must (a) match what was registered AND (b)
    //    pass the operator allowlist. Both checks together close the
    //    open-redirect class of bugs.
    if !client.redirect_uris.contains(&q.redirect_uri) {
        return err_response(
            StatusCode::BAD_REQUEST,
            "redirect_uri does not match registered client",
        );
    }
    if let Err(e) = redirect_uri::validate(&q.redirect_uri, &ctx.config.redirect_uri_allowlist) {
        return err_response(
            StatusCode::BAD_REQUEST,
            &format!("redirect_uri rejected: {e}"),
        );
    }

    // 5. Trusted header: must be present and the user must be set.
    let creds = extract_creds(&headers);
    let (subject, roles) = match read_trusted_user(
        &creds,
        &ctx.config.trusted_user_header,
        &ctx.config.trusted_groups_header,
    ) {
        Some(t) => t,
        None => {
            return err_response(
                StatusCode::UNAUTHORIZED,
                "missing or empty trusted user header",
            )
        }
    };

    // 6. Mint a one-shot code.
    let code = generate_random_string(64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ctx.state.put_code(AuthorizationCode {
        code: code.clone(),
        client_id: q.client_id,
        redirect_uri: q.redirect_uri.clone(),
        code_challenge: q.code_challenge,
        scope: q.scope,
        subject,
        roles,
        expires_at_unix: now + ctx.config.authorization_code_ttl_seconds,
    });

    Redirect::to(&build_redirect(&q.redirect_uri, &code, &q.state)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_auth::oauth_as::types::RegisteredClient;

    fn ctx() -> Arc<AppCtx> {
        let config = Arc::new(super::super::OAuthAsConfig {
            issuer_url: "https://mcp.example.com".to_string(),
            jwt_secret: "x".repeat(32),
            trusted_user_header: "x-forwarded-user".to_string(),
            trusted_groups_header: "x-forwarded-groups".to_string(),
            trusted_source_cidrs: vec!["127.0.0.0/8".to_string()],
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
        Arc::new(AppCtx { config, state })
    }

    fn good_query() -> AuthorizeQuery {
        AuthorizeQuery {
            response_type: "code".to_string(),
            client_id: "client-A".to_string(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".to_string(),
            code_challenge: "abcXYZ-_~.123".to_string(),
            code_challenge_method: "S256".to_string(),
            state: "opaque-csrf".to_string(),
            scope: Some("mcp".to_string()),
        }
    }

    fn good_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-user", "alice".parse().unwrap());
        h.insert("x-forwarded-groups", "dev,oncall".parse().unwrap());
        h
    }

    fn loopback() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:54321".parse().unwrap())
    }
    fn external() -> ConnectInfo<SocketAddr> {
        ConnectInfo("8.8.8.8:54321".parse().unwrap())
    }

    fn parse_redirect_location(resp: Response) -> String {
        resp.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_authorize_emits_code_for_trusted_user() {
        let ctx = ctx();
        let resp = authorize(
            State(ctx.clone()),
            loopback(),
            Query(good_query()),
            good_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = parse_redirect_location(resp);
        assert!(loc.starts_with("https://claude.ai/api/mcp/auth_callback?"));
        assert!(loc.contains("code="));
        assert!(loc.contains("state=opaque-csrf"));
    }

    #[tokio::test]
    async fn test_authorize_rejects_untrusted_source() {
        // Anti-spoof guard: peer IP outside trustedSourceCidrs must
        // be rejected even when all OAuth params look correct.
        let ctx = ctx();
        let resp = authorize(State(ctx), external(), Query(good_query()), good_headers()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_authorize_rejects_pkce_plain() {
        let ctx = ctx();
        let mut q = good_query();
        q.code_challenge_method = "plain".to_string();
        let resp = authorize(State(ctx), loopback(), Query(q), good_headers()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_rejects_missing_code_challenge() {
        let ctx = ctx();
        let mut q = good_query();
        q.code_challenge = String::new();
        let resp = authorize(State(ctx), loopback(), Query(q), good_headers()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_rejects_unknown_client() {
        let ctx = ctx();
        let mut q = good_query();
        q.client_id = "ghost".to_string();
        let resp = authorize(State(ctx), loopback(), Query(q), good_headers()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_rejects_redirect_uri_not_in_dcr() {
        // The URI is in the operator allowlist but the client never
        // registered it — must still be refused.
        let ctx = ctx();
        let mut q = good_query();
        q.redirect_uri = "https://chat.openai.com/aip/g-xyz/oauth/callback".to_string();
        let resp = authorize(State(ctx), loopback(), Query(q), good_headers()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_rejects_missing_trusted_header() {
        let ctx = ctx();
        let resp = authorize(
            State(ctx),
            loopback(),
            Query(good_query()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authorize_state_round_trips_to_redirect() {
        let ctx = ctx();
        let mut q = good_query();
        q.state = "this-is-the-state-i-sent".to_string();
        let resp = authorize(State(ctx), loopback(), Query(q), good_headers()).await;
        let loc = parse_redirect_location(resp);
        assert!(loc.contains("state=this-is-the-state-i-sent"));
    }

    #[tokio::test]
    async fn test_authorize_groups_header_populates_roles_in_code() {
        let ctx = ctx();
        let resp = authorize(
            State(ctx.clone()),
            loopback(),
            Query(good_query()),
            good_headers(),
        )
        .await;
        let loc = parse_redirect_location(resp);
        // Pull the code out of the redirect URL.
        let url = url::Url::parse(&loc).unwrap();
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();
        let stored = ctx.state.consume_code(&code).unwrap();
        assert_eq!(stored.subject, "alice");
        assert_eq!(stored.roles, vec!["dev".to_string(), "oncall".to_string()]);
    }
}
