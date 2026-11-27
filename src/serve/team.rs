//! Authentication for the UI served by `mcp serve --management`.
//!
//! The browser gets the same treatment as an MCP client: the proxy's own
//! provider chain decides who the caller is, and `serverAuth.adminRoles`
//! decides whether they may change anything. The only addition is a login
//! form, because a browser cannot set an `Authorization` header on a
//! navigation — the token is exchanged for an HttpOnly cookie and re-validated
//! on every request, so revoking a token takes effect immediately.

use axum::extract::{ConnectInfo, Extension, Form, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use std::sync::Arc;

use crate::server_auth::{AuthIdentity, Credentials};
use crate::ui::Viewer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use super::reload::{AuthSnapshot, SharedAuth};

pub(crate) const COOKIE: &str = "mcp_team_token";

/// State for the management guard: the same swappable snapshot `/mcp` uses.
#[derive(Clone)]
pub(crate) struct TeamAuth {
    pub(crate) auth: SharedAuth,
    /// Force `Secure` on the session cookie: set when a TLS terminator in front
    /// of the proxy does not forward `X-Forwarded-Proto`.
    pub(crate) secure_cookies: bool,
    /// The same audit trail `/mcp` writes to, so rejected sign-ins are visible.
    pub(crate) audit: Arc<crate::audit::AuditLogger>,
    /// Failed sign-in throttle, per peer address.
    pub(crate) login_attempts: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>>,
}

/// Sign-in attempts allowed per peer per window.
const LOGIN_MAX: u32 = 10;
const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Sliding-window rate limit for the sign-in form.
///
/// Tokens minted by the UI are 48 random characters; tokens typed by an
/// operator are whatever they chose. Ten attempts a minute makes the second
/// case useless to an attacker without turning the proxy into a lockout tool.
fn throttle_allow(team: &TeamAuth, peer: std::net::IpAddr) -> bool {
    let Ok(mut attempts) = team.login_attempts.lock() else {
        return true;
    };
    let now = Instant::now();
    attempts.retain(|_, (_, started)| now.duration_since(*started) < LOGIN_WINDOW);
    let entry = attempts.entry(peer).or_insert((0, now));
    if entry.0 >= LOGIN_MAX {
        return false;
    }
    entry.0 += 1;
    true
}

/// Paths that must stay reachable without a session: the login form itself and
/// the stylesheet it renders with.
fn open_path(path: &str) -> bool {
    path == "/login" || path == "/logout" || path.starts_with("/assets/") || path == "/healthz"
}

pub(crate) async fn guard(State(team): State<TeamAuth>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // The login handler needs the snapshot; hand it the same clone the
    // guard would have used.
    req.extensions_mut().insert(team.clone());

    if open_path(&path) {
        return next.run(req).await;
    }

    let snapshot = AuthSnapshot::read(&team.auth);
    let creds = credentials(req.headers());
    match snapshot.provider.authenticate(&creds).await {
        Ok(identity) => {
            let admin = is_admin(&identity, &snapshot.admin_roles);
            req.extensions_mut().insert(Viewer::team(identity, admin));
            next.run(req).await
        }
        Err(_) => {
            if method == axum::http::Method::GET {
                Redirect::to("/login").into_response()
            } else {
                // A POST loses its body on the redirect, so say why instead of
                // silently dropping the action.
                (
                    StatusCode::UNAUTHORIZED,
                    "mcp ui: not signed in — open /login and try again\n",
                )
                    .into_response()
            }
        }
    }
}

/// Renders the sign-in form.
pub(crate) async fn login_page(Query(query): Query<HashMap<String, String>>) -> Response {
    let next = safe_next(query.get("next").map(String::as_str).unwrap_or("/"));
    match render_login(None, &next) {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// Validates the pasted token against the proxy's own provider chain and, on
/// success, stores it in an HttpOnly cookie.
///
/// The token is re-validated on every request by the guard, so removing it
/// from `serverAuth.bearer.tokens` (or letting a JWT expire) signs the browser
/// out on its next click — there is no session table to keep in sync.
pub(crate) async fn login_submit(
    Extension(team): Extension<TeamAuth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "mcp ui: cross-site login rejected\n").into_response();
    }
    if !throttle_allow(&team, peer.ip()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many sign-in attempts — wait a minute and try again\n",
        )
            .into_response();
    }
    let next = safe_next(form.get("next").map(String::as_str).unwrap_or("/"));
    let token = form.get("token").map(|t| t.trim()).unwrap_or("");

    if token.is_empty() {
        return login_error("paste a bearer token", &next);
    }

    // The form's token is the only credential considered. Forwarded headers are
    // deliberately *not* read here: otherwise a deployment that trusts
    // `x-forwarded-user` would mint a session cookie holding whatever string
    // the form submitted, and that cookie would travel as a bearer token
    // afterwards.
    match identity_for_token(&team, token).await {
        Ok(identity) => {
            let secure = team.secure_cookies || wants_secure_cookie(&headers);
            let mut response = Redirect::to(&next).into_response();
            if let Ok(value) = session_cookie(token, secure).parse() {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            tracing::info!(subject = %identity.subject, "management ui sign-in");
            response
        }
        Err(message) => {
            tracing::warn!(error = %message, "management ui sign-in rejected");
            team.audit.log(crate::audit::AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source: "ui".to_string(),
                method: "auth/failure".to_string(),
                tool_name: None,
                server_name: None,
                identity: "anonymous".to_string(),
                duration_ms: 0,
                success: false,
                error_message: Some(message.clone()),
                arguments: None,
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });
            login_error(&message, &next)
        }
    }
}

/// Validates a pasted token with the proxy's own provider chain.
///
/// Returns an error for an anonymous identity as well: with no provider
/// configured every token "validates" as anonymous, and a session cookie for
/// nobody is worse than a clear refusal.
async fn identity_for_token(team: &TeamAuth, token: &str) -> Result<AuthIdentity, String> {
    let snapshot = AuthSnapshot::read(&team.auth);
    let mut creds = Credentials::new();
    creds.insert("authorization".to_string(), format!("Bearer {token}"));
    let identity = snapshot
        .provider
        .authenticate(&creds)
        .await
        .map_err(|e| format!("the proxy rejected that token: {e}"))?;
    if identity.is_anonymous() {
        return Err(
            "this proxy has no provider configured, so a token cannot identify anyone — \
             add `serverAuth.providers` or sign in through your reverse proxy"
                .to_string(),
        );
    }
    Ok(identity)
}

/// `POST /logout`: a GET here would let any page sign the operator out with an
/// `<img>` tag.
pub(crate) async fn logout(headers: HeaderMap) -> Response {
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "mcp ui: cross-site logout rejected").into_response();
    }
    let mut response = Redirect::to("/login").into_response();
    if let Ok(value) = clear_cookie().parse() {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

fn login_error(message: &str, next: &str) -> Response {
    match render_login(Some(message), next) {
        Ok(html) => (StatusCode::UNAUTHORIZED, axum::response::Html(html)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

fn render_login(error: Option<&str>, next: &str) -> Result<String, String> {
    let mut ctx = serde_json::Map::new();
    ctx.insert("error".to_string(), serde_json::json!(error));
    ctx.insert("next".to_string(), serde_json::json!(next));
    ctx.insert(
        "version".to_string(),
        serde_json::json!(env!("CARGO_PKG_VERSION")),
    );
    crate::ui::render::render("login.html", ctx).map_err(|e| e.to_string())
}

/// Only same-origin absolute paths are accepted, so the form cannot be turned
/// into an open redirect.
fn safe_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") {
        next.to_string()
    } else {
        "/".to_string()
    }
}

/// An admin is an authenticated identity holding one of `adminRoles`.
///
/// Roles compare exactly: the proxy deliberately has no wildcard here, and the
/// UI must not invent one.
pub(crate) fn is_admin(identity: &AuthIdentity, admin_roles: &[String]) -> bool {
    !identity.is_anonymous() && identity.roles.iter().any(|role| admin_roles.contains(role))
}

/// Headers, plus the session cookie as a bearer token when no `Authorization`
/// header was sent.
pub(crate) fn credentials(headers: &HeaderMap) -> Credentials {
    let mut creds = Credentials::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            creds.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    if !creds.contains_key("authorization") {
        if let Some(token) = cookie_token(headers) {
            creds.insert("authorization".to_string(), format!("Bearer {token}"));
        }
    }
    creds
}

pub(crate) fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let encoded = raw
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    String::from_utf8(decoded).ok()
}

/// The `Set-Cookie` value that turns a validated token into a session.
pub(crate) fn session_cookie(token: &str, secure: bool) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token);
    let mut cookie = format!("{COOKIE}={encoded}; Path=/; HttpOnly; SameSite=Strict");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub(crate) fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// Rejects a browser POST that did not originate from this origin.
///
/// The guard skips `/login` (there is no session to protect yet), so the login
/// handler checks this itself: otherwise a hostile page could log the victim
/// into an identity the attacker controls.
pub(crate) fn same_origin(headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site.eq_ignore_ascii_case("cross-site") {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
            return origin.eq_ignore_ascii_case(&format!("http://{host}"))
                || origin.eq_ignore_ascii_case(&format!("https://{host}"));
        }
    }
    true
}

pub(crate) fn wants_secure_cookie(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::sync::Arc;

    fn with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {COOKIE}={value}")).unwrap(),
        );
        headers
    }

    fn team_with(provider: Arc<dyn crate::server_auth::AuthProvider>) -> TeamAuth {
        TeamAuth {
            auth: AuthSnapshot::new(provider, None, vec![]).shared(),
            secure_cookies: false,
            audit: Arc::new(crate::audit::AuditLogger::Disabled),
            login_attempts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    #[tokio::test]
    async fn a_token_only_signs_in_when_a_provider_accepts_it() {
        // NoAuth accepts everything as anonymous; that must not become a cookie.
        let open = team_with(Arc::new(crate::server_auth::NoAuth));
        let err = identity_for_token(&open, "anything").await.unwrap_err();
        assert!(err.contains("no provider"), "{err}");

        let mut tokens = std::collections::HashMap::new();
        tokens.insert(
            "tok-alice".to_string(),
            crate::server_auth::BearerToken::Extended {
                subject: "alice".to_string(),
                roles: vec!["admin".to_string()],
            },
        );
        let bearer = team_with(Arc::new(crate::server_auth::BearerTokenAuth::new(tokens)));
        let identity = identity_for_token(&bearer, "tok-alice")
            .await
            .expect("valid token");
        assert_eq!(identity.subject, "alice");
        assert!(identity_for_token(&bearer, "wrong").await.is_err());
    }

    #[test]
    fn sign_in_attempts_are_rate_limited_per_peer() {
        let team = team_with(Arc::new(crate::server_auth::NoAuth));
        let peer: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..LOGIN_MAX {
            assert!(throttle_allow(&team, peer));
        }
        assert!(!throttle_allow(&team, peer), "the window is full");
        let other: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        assert!(throttle_allow(&team, other), "other peers are unaffected");
    }

    #[test]
    fn cookie_round_trips_tokens_with_cookie_hostile_characters() {
        let token = "abc;def=ghi jkl/+==";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token);
        let headers = with_cookie(&encoded);
        assert_eq!(cookie_token(&headers).as_deref(), Some(token));

        let creds = credentials(&headers);
        assert_eq!(
            creds.get("authorization").map(String::as_str),
            Some(format!("Bearer {token}").as_str())
        );
    }

    #[test]
    fn an_authorization_header_wins_over_the_cookie() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("cookie-token");
        let mut headers = with_cookie(&encoded);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        let creds = credentials(&headers);
        assert_eq!(
            creds.get("authorization").map(String::as_str),
            Some("Bearer header-token")
        );
    }

    #[test]
    fn admin_requires_a_role_and_an_authenticated_identity() {
        let roles = vec!["admin".to_string()];
        assert!(is_admin(&AuthIdentity::new("alice", roles.clone()), &roles));
        assert!(!is_admin(
            &AuthIdentity::new("bob", vec!["dev".into()]),
            &roles
        ));
        assert!(!is_admin(&AuthIdentity::anonymous(), &roles));
    }

    #[test]
    fn cross_site_logins_are_refused() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!same_origin(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("mcp.example.com"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!same_origin(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("mcp.example.com"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://mcp.example.com"),
        );
        assert!(same_origin(&headers));
    }

    #[test]
    fn the_next_parameter_cannot_become_an_open_redirect() {
        assert_eq!(safe_next("/servers"), "/servers");
        assert_eq!(safe_next("//evil.example"), "/");
        assert_eq!(safe_next("https://evil.example"), "/");
        assert_eq!(safe_next(""), "/");
    }

    #[test]
    fn secure_flag_follows_the_forwarded_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(wants_secure_cookie(&headers));

        let plain = HeaderMap::new();
        assert!(!wants_secure_cookie(&plain));
        assert!(session_cookie("t", false).ends_with("SameSite=Strict"));
        assert!(session_cookie("t", true).contains("; Secure"));
    }
}
