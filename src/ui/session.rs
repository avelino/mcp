//! Session handling for the local UI.
//!
//! The UI binds to loopback and is reachable by every process of the user, so
//! the token is not a defence against local code — it is a defence against the
//! browser. A page on the internet cannot read the cookie (SameSite=Strict,
//! HttpOnly) and cannot forge the `Origin`/`Fetch-Site` headers a POST carries.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use std::sync::Arc;

use super::{unauthorized, UiState};

const COOKIE: &str = "mcp_ui";

/// Bearer of the one-time secret printed on startup.
pub struct SessionToken(String);

impl SessionToken {
    pub fn generate() -> Self {
        // 48 chars from the crate's opaque-token charset (62 symbols).
        Self(crate::auth::oauth_primitives::generate_random_string(48))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Rejects requests that did not come from the browser session this process
/// started.
pub async fn guard(State(state): State<Arc<UiState>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path.starts_with("/assets/") || path == "/healthz" {
        return next.run(req).await;
    }

    let headers = req.headers().clone();
    let method = req.method().clone();

    if !host_is_local(&headers, &state.addr) {
        return (
            StatusCode::BAD_REQUEST,
            "mcp ui: unexpected Host header (DNS rebinding guard)",
        )
            .into_response();
    }

    if method != Method::GET && method != Method::HEAD && !same_site(&headers, &state.addr) {
        return (StatusCode::FORBIDDEN, "mcp ui: cross-site request rejected").into_response();
    }

    if cookie_token(&headers).as_deref() == Some(state.token.as_str()) {
        return next.run(req).await;
    }

    // First visit: the URL printed by `mcp ui` carries ?token=…  Turn it into a
    // cookie and redirect so the secret stops appearing in the address bar and
    // in Referer headers.
    if let Some(token) = query_param(req.uri().query().unwrap_or(""), "token") {
        if token == state.token {
            let target = strip_token(req.uri().query().unwrap_or(""));
            let location = if target.is_empty() {
                path
            } else {
                format!("{path}?{target}")
            };
            let cookie = format!(
                "{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
                state.token
            );
            let mut response = Redirect::to(&location).into_response();
            if let Ok(value) = cookie.parse() {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            return response;
        }
    }

    unauthorized()
}

fn host_is_local(headers: &HeaderMap, bound: &str) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.to_ascii_lowercase())
    else {
        return false;
    };

    let port = bound.rsplit(':').next().unwrap_or("7332");
    let mut allowed = vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
        bound.to_ascii_lowercase(),
    ];
    // An explicit non-loopback bind is allowed as long as the client reached it
    // by IP literal: a hostile DNS name cannot resolve to that literal.
    let host_part = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host);
    if host_part.parse::<std::net::IpAddr>().is_ok() {
        allowed.push(host.clone());
    }
    allowed.iter().any(|a| a == &host)
}

/// A browser POST must be same-origin. Non-browser clients (curl) send neither
/// header and are allowed: they already had to read the token from the file
/// system or the terminal.
fn same_site(headers: &HeaderMap, bound: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site.eq_ignore_ascii_case("cross-site") || site.eq_ignore_ascii_case("same-site") {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let port = bound.rsplit(':').next().unwrap_or("7332");
        let ok = ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .any(|h| origin.eq_ignore_ascii_case(&format!("http://{h}:{port}")));
        if !ok {
            return false;
        }
    }
    true
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| super::urldecode(v))
}

fn strip_token(query: &str) -> String {
    query
        .split('&')
        .filter(|pair| !pair.starts_with("token="))
        .filter(|pair| !pair.is_empty())
        .collect::<Vec<_>>()
        .join("&")
}
