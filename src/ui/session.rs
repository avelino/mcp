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
use std::time::Instant;

use super::{unauthorized, UiState};

const COOKIE: &str = "mcp_ui";

/// Bearer of the one-time secret printed on startup, or of a session created
/// by exchanging it. Same shape for both on purpose: 48 random characters from
/// the crate's opaque-token charset.
pub struct SessionToken(String);

/// Constant-time comparison for short secrets.
///
/// A remote timing attack against 48 random characters is not practical, but
/// the comparison is also what protects the CSRF nonce, and a loop is cheaper
/// than the reasoning about whether it matters.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    difference == 0
}

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

    if method != Method::GET && method != Method::HEAD && !same_site(&headers) {
        return (StatusCode::FORBIDDEN, "mcp ui: cross-site request rejected").into_response();
    }

    if let Some(cookie) = cookie_token(&headers) {
        if state
            .sessions
            .lock()
            .ok()
            .is_some_and(|set| set.contains(&cookie))
        {
            return next.run(req).await;
        }
    }

    // First visit: the URL printed by `mcp ui` carries the bootstrap token.
    // It is spent here and replaced by a fresh session token, so a URL that
    // leaks through history or a log is worthless after the first visit — and
    // expires on its own if it is never visited at all.
    if let Some(candidate) = query_param(req.uri().query().unwrap_or(""), "token") {
        if spend_bootstrap(&state, &candidate) {
            let session = SessionToken::generate().as_str().to_string();
            if let Ok(mut sessions) = state.sessions.lock() {
                if sessions.len() >= MAX_SESSIONS {
                    sessions.clear();
                }
                sessions.insert(session.clone());
            }
            let target = strip_token(req.uri().query().unwrap_or(""));
            let location = if target.is_empty() {
                path
            } else {
                format!("{path}?{target}")
            };
            let cookie = format!("{COOKIE}={session}; Path=/; HttpOnly; SameSite=Strict");
            let mut response = Redirect::to(&location).into_response();
            if let Ok(value) = cookie.parse() {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            return response;
        }
    }

    unauthorized()
}

/// At most this many live browser sessions per process.
const MAX_SESSIONS: usize = 64;

/// Consumes the bootstrap token, if it is the right one and still valid.
///
/// The check and the take happen under one lock: a wrong token must not spend
/// it, and two simultaneous uses must not both win.
pub(crate) fn spend_bootstrap(state: &UiState, candidate: &str) -> bool {
    let Ok(mut bootstrap) = state.bootstrap.lock() else {
        return false;
    };
    let Some(current) = bootstrap.as_ref() else {
        return false;
    };
    if current.expires <= Instant::now() {
        *bootstrap = None;
        return false;
    }
    if !ct_eq(&current.token, candidate) {
        return false;
    }
    *bootstrap = None;
    true
}

#[cfg(test)]
fn bootstrap_valid(state: &UiState, candidate: &str) -> bool {
    state
        .bootstrap
        .lock()
        .ok()
        .and_then(|b| {
            b.as_ref()
                .map(|b| b.expires > Instant::now() && ct_eq(&b.token, candidate))
        })
        .unwrap_or(false)
}

fn host_is_local(headers: &HeaderMap, bound: &str) -> bool {
    let Ok(bound) = bound.parse::<std::net::SocketAddr>() else {
        return false;
    };
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.to_ascii_lowercase())
    else {
        return false;
    };
    host_matches(&host, bound)
}

/// Whether `Host` names this server.
///
/// Derived from the bound address rather than a hardcoded loopback list: with
/// `--addr 192.168.1.5:7332` the browser reaches the UI by that IP, and the
/// check has to accept it. Loopback binds stay loopback-only — an arbitrary IP
/// literal is not a loopback alias.
fn host_matches(host: &str, bound: std::net::SocketAddr) -> bool {
    let port = bound.port();
    if host == format!("localhost:{port}")
        || host == format!("127.0.0.1:{port}")
        || host == format!("[::1]:{port}")
    {
        return true;
    }
    let Some((host_part, host_port)) = host.rsplit_once(':') else {
        return false;
    };
    if host_port.parse::<u16>().ok() != Some(port) {
        return false;
    }
    let Ok(ip) = host_part
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
    else {
        return false;
    };
    let bound_ip = bound.ip();
    if bound_ip.is_unspecified() {
        // `0.0.0.0` / `::` — every local address is a legitimate way in.
        true
    } else {
        ip == bound_ip
    }
}

/// A browser POST must be same-origin.
///
/// Compared against the `Host` header, which `host_is_local` has already
/// vouched for: a rebinding request carries its own domain in both headers and
/// would otherwise look perfectly same-origin. Non-browser clients (curl) send
/// neither header and are allowed — they already had to read the token from the
/// terminal.
fn same_site(headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site.eq_ignore_ascii_case("cross-site") || site.eq_ignore_ascii_case("same-site") {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        return origin.eq_ignore_ascii_case(&format!("http://{host}"))
            || origin.eq_ignore_ascii_case(&format!("https://{host}"));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> std::net::SocketAddr {
        text.parse().expect("addr")
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                name.parse::<axum::http::HeaderName>().unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn constant_time_equality_compares_content_and_length() {
        assert!(ct_eq("same", "same"));
        assert!(!ct_eq("same", "samf"));
        assert!(!ct_eq("same", "same "));
        assert!(!ct_eq("", "x"));
    }

    #[test]
    fn a_loopback_bind_only_accepts_loopback_hosts() {
        let bound = addr("127.0.0.1:7332");
        assert!(host_matches("127.0.0.1:7332", bound));
        assert!(host_matches("localhost:7332", bound));
        assert!(host_matches("[::1]:7332", bound));
        assert!(
            !host_matches("192.168.1.5:7332", bound),
            "an IP literal is not loopback"
        );
        assert!(!host_matches("evil.example:7332", bound));
        assert!(!host_matches("127.0.0.1:7333", bound), "port must match");
    }

    #[test]
    fn an_explicit_non_loopback_bind_accepts_that_address() {
        let bound = addr("192.168.1.5:7332");
        assert!(host_matches("192.168.1.5:7332", bound));
        assert!(host_matches("localhost:7332", bound));
        assert!(!host_matches("192.168.1.6:7332", bound));
        assert!(!host_matches("evil.example:7332", bound));
    }

    #[test]
    fn an_unspecified_bind_accepts_any_ip_literal_but_not_a_domain() {
        let bound = addr("0.0.0.0:7332");
        assert!(host_matches("10.0.0.4:7332", bound));
        assert!(host_matches("127.0.0.1:7332", bound));
        assert!(!host_matches("evil.example:7332", bound));
    }

    #[test]
    fn same_origin_follows_the_host_header() {
        let same = headers(&[
            ("host", "192.168.1.5:7332"),
            ("origin", "http://192.168.1.5:7332"),
        ]);
        assert!(
            same_site(&same),
            "a non-loopback bind must accept its own origin"
        );

        let other = headers(&[
            ("host", "192.168.1.5:7332"),
            ("origin", "http://evil.example"),
        ]);
        assert!(!same_site(&other));

        let rebinding = headers(&[
            ("host", "evil.example:7332"),
            ("origin", "http://evil.example:7332"),
        ]);
        assert!(
            same_site(&rebinding),
            "same_site compares Origin to Host; rejecting the Host is host_is_local's job"
        );
        assert!(!host_is_local(&rebinding, "127.0.0.1:7332"));
    }

    #[test]
    fn a_cross_site_fetch_is_refused_regardless_of_origin() {
        let fetch = headers(&[
            ("sec-fetch-site", "cross-site"),
            ("origin", "http://127.0.0.1:7332"),
        ]);
        assert!(!same_site(&fetch));
    }

    #[test]
    fn a_client_without_origin_is_allowed() {
        assert!(same_site(&headers(&[("host", "127.0.0.1:7332")])));
    }
}
