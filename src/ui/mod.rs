//! Local web UI (`mcp ui`).
//!
//! The UI is a thin, server-rendered view over modules that already exist:
//! `config_source` for reading and writing `servers.json`, `audit` for the
//! activity trail, `cache` for the catalog, `client` for tool calls, and
//! `instances` for the processes running on this machine.
//!
//! Design constraints, in order:
//!
//! 1. The file is the source of truth. Every page re-reads it; nothing is
//!    cached in the server except the session token.
//! 2. Writes are diffs. Editing produces a patch, the patch is rendered as a
//!    diff and validated, and only then written (atomically, with a backup).
//! 3. No secret reaches the template. Config values are redacted before
//!    rendering, and `${VAR}` placeholders are shown literally.
//! 4. No JavaScript framework and no build step. htmx is vendored; the pages
//!    work as plain forms without it.

mod data;
mod handlers;
mod render;
mod session;

use anyhow::{Context, Result};

use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::audit::AuditLogger;
use crate::cache::ToolCacheStore;

pub use session::SessionToken;

const HTMX: &str = include_str!("assets/htmx.min.js");
const APP_CSS: &str = include_str!("assets/app.css");

/// How the UI was started.
pub struct Options {
    pub addr: String,
    pub open: bool,
    /// Disables every mutating route.
    pub read_only: bool,
}

/// Shared server state. Handlers get an `Arc<UiState>`.
pub struct UiState {
    pub addr: String,
    pub token: String,
    /// Why the UI is read-only, when it is.
    pub read_only: bool,
    pub started: Instant,
    pub audit: Arc<AuditLogger>,
    pub cache: ToolCacheStore,
}

impl UiState {
    pub fn uptime(&self) -> String {
        let secs = self.started.elapsed().as_secs();
        if secs < 60 {
            format!("{secs}s")
        } else if secs < 3600 {
            format!("{}m", secs / 60)
        } else {
            format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
        }
    }
}

/// Starts the UI and blocks until the process is stopped.
pub async fn run(opts: Options) -> Result<()> {
    let cfg = crate::config::load_config().context("failed to load config")?;
    let pool = crate::db::create_pool(&cfg.audit)?;
    let audit = Arc::new(AuditLogger::open(&cfg.audit, pool.clone())?);
    let cache = ToolCacheStore::new(pool.clone());

    let token = SessionToken::generate();
    let state = Arc::new(UiState {
        addr: opts.addr.clone(),
        token: token.as_str().to_string(),
        read_only: opts.read_only,
        started: Instant::now(),
        audit,
        cache,
    });

    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(&opts.addr)
        .await
        .with_context(|| format!("failed to bind {}", opts.addr))?;
    let bound = listener.local_addr().unwrap_or_else(|_| {
        opts.addr
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 7332)))
    });

    let url = format!("http://{bound}/?token={}", state.token);
    println!("mcp ui listening on http://{bound}");
    println!("open: {url}");
    if state.read_only {
        println!("read-only: mutations are disabled");
    }

    if opts.open {
        if let Err(e) = open::that(&url) {
            eprintln!("could not open the browser: {e}");
        }
    }

    axum::serve(listener, app)
        .await
        .context("ui server stopped")?;
    Ok(())
}

fn router(state: Arc<UiState>) -> Router {
    Router::new()
        .route("/", get(handlers::overview::index))
        .route("/overview", get(handlers::overview::index))
        .route(
            "/servers",
            get(handlers::servers::list).post(handlers::servers::add),
        )
        .route("/servers/add", post(handlers::servers::add))
        .route(
            "/servers/{name}",
            get(handlers::servers::detail).post(handlers::servers::apply_edit),
        )
        .route(
            "/servers/{name}/edit",
            get(handlers::servers::edit_form).post(handlers::servers::apply_edit),
        )
        .route("/servers/{name}/plan", post(handlers::servers::plan_edit))
        .route("/servers/{name}/delete", post(handlers::servers::delete))
        .route(
            "/servers/{name}/discover",
            post(handlers::servers::discover),
        )
        .route("/playground", get(handlers::playground::index))
        .route("/playground/call", post(handlers::playground::call))
        .route("/activity", get(handlers::activity::index))
        .route("/activity/rows", get(handlers::activity::rows_only))
        .route("/activity.json", get(handlers::activity::export))
        .route("/access", get(handlers::access::index))
        .route("/access/check", post(handlers::access::check))
        .route("/settings", get(handlers::settings::index))
        .route("/reload", post(handlers::settings::reload))
        .route("/healthz", get(healthz))
        .route("/assets/app.css", get(css))
        .route("/assets/htmx.js", get(htmx))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::guard,
        ))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        APP_CSS,
    )
}

async fn htmx() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        HTMX,
    )
}

/// Errors a handler can return, each with the status the browser should see.
pub enum UiError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Internal(anyhow::Error),
}

impl std::fmt::Debug for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UiError::BadRequest(m) => write!(f, "bad request: {m}"),
            UiError::NotFound(m) => write!(f, "not found: {m}"),
            UiError::Conflict(m) => write!(f, "conflict: {m}"),
            UiError::Internal(e) => write!(f, "internal error: {e:#}"),
        }
    }
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UiError::BadRequest(m) => write!(f, "{m}"),
            UiError::NotFound(m) => write!(f, "{m}"),
            UiError::Conflict(m) => write!(f, "{m}"),
            UiError::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for UiError {
    fn from(value: anyhow::Error) -> Self {
        UiError::Internal(value)
    }
}

impl From<render::RenderError> for UiError {
    fn from(value: render::RenderError) -> Self {
        UiError::Internal(anyhow::anyhow!("template error: {value}"))
    }
}

impl IntoResponse for UiError {
    fn into_response(self) -> Response {
        let (status, title, detail) = match self {
            UiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "Bad request", m),
            UiError::NotFound(m) => (StatusCode::NOT_FOUND, "Not found", m),
            UiError::Conflict(m) => (StatusCode::CONFLICT, "Conflict", m),
            UiError::Internal(e) => {
                tracing::error!(error = format!("{e:#}"), "ui request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    format!("{e:#}"),
                )
            }
        };
        let body = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>{title} · mcp</title><link rel=\"stylesheet\" href=\"/assets/app.css\"></head>\
             <body><div class=\"view\" style=\"max-width:720px\">\
             <h1>{title}</h1><p class=\"sub\">{detail}</p>\
             <p style=\"margin-top:20px\"><a class=\"btn\" href=\"/overview\">Back to overview</a></p>\
             </div></body></html>",
            title = title,
            detail = render::escape(&detail),
        );
        (status, Html(body)).into_response()
    }
}

pub type UiResult<T> = std::result::Result<T, UiError>;

/// `serde_json::Map::insert` wants an owned key; every call site here has a
/// literal. This keeps the handlers readable.
pub trait MapExt {
    fn put(&mut self, key: &str, value: serde_json::Value);
}

impl MapExt for serde_json::Map<String, serde_json::Value> {
    fn put(&mut self, key: &str, value: serde_json::Value) {
        self.insert(key.to_string(), value);
    }
}

/// One-shot message carried in the query string after a redirect.
#[derive(Debug, Default, Clone)]
pub struct Flash {
    pub ok: Option<String>,
    pub err: Option<String>,
}

impl Flash {
    pub fn from_query(query: &std::collections::HashMap<String, String>) -> Self {
        Self {
            ok: query.get("ok").cloned().filter(|s| !s.is_empty()),
            err: query.get("err").cloned().filter(|s| !s.is_empty()),
        }
    }
}

/// 303 to `location`, carrying a one-shot message in the query string.
pub fn redirect_with(location: &str, key: &str, message: &str) -> Redirect {
    let sep = if location.contains('?') { '&' } else { '?' };
    let encoded = urlencode(message);
    Redirect::to(&format!("{location}{sep}{key}={encoded}"))
}

pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// A small HTML body for script-less clients that hit an authenticated route
/// without a session.
pub fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
        "mcp ui: missing or invalid session token. Open the URL printed by `mcp ui`.\n",
    )
        .into_response()
}
