use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use tokio_stream::wrappers::ReceiverStream;

use crate::audit::{AuditEntry, AuditLogger};
use crate::cache::ToolCacheStore;
use crate::config::Config;
use crate::protocol::{error_codes, JsonRpcRequest, JsonRpcResponse};
use crate::server_auth::oauth_as::{self, AsState};
use crate::server_auth::{self, AclConfig, AuthIdentity, AuthProvider, Credentials};
use crate::telemetry::extract_parent_context;

use super::discovery::discover_pending_backends;
use super::dispatch::dispatch_request;
use super::proxy::{shutdown_clients_in_parallel, BackendState, ProxyServer, SharedProxy};

type SseSender = tokio::sync::mpsc::Sender<Result<Event, std::convert::Infallible>>;
type SessionMap = Arc<Mutex<HashMap<String, SseSender>>>;

#[derive(Clone)]
struct AppState {
    proxy: SharedProxy,
    auth_provider: Arc<dyn AuthProvider>,
    acl: Option<AclConfig>,
    sessions: SessionMap,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

/// Extract credentials from HTTP headers (only transport-aware code).
fn extract_credentials(headers: &HeaderMap) -> Credentials {
    let mut creds = Credentials::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            creds.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    creds
}

/// Authenticate an HTTP request. Returns identity on success, or a 401 response.
/// Logs authentication failures to the audit log.
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    source: &str,
) -> Result<AuthIdentity, (StatusCode, Json<Value>)> {
    let creds = extract_credentials(headers);
    match state.auth_provider.authenticate(&creds).await {
        Ok(identity) => Ok(identity),
        Err(e) => {
            // Log auth failure using async lock (safe in async context).
            let audit = Arc::clone(&state.proxy.lock().await.audit);
            audit.log(AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source: source.to_string(),
                method: "auth/failure".to_string(),
                tool_name: None,
                server_name: None,
                identity: "anonymous".to_string(),
                duration_ms: 0,
                success: false,
                error_message: Some(format!("authentication failed: {e}")),
                arguments: None,
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });
            let err = JsonRpcResponse::error(
                Value::Null,
                error_codes::PROXY_ERROR,
                &format!("authentication failed: {e}"),
            );
            Err((StatusCode::UNAUTHORIZED, Json(json!(err))))
        }
    }
}

/// A `400 Bad Request` carrying a JSON-RPC parse error, for a body we could
/// not read far enough to know its id.
fn parse_error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    let err = JsonRpcResponse::error(
        Value::Null,
        error_codes::PARSE_ERROR,
        &format!("parse error: {e}"),
    );
    (StatusCode::BAD_REQUEST, Json(json!(err)))
}

/// Decode a routing header, or give back the rejection message for a
/// sentinel that will not decode.
///
/// The spec lists "a header value contains invalid characters" as its own
/// rejection condition, and both routing headers answer it the same way.
fn decoded_header(declared: &str, header_name: &str) -> Result<String, String> {
    crate::protocol::decode_header_value(declared)
        .ok_or_else(|| format!("{header_name} header '{declared}' is a malformed Base64 sentinel"))
}

/// Validate the `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` request
/// metadata headers against the JSON-RPC body. Returns the mismatch message,
/// or `None` when everything lines up.
///
/// 2026-07-28 requires clients to *send* these on Streamable HTTP POSTs, but
/// we deliberately only validate what is actually present: every
/// pre-2026-07-28 client sends neither routing header, and clients from
/// 2025-06-18 onwards send `MCP-Protocol-Version` with no `_meta` to compare
/// it against. Demanding the full set would break all of them at once. A
/// header that contradicts the body, on the other hand, means a gateway
/// routed or metered on a lie — that we reject.
fn check_routing_headers(headers: &HeaderMap, req: &JsonRpcRequest) -> Option<String> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    // The spec requires the header to agree with `_meta`'s protocolVersion.
    // Only comparable when the body actually declares one; a header alone is
    // the 2025-06-18-through-2025-11-25 shape and stays valid.
    if let (Some(declared), Some(body_version)) = (
        header(crate::protocol::HEADER_MCP_PROTOCOL_VERSION),
        crate::protocol::request_protocol_version(req.params.as_ref()),
    ) {
        if declared != body_version {
            return Some(format!(
                "{} header '{declared}' does not match request _meta protocol version '{body_version}'",
                crate::protocol::HEADER_MCP_PROTOCOL_VERSION
            ));
        }
    }

    // Decoded before comparing, exactly like `Mcp-Name` below. A method name
    // is header-safe in practice, so this decode is never *needed* today —
    // but the client runs every routing header through `protocol::header_value`
    // on the way out, and an encode with no matching decode is the precise
    // shape of the bug that already rejected every real `resources/read` once.
    // Symmetry is cheaper than a reachability argument.
    if let Some(declared) = header(crate::protocol::HEADER_MCP_METHOD) {
        let decoded = match decoded_header(declared, crate::protocol::HEADER_MCP_METHOD) {
            Ok(decoded) => decoded,
            Err(message) => return Some(message),
        };
        if decoded != req.method {
            return Some(format!(
                "{} header '{declared}' does not match request method '{}'",
                crate::protocol::HEADER_MCP_METHOD,
                req.method
            ));
        }
    }

    if let Some(declared) = header(crate::protocol::HEADER_MCP_NAME) {
        // "Servers MUST decode an encoded Mcp-Name value before comparing it
        // to the corresponding request body value."
        let decoded = match decoded_header(declared, crate::protocol::HEADER_MCP_NAME) {
            Ok(decoded) => decoded,
            Err(message) => return Some(message),
        };
        let expected = crate::protocol::mcp_name_for(&req.method, req.params.as_ref());
        match expected {
            Some(expected) if decoded == expected => {}
            Some(expected) => {
                return Some(format!(
                    "{} header '{declared}' does not match request target '{expected}'",
                    crate::protocol::HEADER_MCP_NAME
                ))
            }
            // The method targets no primitive, so any name is a lie.
            None => {
                return Some(format!(
                    "{} header '{declared}' sent for method '{}', which targets no primitive",
                    crate::protocol::HEADER_MCP_NAME,
                    req.method
                ))
            }
        }
    }

    None
}

/// Reject an `MCP-Protocol-Version` header naming a revision we do not speak.
///
/// `dispatch_request` already does this for the version declared in
/// `params._meta`, but the header is a second, independent way to select
/// 2026-07-28 semantics — `declares_stateless_revision` reads it, and
/// `is_stateless_version` is a bare date compare with no membership test. So
/// without this, `MCP-Protocol-Version: 2099-01-01` bought the new behavior
/// and never got the `-32022` that tells the client what we actually speak.
fn check_protocol_version_header(
    headers: &HeaderMap,
    req: &JsonRpcRequest,
) -> Option<JsonRpcResponse> {
    let declared = headers
        .get(crate::protocol::HEADER_MCP_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok())?;
    if crate::protocol::is_version_supported(declared) {
        return None;
    }
    Some(JsonRpcResponse::unsupported_protocol_version(
        req.id.clone(),
        declared,
    ))
}

/// Whether a peer opted into the revision whose HTTP status codes and result
/// envelope differ from what we have always returned.
///
/// Declaring the revision is the opt-in: either in the body's `_meta` (the
/// stateless shape) or in the `MCP-Protocol-Version` header. A peer that does
/// neither is on a pre-2026-07-28 revision and must keep seeing byte-identical
/// behavior.
///
/// The version has to be one we actually speak, not merely a later date:
/// `is_stateless_version` is an ordering test, so an unknown future revision
/// would otherwise select 2026-07-28 semantics for a peer we cannot talk to.
/// `check_protocol_version_header` rejects that case outright on the HTTP
/// path; requiring support here means this function is still right when read
/// on its own.
fn declares_stateless_revision(headers: &HeaderMap, req: &JsonRpcRequest) -> bool {
    let from_header = headers
        .get(crate::protocol::HEADER_MCP_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok());
    super::dispatch::body_declares_stateless(req)
        || from_header.is_some_and(|v| {
            crate::protocol::is_version_supported(v) && crate::protocol::is_stateless_version(v)
        })
}

/// HTTP status for a JSON-RPC error the 2026-07-28 transport pins to a
/// specific status code.
///
/// This is not pedantry: the spec's era-detection algorithm has clients
/// inspect the *body* of a `400` to decide whether to fall back to
/// `initialize`. Answering `200` makes us invisible to that logic and breaks
/// other clients' compatibility handling.
///
/// `-32020` and `-32022` are unreachable for a legacy peer by construction:
/// the first needs a routing header no pre-2026-07-28 client sends, the
/// second needs a `_meta` protocol version no pre-2026-07-28 client sends.
/// `-32601` is reachable by anyone — every legacy client asking for a method
/// we never implemented gets one — so it only becomes a `404` for a peer that
/// declared the new revision. Everything else keeps riding on `200`, which is
/// what JSON-RPC-over-HTTP has always done here.
fn status_for_response(response: &JsonRpcResponse, stateless_peer: bool) -> StatusCode {
    let Some(error) = response.error.as_ref() else {
        return StatusCode::OK;
    };
    match error.code {
        error_codes::HEADER_MISMATCH | error_codes::UNSUPPORTED_PROTOCOL_VERSION => {
            StatusCode::BAD_REQUEST
        }
        error_codes::METHOD_NOT_FOUND if stateless_peer => StatusCode::NOT_FOUND,
        _ => StatusCode::OK,
    }
}

/// Bind a TCP listener with TCP keepalive enabled. Short keepalive intervals
/// let us detect dead client sockets (e.g. opencode crashed mid-request) in
/// ~60s instead of waiting for the OS default (2h on macOS).
fn bind_listener_with_keepalive(addr: std::net::SocketAddr) -> Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    socket.set_tcp_keepalive(&keepalive)?;

    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(tokio::net::TcpListener::from_std(std_listener)?)
}

/// Validate that a bind address is safe.
/// Non-loopback addresses require --insecure flag.
fn validate_bind_addr(addr: &str, insecure: bool) -> Result<std::net::SocketAddr> {
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{addr}': {e}"))?;

    if !insecure && !sock_addr.ip().is_loopback() {
        bail!(
            "refusing to bind to non-loopback address {addr} without TLS.\n\
             Use --insecure to allow plaintext on non-loopback interfaces,\n\
             or bind to 127.0.0.1:{port} for local-only access.",
            port = sock_addr.port()
        );
    }

    Ok(sock_addr)
}

pub async fn run_http(mut config: Config, bind_addr: &str, insecure: bool) -> Result<()> {
    let sock_addr = validate_bind_addr(bind_addr, insecure)?;

    // OAuth AS state — only allocated when the operator opted in via
    // `serverAuth.providers` containing "oauth_as". Loaded from disk
    // (or env-var inline) so registered clients and refresh tokens
    // survive a restart.
    let as_enabled = config.server_auth.providers.iter().any(|p| p == "oauth_as");
    let as_state: Option<Arc<AsState>> = if as_enabled {
        let s = oauth_as::load_state()
            .map_err(|e| anyhow::anyhow!("failed to load AS state: {e:#}"))?;
        Some(Arc::new(s))
    } else {
        None
    };

    let auth_provider = server_auth::build_auth_provider(&config.server_auth, as_state.as_ref())?;
    let acl = config.server_auth.acl.clone();

    // Serve-mode default resolution: when `audit.output` is unset
    // (`None`), auto-promote to `FileAndStdout` so audit also streams
    // to stdout for the container log driver. Any explicit value the
    // operator set (including a deliberate `Some(File)` for chrondb-only)
    // is honored verbatim.
    let resolved_audit = crate::audit::AuditOutput::resolve_for_serve(
        config.audit.output.clone(),
        crate::audit::ServeContext::Http,
    );
    config.audit.output = Some(resolved_audit.clone());

    let pool = if resolved_audit.writes_to_file() {
        crate::db::create_pool(&config.audit).unwrap_or_else(|e| {
            tracing::warn!(error = format!("{e:#}"), "failed to create db pool");
            Arc::new(crate::db::DbPool::disabled())
        })
    } else {
        Arc::new(crate::db::DbPool::disabled())
    };
    let audit = AuditLogger::open(&config.audit, pool.clone()).unwrap_or(AuditLogger::Disabled);
    let cache_store = ToolCacheStore::new(pool);
    let mut server = ProxyServer::new(
        Arc::new(audit),
        config.servers.clone(),
        config.config_hashes.clone(),
        cache_store,
    );
    server.load_from_cache();
    let has_cached_tools = !server.tools.is_empty();
    let shared: SharedProxy = Arc::new(Mutex::new(server));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let state = AppState {
        proxy: shared.clone(),
        auth_provider,
        acl,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        shutdown: shutdown_rx,
    };

    // OTel observable gauges. The closures hold `Weak` refs so they don't
    // keep the proxy alive past shutdown. `try_lock` is best-effort: if the
    // mutex is contended at observation time we report 0 instead of stalling
    // the metrics export task.
    {
        let proxy_weak = Arc::downgrade(&shared);
        let sessions_weak = Arc::downgrade(&state.sessions);
        crate::telemetry::register_proxy_observers(
            move || {
                proxy_weak
                    .upgrade()
                    .and_then(|p| {
                        p.try_lock().ok().map(|p| {
                            p.backends
                                .values()
                                .filter(|s| matches!(s, BackendState::Connected { .. }))
                                .count() as u64
                        })
                    })
                    .unwrap_or(0)
            },
            move || {
                sessions_weak
                    .upgrade()
                    .and_then(|s| s.try_lock().ok().map(|m| m.len() as u64))
                    .unwrap_or(0)
            },
        );
    }

    // Background GC for the OAuth AS — drops expired authorization
    // codes and refresh tokens. Cheap pass; runs every 60s.
    if let Some(ref state) = as_state {
        let gc_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let removed = gc_state.gc_expired();
                if removed > 0 {
                    if let Err(e) = oauth_as::save_state(&gc_state) {
                        tracing::warn!(
                            error = format!("{e:#}"),
                            "failed to persist AS state after GC"
                        );
                    }
                }
            }
        });
    }

    // Background reaper: shuts down idle backends periodically.
    // Lock is released before async shutdown so request handlers are never
    // blocked. Shutdowns run in parallel via JoinSet, and any backend whose
    // graceful close stalls is force-killed via Drop.
    let reaper_proxy = shared.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let idle_clients = {
                let mut proxy = reaper_proxy.lock().await;
                proxy.collect_idle_backends()
            };
            shutdown_clients_in_parallel(idle_clients).await;
        }
    });

    // Background refresh: re-discover tools from real backends after serving
    // cached tools. The lock is only held briefly to clear the discovered set;
    // the actual discovery I/O runs without the proxy mutex held, so client
    // requests for cached tools fly through with zero contention while the
    // refresh is in progress.
    if has_cached_tools {
        let refresh_proxy = shared.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            {
                let mut proxy = refresh_proxy.lock().await;
                proxy.reset_cache_loaded_for_refresh();
            }
            discover_pending_backends(&refresh_proxy).await;
        });
    }

    // Log all incoming requests for debugging
    let request_logger = axum::middleware::from_fn(
        |req: axum::extract::Request, next: axum::middleware::Next| async move {
            tracing::debug!(
                method = %req.method(),
                uri = %req.uri(),
                accept = req.headers()
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-"),
                "incoming request"
            );
            next.run(req).await
        },
    );

    let core_router = Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler).get(mcp_sse_handler))
        .route("/mcp/sse", get(mcp_sse_handler))
        .with_state(state.clone());

    // Mount the OAuth AS sub-router when the operator enabled it.
    // Without it, the well-known/discovery paths simply 404 — same
    // shape the previous short-circuit produced, just routed through
    // the standard fallback now.
    let app = if let Some(ref state) = as_state {
        let cfg = Arc::new(
            config
                .server_auth
                .oauth_as
                .clone()
                .expect("oauth_as enabled but no oauthAs config — caught at boot"),
        );
        core_router.merge(oauth_as::router(cfg, state.clone()))
    } else {
        core_router
    };

    let app = app
        .fallback(|req: axum::extract::Request| async move {
            let path = req.uri().path().to_string();
            let method = req.method().clone();
            tracing::debug!(
                method = %method,
                path = %path,
                "unhandled request"
            );
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
        })
        .layer(request_logger);

    tracing::info!(addr = %sock_addr, "HTTP server listening");
    if sock_addr.ip().is_loopback() {
        tracing::info!("bound to loopback — local access only");
    } else {
        tracing::warn!("bound to non-loopback address without TLS");
    }

    let listener = bind_listener_with_keepalive(sock_addr)?;

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown_signal = async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
        tracing::info!("shutdown signal received");
        let _ = shutdown_tx.send(true);
    };

    // ConnectInfo<SocketAddr> is required by the OAuth /authorize
    // handler so it can verify the request originates from a trusted
    // CIDR (anti-spoof against direct clients injecting
    // X-Forwarded-User). Wiring it unconditionally is harmless for
    // other handlers.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await?;

    // Cleanup backends — bounded so a stuck handler doesn't block exit.
    // Drain under the lock (cheap), then run all shutdowns in parallel.
    let cleanup = async {
        let drained = {
            let mut proxy = state.proxy.lock().await;
            proxy.drain_connected()
        };
        shutdown_clients_in_parallel(drained).await;
    };
    if tokio::time::timeout(Duration::from_secs(10), cleanup)
        .await
        .is_err()
    {
        tracing::warn!("shutdown timed out — forcing exit");
    }
    tracing::info!("shutting down");

    Ok(())
}

// GET /health
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let proxy = state.proxy.lock().await;
    let connected = proxy
        .backends
        .values()
        .filter(|s| matches!(s, BackendState::Connected { .. }))
        .count();
    let active_clients = state.sessions.lock().await.len();
    let body = json!({
        "status": "ok",
        "backends_configured": proxy.configs.len(),
        "backends_connected": connected,
        "active_clients": active_clients,
        "tools": proxy.tools.len(),
        "version": env!("CARGO_PKG_VERSION"),
    });
    Json(body)
}

// POST /mcp — JSON-RPC request/response
async fn mcp_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Validate content type
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.is_empty() && !content_type.contains("application/json") {
        let err = JsonRpcResponse::error(
            Value::Null,
            error_codes::PARSE_ERROR,
            "content-type must be application/json",
        );
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(json!(err)));
    }

    // Authenticate
    let identity = match authenticate_request(&state, &headers, "serve:http").await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Parse JSON-RPC message (request or notification)
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return parse_error(e),
    };

    // Notifications have no "id" field — accept and return 202
    if msg.get("id").is_none() {
        return (StatusCode::ACCEPTED, Json(json!(null)));
    }

    let req: JsonRpcRequest = match serde_json::from_value(msg) {
        Ok(r) => r,
        Err(e) => return parse_error(e),
    };

    if let Some(mismatch) = check_routing_headers(&headers, &req) {
        let err = JsonRpcResponse::error(
            req.id.clone(),
            crate::protocol::error_codes::HEADER_MISMATCH,
            &mismatch,
        );
        return (StatusCode::BAD_REQUEST, Json(json!(err)));
    }

    // A version we do not speak is rejected wherever it was declared. The
    // body's `_meta` is checked in `dispatch_request`; the header has to be
    // checked here, before it is allowed to select any behavior.
    if let Some(err) = check_protocol_version_header(&headers, &req) {
        return (StatusCode::BAD_REQUEST, Json(json!(err)));
    }

    // Per-request timeout: a single hung backend or dead client must NEVER
    // be able to wedge other in-flight requests. The actual backend hang is
    // already handled inside the transport (stdio has its own timeout) but
    // this is the belt-and-suspenders bound at the proxy boundary.
    let request_timeout = std::time::Duration::from_secs(
        std::env::var("MCP_PROXY_REQUEST_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120),
    );
    let req_id = req.id.clone();
    // Decided before `req` is consumed by dispatch.
    let stateless_peer = declares_stateless_revision(&headers, &req);
    // W3C parent context from inbound headers. When the client is OTel-aware
    // (Claude.ai, an instrumented gateway), this stitches the proxy span
    // under the caller's trace. With telemetry off, this is a no-op.
    use opentelemetry::trace::FutureExt as _;
    let parent_cx = extract_parent_context(&headers);
    let dispatch_fut = dispatch_request(
        &state.proxy,
        req,
        &identity,
        &state.acl,
        "serve:http",
        stateless_peer,
    )
    .with_context(parent_cx);
    let response = match tokio::time::timeout(request_timeout, dispatch_fut).await {
        Ok(resp) => resp,
        Err(_) => JsonRpcResponse::error(
            req_id,
            error_codes::PROXY_ERROR,
            &format!(
                "proxy request timed out after {}s",
                request_timeout.as_secs()
            ),
        ),
    };
    let status = status_for_response(&response, stateless_peer);
    let response_json = serde_json::to_value(&response).unwrap();

    // If this POST came from an SSE session, send the response over the SSE
    // stream and return 202 Accepted (old HTTP+SSE transport).
    //
    // Critical: `tx.send(...).await` would block indefinitely if the SSE
    // channel buffer is full (slow or dead consumer). That used to wedge the
    // entire request handler. We bound the send with a 5s timeout and, on
    // failure, evict the session so future requests fail fast and the client
    // can reconnect.
    if let Some(session_id) = query.get("session_id") {
        let tx = {
            let sessions = state.sessions.lock().await;
            sessions.get(session_id).cloned()
        };
        if let Some(tx) = tx {
            let event = Event::default()
                .event("message")
                .data(serde_json::to_string(&response_json).unwrap());
            let send_result =
                tokio::time::timeout(std::time::Duration::from_secs(5), tx.send(Ok(event))).await;
            match send_result {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    // Receiver gone or buffer wedged → evict the session.
                    state.sessions.lock().await.remove(session_id);
                    tracing::debug!(
                        session_id = %session_id,
                        "sse session evicted: stream send timed out or closed"
                    );
                }
            }
            return (StatusCode::ACCEPTED, Json(json!(null)));
        }
    }

    // Streamable HTTP transport: return response directly
    (status, Json(response_json))
}

// GET /mcp/sse — SSE endpoint for streaming (old HTTP+SSE transport)
// Client connects via SSE, receives `endpoint` event, sends requests via POST,
// and receives JSON-RPC responses as SSE `message` events.
async fn mcp_sse_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // Authenticate
    if let Err(resp) = authenticate_request(&state, &headers, "serve:http").await {
        return resp.into_response();
    }

    // Formally deprecated by 2026-07-28 with a 12-month offramp. Clients on
    // it keep working exactly as before — this is a nudge, not a gate.
    tracing::warn!(
        "client connected over the deprecated HTTP+SSE transport; \
         migrate to Streamable HTTP (POST /mcp) before it is removed"
    );

    // Buffer 256 absorbs bursts (e.g. tools/list snapshot of ~200 tools).
    // Combined with the 5s send timeout in the POST handler, no individual
    // backpressure event can wedge the proxy.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(256);

    // Send the endpoint event so clients know where to POST
    let session_id = uuid::Uuid::new_v4().to_string();
    let endpoint_event = Event::default()
        .event("endpoint")
        .data(format!("/mcp?session_id={session_id}"));

    // Register this session so POST handler can send responses via SSE
    {
        let mut sessions = state.sessions.lock().await;
        sessions.insert(session_id.clone(), tx.clone());
    }

    let sessions_clone = state.sessions.clone();
    let session_id_clone = session_id.clone();
    let mut shutdown_rx = state.shutdown.clone();
    tokio::spawn(async move {
        // Send the endpoint URI with a short bound — if the receiver isn't
        // ready in 5s the client is effectively dead.
        if tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tx.send(Ok(endpoint_event)),
        )
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
        {
            sessions_clone.lock().await.remove(&session_id_clone);
            return;
        }

        // Keep connection alive with periodic pings. We use `try_send` so a
        // momentarily-full buffer never blocks this background task — if the
        // buffer is genuinely backed up, the next interval will catch it.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        let mut consecutive_send_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let ping = Event::default().comment("ping");
                    match tx.try_send(Ok(ping)) {
                        Ok(()) => {
                            consecutive_send_failures = 0;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            break; // Client disconnected
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            consecutive_send_failures += 1;
                            // After ~1 minute (4 × 15s intervals) of full
                            // buffer, treat the session as wedged and evict.
                            if consecutive_send_failures >= 4 {
                                tracing::debug!(
                                    session_id = %session_id_clone,
                                    "sse session evicted: ping buffer full"
                                );
                                break;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    break; // Server shutting down
                }
            }
        }

        // Cleanup session on disconnect/eviction
        let mut sessions = sessions_clone.lock().await;
        sessions.remove(&session_id_clone);
    });

    Sse::new(ReceiverStream::new(rx)).into_response()
}

/// The production `/health` + `/mcp` router, built around an already-running
/// proxy instead of booting one from a `Config`.
///
/// `run_http` owns process-level concerns an integration test must not take
/// on (signal handlers, the audit DB pool, global OTel observers, background
/// reapers). Everything on the request path — authentication, routing-header
/// validation, `dispatch_request`, the SSE fallback — is shared with it, so a
/// test driving this router is driving the real thing.
#[cfg(test)]
pub(super) fn test_router(
    proxy: SharedProxy,
    auth_provider: Arc<dyn AuthProvider>,
    acl: Option<AclConfig>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Router {
    let state = AppState {
        proxy,
        auth_provider,
        acl,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        shutdown,
    };
    Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler).get(mcp_sse_handler))
        .route("/mcp/sse", get(mcp_sse_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bind_addr_loopback() {
        assert!(validate_bind_addr("127.0.0.1:8080", false).is_ok());
        assert!(validate_bind_addr("[::1]:8080", false).is_ok());
    }

    #[test]
    fn test_validate_bind_addr_non_loopback_rejected() {
        let result = validate_bind_addr("0.0.0.0:8080", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--insecure"));
    }

    #[test]
    fn test_validate_bind_addr_non_loopback_with_insecure() {
        assert!(validate_bind_addr("0.0.0.0:8080", true).is_ok());
    }

    #[test]
    fn test_validate_bind_addr_invalid() {
        assert!(validate_bind_addr("not-an-address", false).is_err());
    }

    // --- Mcp-Method / Mcp-Name validation ---

    fn routing_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (k, v) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        headers
    }

    /// Every pre-2026-07-28 client sends neither header. Absence is never a
    /// mismatch.
    #[test]
    fn absent_routing_headers_are_not_a_mismatch() {
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"})));
        assert!(check_routing_headers(&HeaderMap::new(), &req).is_none());
    }

    #[test]
    fn agreeing_routing_headers_pass() {
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"})));
        let headers = routing_headers(&[
            (crate::protocol::HEADER_MCP_METHOD, "tools/call"),
            (crate::protocol::HEADER_MCP_NAME, "search"),
        ]);
        assert!(check_routing_headers(&headers, &req).is_none());
    }

    /// A URI that cannot travel verbatim arrives Base64-sentinel encoded, and
    /// the spec makes decoding before comparison a MUST. Skipping the decode
    /// rejects `resources/read` on any URI with a space or non-ASCII in it.
    #[test]
    fn sentinel_encoded_name_matches_the_uri_it_encodes() {
        for uri in [
            "file:///weekly%20report.txt",
            "file:///a b.txt",
            "https://x/café",
            "s3://bucket/100%",
            "=?base64?literal?=",
        ] {
            let req = JsonRpcRequest::new(1, "resources/read", Some(json!({"uri": uri})));
            let encoded = crate::protocol::header_value(uri).expect("encodable");
            let headers = routing_headers(&[(crate::protocol::HEADER_MCP_NAME, &encoded)]);
            assert!(
                check_routing_headers(&headers, &req).is_none(),
                "{uri} sent as {encoded} was rejected"
            );
        }
    }

    /// A `%` is a legal header character, so a URI carrying one travels
    /// verbatim. Re-encoding it is the bug that broke `resources/read` on
    /// most real URIs; nothing here may reintroduce it.
    #[test]
    fn raw_name_still_matches() {
        let req = JsonRpcRequest::new(
            1,
            "resources/read",
            Some(json!({"uri": "file:///weekly%20report.txt"})),
        );
        let headers = routing_headers(&[(
            crate::protocol::HEADER_MCP_NAME,
            "file:///weekly%20report.txt",
        )]);
        assert!(check_routing_headers(&headers, &req).is_none());
    }

    /// A sentinel we cannot decode is its own rejection condition in the
    /// spec ("a header value contains invalid characters"), not a value to
    /// fall back to comparing literally.
    #[test]
    fn malformed_sentinel_is_rejected() {
        for declared in [
            "=?base64?!!!not-base64!!!?=",
            // Valid Base64, invalid UTF-8.
            "=?base64?/w==?=",
            // A plain value that merely *looks* like the sentinel: clients
            // MUST encode it, so seeing it raw means the value is malformed.
            "=?base64?literal?=",
        ] {
            let req = JsonRpcRequest::new(1, "resources/read", Some(json!({"uri": "file:///x"})));
            let headers = routing_headers(&[(crate::protocol::HEADER_MCP_NAME, declared)]);
            let msg = check_routing_headers(&headers, &req)
                .unwrap_or_else(|| panic!("{declared} was accepted"));
            assert!(msg.contains("malformed"), "unexpected message: {msg}");
        }
    }

    /// Decoding must widen the *encoding* accepted, never the target: an
    /// encoded header still has to name the primitive the body names.
    #[test]
    fn sentinel_encoding_does_not_widen_the_target() {
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"})));
        let encoded = crate::protocol::header_value("delete_everything").expect("encodable");
        // `delete_everything` is header-safe, so force the sentinel form.
        let forced = crate::protocol::header_value("delete_everything\n").expect("encodable");
        for declared in [encoded.as_str(), forced.as_str()] {
            let headers = routing_headers(&[(crate::protocol::HEADER_MCP_NAME, declared)]);
            assert!(
                check_routing_headers(&headers, &req).is_some(),
                "{declared} was accepted for tools/call on 'search'"
            );
        }
    }

    // --- MCP-Protocol-Version header vs body `_meta` ---

    #[test]
    fn protocol_version_header_agreeing_with_meta_passes() {
        let req = JsonRpcRequest::new(
            1,
            "tools/list",
            Some(json!({"_meta": {crate::protocol::meta_keys::PROTOCOL_VERSION: "2026-07-28"}})),
        );
        let headers =
            routing_headers(&[(crate::protocol::HEADER_MCP_PROTOCOL_VERSION, "2026-07-28")]);
        assert!(check_routing_headers(&headers, &req).is_none());
    }

    #[test]
    fn protocol_version_header_disagreeing_with_meta_is_rejected() {
        let req = JsonRpcRequest::new(
            1,
            "tools/list",
            Some(json!({"_meta": {crate::protocol::meta_keys::PROTOCOL_VERSION: "2026-07-28"}})),
        );
        let headers =
            routing_headers(&[(crate::protocol::HEADER_MCP_PROTOCOL_VERSION, "2025-11-25")]);
        assert!(check_routing_headers(&headers, &req).is_some());
    }

    /// Compat: 2025-06-18 through 2025-11-25 clients send the header and no
    /// `_meta` at all. There is nothing to compare it against, and rejecting
    /// them would break every one of them.
    #[test]
    fn protocol_version_header_without_meta_is_accepted() {
        for version in ["2025-11-25", "2025-06-18", "2025-03-26"] {
            let req = JsonRpcRequest::new(1, "tools/list", None);
            let headers =
                routing_headers(&[(crate::protocol::HEADER_MCP_PROTOCOL_VERSION, version)]);
            assert!(check_routing_headers(&headers, &req).is_none());
        }
    }

    // --- HTTP status codes (2026-07-28) ---

    fn versioned(version: &str) -> JsonRpcRequest {
        JsonRpcRequest::new(
            1,
            "tools/list",
            Some(json!({"_meta": {crate::protocol::meta_keys::PROTOCOL_VERSION: version}})),
        )
    }

    #[test]
    fn stateless_revision_is_detected_from_body_or_header() {
        let empty = HeaderMap::new();
        assert!(declares_stateless_revision(
            &empty,
            &versioned(crate::protocol::PROTOCOL_VERSION)
        ));
        assert!(!declares_stateless_revision(
            &empty,
            &versioned(crate::protocol::PROTOCOL_VERSION_LEGACY)
        ));

        let legacy_req = JsonRpcRequest::new(1, "tools/list", None);
        assert!(!declares_stateless_revision(&empty, &legacy_req));
        assert!(declares_stateless_revision(
            &routing_headers(&[(
                crate::protocol::HEADER_MCP_PROTOCOL_VERSION,
                crate::protocol::PROTOCOL_VERSION
            )]),
            &legacy_req
        ));
        assert!(!declares_stateless_revision(
            &routing_headers(&[(
                crate::protocol::HEADER_MCP_PROTOCOL_VERSION,
                crate::protocol::PROTOCOL_VERSION_LEGACY
            )]),
            &legacy_req
        ));
    }

    #[test]
    fn spec_pinned_errors_get_their_status_codes() {
        let mismatch =
            JsonRpcResponse::error(json!(1), error_codes::HEADER_MISMATCH, "header mismatch");
        let unsupported = JsonRpcResponse::unsupported_protocol_version(json!(1), "1999-01-01");
        for resp in [&mismatch, &unsupported] {
            // Unreachable for a legacy peer, so the status does not depend on
            // the peer's declared revision.
            assert_eq!(status_for_response(resp, true), StatusCode::BAD_REQUEST);
            assert_eq!(status_for_response(resp, false), StatusCode::BAD_REQUEST);
        }

        let unknown_method =
            JsonRpcResponse::error(json!(1), error_codes::METHOD_NOT_FOUND, "method not found");
        assert_eq!(
            status_for_response(&unknown_method, true),
            StatusCode::NOT_FOUND
        );
    }

    /// The compat guarantee: a legacy peer must not start seeing 4xx where it
    /// saw 200. Every legacy client that ever asked for a method we do not
    /// implement got a 200 with a `-32601` body.
    #[test]
    fn legacy_peers_keep_seeing_200() {
        let unknown_method =
            JsonRpcResponse::error(json!(1), error_codes::METHOD_NOT_FOUND, "method not found");
        assert_eq!(status_for_response(&unknown_method, false), StatusCode::OK);

        for code in [
            error_codes::INVALID_PARAMS,
            error_codes::INTERNAL_ERROR,
            error_codes::PROXY_ERROR,
        ] {
            let resp = JsonRpcResponse::error(json!(1), code, "boom");
            assert_eq!(status_for_response(&resp, false), StatusCode::OK);
            assert_eq!(status_for_response(&resp, true), StatusCode::OK);
        }

        let ok = JsonRpcResponse::success(json!(1), json!({"tools": []}));
        assert_eq!(status_for_response(&ok, true), StatusCode::OK);
        assert_eq!(status_for_response(&ok, false), StatusCode::OK);
    }

    /// Accepting the encoded form must not accept a *different* primitive.
    #[test]
    fn disagreeing_routing_headers_are_rejected() {
        let call = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"})));
        let cases: Vec<(JsonRpcRequest, Vec<(&str, &str)>)> = vec![
            // Method lies.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"}))),
                vec![(crate::protocol::HEADER_MCP_METHOD, "tools/list")],
            ),
            // Name lies.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "delete_everything")],
            ),
            // Name is a *prefix* of the target, not the target.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "sear")],
            ),
            // Sentinel decoding must not make these equal: the body says
            // `%20`, the header says a literal space. `%` is a legal header
            // character and carries no encoding meaning here.
            (
                JsonRpcRequest::new(1, "resources/read", Some(json!({"uri": "f:///a%20b"}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "f:///a b")],
            ),
            // Percent-escaping a value that needed the sentinel is not the
            // same value either.
            (
                JsonRpcRequest::new(1, "resources/read", Some(json!({"uri": "f:///a b"}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "f:///a%2520b")],
            ),
            // A name on a method that targets no primitive.
            (
                JsonRpcRequest::new(1, "tools/list", None),
                vec![(crate::protocol::HEADER_MCP_NAME, "search")],
            ),
            // Params present but nameless — nothing to match against.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"arguments": {}}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "search")],
            ),
            // A non-string name cannot be matched, so any header is a lie.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": 42}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "42")],
            ),
            // Case differences are differences: names are case-sensitive.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "SEARCH")],
            ),
            // Empty header value never designates anything.
            (
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"}))),
                vec![(crate::protocol::HEADER_MCP_NAME, "")],
            ),
        ];

        for (req, pairs) in cases {
            let headers = routing_headers(&pairs);
            assert!(
                check_routing_headers(&headers, &req).is_some(),
                "{pairs:?} on {} was accepted",
                req.method
            );
        }
        // Sanity: the shared happy case really does pass, so the loop above
        // is not trivially green.
        assert!(check_routing_headers(
            &routing_headers(&[(crate::protocol::HEADER_MCP_NAME, "search")]),
            &call
        )
        .is_none());
    }

    #[test]
    fn test_extract_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer tok-123".parse().unwrap());
        headers.insert("x-forwarded-user", "alice".parse().unwrap());

        let creds = extract_credentials(&headers);
        assert_eq!(creds.get("authorization").unwrap(), "Bearer tok-123");
        assert_eq!(creds.get("x-forwarded-user").unwrap(), "alice");
    }

    #[tokio::test]
    async fn test_sse_session_registration_and_cleanup() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let session_id = "test-session-123".to_string();

        // Simulate registration
        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        {
            let mut map = sessions.lock().await;
            map.insert(session_id.clone(), tx);
            assert!(map.contains_key(&session_id));
        }

        // Simulate cleanup on disconnect
        {
            let mut map = sessions.lock().await;
            map.remove(&session_id);
            assert!(!map.contains_key(&session_id));
        }
    }

    #[tokio::test]
    async fn test_sse_session_response_routing() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let session_id = "route-test".to_string();

        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        {
            let mut map = sessions.lock().await;
            map.insert(session_id.clone(), tx);
        }

        // Simulate sending a response via the session channel
        {
            let map = sessions.lock().await;
            let sender = map.get(&session_id).unwrap();
            let event = Event::default()
                .event("message")
                .data(r#"{"id":1,"jsonrpc":"2.0","result":{"ok":true}}"#);
            sender.send(Ok(event)).await.unwrap();
        }

        // Verify the response arrives
        let received = rx.recv().await.unwrap().unwrap();
        // Event was received successfully
        assert!(format!("{:?}", received).contains("ok"));
    }

    /// Half the pair is still a valid claim: a client may send `Mcp-Method`
    /// on a method that targets no primitive, and gets no `Mcp-Name` to send.
    #[test]
    fn method_header_alone_is_ok() {
        let req = JsonRpcRequest::new(1, "tools/list", None);
        let headers = routing_headers(&[(crate::protocol::HEADER_MCP_METHOD, "tools/list")]);
        assert!(check_routing_headers(&headers, &req).is_none());
    }

    /// Header *names* are case-insensitive on the wire; header *values* are
    /// not — a method is a method, not a case-folded label.
    #[test]
    fn header_name_casing_does_not_matter_but_value_casing_does() {
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "gh__issue"})));
        assert!(
            check_routing_headers(&routing_headers(&[("Mcp-Method", "tools/call")]), &req)
                .is_none()
        );
        assert!(
            check_routing_headers(&routing_headers(&[("mcp-method", "Tools/Call")]), &req)
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_sse_session_missing_does_not_panic() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let map = sessions.lock().await;
        // Looking up a nonexistent session returns None, not panic
        assert!(map.get("nonexistent").is_none());
    }
}
