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
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::server_auth::oauth_as::{self, AsState};
use crate::server_auth::{self, AclConfig, AuthIdentity, AuthProvider, Credentials};

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
            let err =
                JsonRpcResponse::error(Value::Null, -32000, &format!("authentication failed: {e}"));
            Err((StatusCode::UNAUTHORIZED, Json(json!(err))))
        }
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

pub async fn run_http(config: Config, bind_addr: &str, insecure: bool) -> Result<()> {
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

    let pool = if config.audit.output == crate::audit::AuditOutput::File {
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
                let cached: Vec<String> = proxy.discovered_backends.iter().cloned().collect();
                for name in &cached {
                    proxy.discovered_backends.remove(name);
                }
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
        let err =
            JsonRpcResponse::error(Value::Null, -32700, "content-type must be application/json");
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
        Err(e) => {
            let err = JsonRpcResponse::error(Value::Null, -32700, &format!("parse error: {e}"));
            return (StatusCode::BAD_REQUEST, Json(json!(err)));
        }
    };

    // Notifications have no "id" field — accept and return 202
    if msg.get("id").is_none() {
        return (StatusCode::ACCEPTED, Json(json!(null)));
    }

    let req: JsonRpcRequest = match serde_json::from_value(msg) {
        Ok(r) => r,
        Err(e) => {
            let err = JsonRpcResponse::error(Value::Null, -32700, &format!("parse error: {e}"));
            return (StatusCode::BAD_REQUEST, Json(json!(err)));
        }
    };

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
    let response_json = match tokio::time::timeout(
        request_timeout,
        dispatch_request(&state.proxy, req, &identity, &state.acl, "serve:http"),
    )
    .await
    {
        Ok(resp) => serde_json::to_value(&resp).unwrap(),
        Err(_) => {
            let err = JsonRpcResponse::error(
                req_id,
                -32000,
                &format!(
                    "proxy request timed out after {}s",
                    request_timeout.as_secs()
                ),
            );
            serde_json::to_value(&err).unwrap()
        }
    };

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
    (StatusCode::OK, Json(response_json))
}

// GET /mcp/sse — SSE endpoint for streaming (old HTTP+SSE transport)
// Client connects via SSE, receives `endpoint` event, sends requests via POST,
// and receives JSON-RPC responses as SSE `message` events.
async fn mcp_sse_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // Authenticate
    if let Err(resp) = authenticate_request(&state, &headers, "serve:http").await {
        return resp.into_response();
    }

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

    #[tokio::test]
    async fn test_sse_session_missing_does_not_panic() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let map = sessions.lock().await;
        // Looking up a nonexistent session returns None, not panic
        assert!(map.get("nonexistent").is_none());
    }
}
