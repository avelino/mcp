use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::audit::{AuditEntry, AuditLogger};
use crate::client::McpClient;
use crate::config::Config;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, Tool, PROTOCOL_VERSION};
use crate::server_auth::{self, AclConfig, AuthIdentity, AuthProvider, Credentials};

const SEPARATOR: &str = "__";

struct ProxyServer {
    backends: HashMap<String, McpClient>,
    tool_map: HashMap<String, (String, String)>, // namespaced -> (server, original_name)
    tools: Vec<Tool>,
    audit: Arc<AuditLogger>,
}

impl ProxyServer {
    fn new(audit: Arc<AuditLogger>) -> Self {
        Self {
            backends: HashMap::new(),
            tool_map: HashMap::new(),
            tools: Vec::new(),
            audit,
        }
    }

    async fn connect_backends(&mut self, config: &Config) {
        for (name, server_config) in &config.servers {
            eprintln!("[serve] connecting to {name}...");
            match McpClient::connect(server_config).await {
                Ok(mut client) => match client.list_tools().await {
                    Ok(tools) => {
                        eprintln!("[serve] {name}: {} tool(s)", tools.len());
                        for tool in tools {
                            let namespaced = format!("{name}{SEPARATOR}{}", tool.name);
                            let description = match &tool.description {
                                Some(desc) => Some(format!("[{name}] {desc}")),
                                None => Some(format!("[{name}]")),
                            };
                            self.tool_map
                                .insert(namespaced.clone(), (name.clone(), tool.name.clone()));
                            self.tools.push(Tool {
                                name: namespaced,
                                description,
                                input_schema: tool.input_schema,
                            });
                        }
                        self.backends.insert(name.clone(), client);
                    }
                    Err(e) => {
                        eprintln!("[serve] {name}: failed to list tools: {e:#}");
                        let _ = client.shutdown().await;
                    }
                },
                Err(e) => {
                    eprintln!("[serve] {name}: failed to connect: {e:#}");
                }
            }
        }
        eprintln!(
            "[serve] ready — {} backend(s), {} tool(s)",
            self.backends.len(),
            self.tools.len()
        );
    }

    fn handle_initialize(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mcp-proxy",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
    }

    fn handle_tools_list(
        &self,
        id: Value,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> JsonRpcResponse {
        let tools: Vec<Value> = self
            .tools
            .iter()
            .filter(|t| server_auth::is_tool_allowed(identity, &t.name, acl))
            .map(|t| serde_json::to_value(t).unwrap())
            .collect();
        JsonRpcResponse::success(id, json!({ "tools": tools }))
    }

    async fn handle_tools_call(
        &mut self,
        id: Value,
        params: Option<Value>,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::error(id, -32602, "missing params for tools/call");
            }
        };

        let tool_name = match params.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return JsonRpcResponse::error(id, -32602, "missing 'name' in tools/call params");
            }
        };

        if !server_auth::is_tool_allowed(identity, &tool_name, acl) {
            return JsonRpcResponse::error(
                id,
                -32603,
                &format!(
                    "access denied: '{}' cannot use tool '{tool_name}'",
                    identity.subject
                ),
            );
        }

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let (server_name, original_name) = match self.tool_map.get(&tool_name) {
            Some(mapping) => mapping.clone(),
            None => {
                return JsonRpcResponse::error(id, -32602, &format!("unknown tool: {tool_name}"));
            }
        };

        let client = match self.backends.get_mut(&server_name) {
            Some(c) => c,
            None => {
                return JsonRpcResponse::error(
                    id,
                    -32603,
                    &format!("backend '{server_name}' is not connected"),
                );
            }
        };

        match client.call_tool(&original_name, arguments).await {
            Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap()),
            Err(e) => JsonRpcResponse::error(id, -32603, &format!("[{server_name}] {e:#}")),
        }
    }

    fn extract_tool_info(
        req: &JsonRpcRequest,
        tool_map: &HashMap<String, (String, String)>,
    ) -> Option<(String, String)> {
        if req.method != "tools/call" {
            return None;
        }
        let params = req.params.as_ref()?;
        let tool_name = params.get("name")?.as_str()?;
        tool_map
            .get(tool_name)
            .map(|(server, _original)| (tool_name.to_string(), server.clone()))
    }

    async fn handle_request(
        &mut self,
        req: JsonRpcRequest,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
        source: &str,
    ) -> JsonRpcResponse {
        let start = std::time::Instant::now();
        let method = req.method.clone();
        let tool_info = Self::extract_tool_info(&req, &self.tool_map);

        let response = match req.method.as_str() {
            "initialize" => self.handle_initialize(req.id),
            "tools/list" => self.handle_tools_list(req.id, identity, acl),
            "tools/call" => {
                self.handle_tools_call(req.id, req.params, identity, acl)
                    .await
            }
            _ => {
                JsonRpcResponse::error(req.id, -32601, &format!("method not found: {}", req.method))
            }
        };

        self.audit.log(AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: source.to_string(),
            method,
            tool_name: tool_info.as_ref().map(|(t, _)| t.clone()),
            server_name: tool_info.as_ref().map(|(_, s)| s.clone()),
            identity: identity.subject.clone(),
            duration_ms: start.elapsed().as_millis() as u64,
            success: response.error.is_none(),
            error_message: response.error.as_ref().map(|e| e.message.clone()),
            arguments: None,
        });

        response
    }

    async fn shutdown_all(&mut self) {
        for (name, mut client) in self.backends.drain() {
            if let Err(e) = client.shutdown().await {
                eprintln!("[serve] {name}: shutdown error: {e:#}");
            }
        }
    }
}

// --- Stdio mode ---

pub async fn run_stdio(config: Config) -> Result<()> {
    let audit = AuditLogger::open(&config.audit).unwrap_or(AuditLogger::Disabled);
    let mut server = ProxyServer::new(Arc::new(audit));
    let identity = AuthIdentity::anonymous();
    let acl = config.server_auth.acl.clone();

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut backends_connected = false;

    eprintln!("[serve] waiting for MCP client...");

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try parsing as a request (has "id")
        if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(line) {
            if !backends_connected && req.method != "initialize" {
                server.connect_backends(&config).await;
                backends_connected = true;
            }

            let response = server
                .handle_request(req, &identity, &acl, "serve:stdio")
                .await;

            let mut data = serde_json::to_string(&response)?;
            data.push('\n');
            stdout.write_all(data.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        // Notifications (no id) — just acknowledge silently
        // e.g. "notifications/initialized", "notifications/cancelled"
    }

    server.shutdown_all().await;
    eprintln!("[serve] shutting down");
    Ok(())
}

// --- HTTP mode ---

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use tokio_stream::wrappers::ReceiverStream;

type SharedProxy = Arc<Mutex<ProxyServer>>;
type SseSender = tokio::sync::mpsc::Sender<Result<Event, std::convert::Infallible>>;
type SessionMap = Arc<Mutex<HashMap<String, SseSender>>>;

#[derive(Clone)]
struct AppState {
    proxy: SharedProxy,
    auth_provider: Arc<dyn AuthProvider>,
    acl: Option<AclConfig>,
    sessions: SessionMap,
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
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthIdentity, (StatusCode, Json<Value>)> {
    let creds = extract_credentials(headers);
    state.auth_provider.authenticate(&creds).await.map_err(|e| {
        let err =
            JsonRpcResponse::error(Value::Null, -32000, &format!("authentication failed: {e}"));
        (StatusCode::UNAUTHORIZED, Json(json!(err)))
    })
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

    let auth_provider = server_auth::build_auth_provider(&config.server_auth)?;
    let acl = config.server_auth.acl.clone();

    let audit = AuditLogger::open(&config.audit).unwrap_or(AuditLogger::Disabled);
    let mut server = ProxyServer::new(Arc::new(audit));
    server.connect_backends(&config).await;
    let shared: SharedProxy = Arc::new(Mutex::new(server));

    let state = AppState {
        proxy: shared.clone(),
        auth_provider,
        acl,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    // Log all incoming requests for debugging
    let request_logger =
        axum::middleware::from_fn(|req: axum::extract::Request, next: axum::middleware::Next| async move {
            eprintln!(
                "[serve] {} {} {}",
                req.method(),
                req.uri(),
                req.headers()
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
            );
            next.run(req).await
        });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler).get(mcp_sse_handler))
        .route("/mcp/sse", get(mcp_sse_handler))
        .fallback(|req: axum::extract::Request| async move {
            let path = req.uri().path().to_string();
            let method = req.method().clone();
            eprintln!(
                "[serve] UNHANDLED {} {} (headers: {:?})",
                method,
                path,
                req.headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
                    .collect::<Vec<_>>()
            );
            // OAuth/OIDC discovery endpoints: return 404 with valid JSON
            // so clients that probe for auth don't crash on empty bodies
            if path.contains(".well-known") || path == "/register" {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "not_found", "error_description": "This server does not support OAuth"})),
                );
            }
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
        })
        .layer(request_logger)
        .with_state(state.clone());

    eprintln!("[serve] HTTP server listening on {sock_addr}");
    if sock_addr.ip().is_loopback() {
        eprintln!("[serve] bound to loopback — local access only");
    } else {
        eprintln!("[serve] WARNING: bound to non-loopback address without TLS");
    }

    let listener = tokio::net::TcpListener::bind(sock_addr).await?;

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown_signal = async {
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
        eprintln!("\n[serve] shutdown signal received");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Cleanup backends
    let mut proxy = state.proxy.lock().await;
    proxy.shutdown_all().await;
    eprintln!("[serve] shutting down");

    Ok(())
}

// GET /health
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let proxy = state.proxy.lock().await;
    let body = json!({
        "status": "ok",
        "backends": proxy.backends.len(),
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
    let identity = match authenticate_request(&state, &headers).await {
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

    let mut proxy = state.proxy.lock().await;
    let response = proxy
        .handle_request(req, &identity, &state.acl, "serve:http")
        .await;

    let response_json = serde_json::to_value(&response).unwrap();

    // If this POST came from an SSE session, send the response over the SSE stream
    // and return 202 Accepted (old HTTP+SSE transport)
    if let Some(session_id) = query.get("session_id") {
        let sessions = state.sessions.lock().await;
        if let Some(tx) = sessions.get(session_id) {
            let event = Event::default()
                .event("message")
                .data(serde_json::to_string(&response_json).unwrap());
            let _ = tx.send(Ok(event)).await;
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
    if let Err(resp) = authenticate_request(&state, &headers).await {
        return resp.into_response();
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(32);

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
    tokio::spawn(async move {
        // Send endpoint URI
        if tx.send(Ok(endpoint_event)).await.is_err() {
            return;
        }

        // Keep connection alive with periodic pings
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            let ping = Event::default().comment("ping");
            if tx.send(Ok(ping)).await.is_err() {
                break; // Client disconnected
            }
        }

        // Cleanup session on disconnect
        let mut sessions = sessions_clone.lock().await;
        sessions.remove(&session_id_clone);
    });

    Sse::new(ReceiverStream::new(rx)).into_response()
}

// --- Public entry point ---

pub async fn run(config: Config, http_addr: Option<&str>, insecure: bool) -> Result<()> {
    match http_addr {
        Some(addr) => run_http(config, addr, insecure).await,
        None => run_stdio(config).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Tool;

    #[test]
    fn test_split_tool_name_via_separator() {
        assert_eq!(
            "sentry__search_issues".split_once(SEPARATOR),
            Some(("sentry", "search_issues"))
        );
        assert_eq!(
            "slack__send_message".split_once(SEPARATOR),
            Some(("slack", "send_message"))
        );
        assert_eq!("no_separator".split_once(SEPARATOR), None);
        assert_eq!("a__b__c".split_once(SEPARATOR), Some(("a", "b__c")));
    }

    #[test]
    fn test_tool_namespacing() {
        let tool = Tool {
            name: "search_issues".to_string(),
            description: Some("Search for issues".to_string()),
            input_schema: None,
        };

        let server_name = "sentry";
        let namespaced = format!("{server_name}{SEPARATOR}{}", tool.name);
        let description = format!("[{server_name}] {}", tool.description.as_deref().unwrap());

        assert_eq!(namespaced, "sentry__search_issues");
        assert_eq!(description, "[sentry] Search for issues");
    }

    #[test]
    fn test_proxy_server_initialize_response() {
        let server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let resp = server.handle_initialize(Value::from(1));
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "mcp-proxy");
    }

    #[test]
    fn test_proxy_server_initialize_with_string_id() {
        let server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let resp = server.handle_initialize(Value::String("req-1".to_string()));
        assert!(resp.error.is_none());
        assert_eq!(resp.id, Some(Value::String("req-1".to_string())));
    }

    #[test]
    fn test_proxy_server_empty_tools_list() {
        let server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        let resp = server.handle_tools_list(Value::from(2), &identity, &None);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_proxy_server_tools_list_with_tools() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search for issues".to_string()),
            input_schema: None,
        });
        server.tool_map.insert(
            "sentry__search_issues".to_string(),
            ("sentry".to_string(), "search_issues".to_string()),
        );

        let identity = AuthIdentity::anonymous();
        let resp = server.handle_tools_list(Value::from(3), &identity, &None);
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "sentry__search_issues");
        assert_eq!(tools[0]["description"], "[sentry] Search for issues");
    }

    #[tokio::test]
    async fn test_proxy_server_unknown_tool() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        let params = Some(serde_json::json!({"name": "nonexistent__tool"}));
        let resp = server
            .handle_tools_call(Value::from(4), params, &identity, &None)
            .await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("unknown tool"));
    }

    #[tokio::test]
    async fn test_proxy_server_missing_params() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        let resp = server
            .handle_tools_call(Value::from(5), None, &identity, &None)
            .await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test]
    async fn test_proxy_server_missing_name_in_params() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        let params = Some(serde_json::json!({"arguments": {}}));
        let resp = server
            .handle_tools_call(Value::from(6), params, &identity, &None)
            .await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("missing 'name'"));
    }

    #[tokio::test]
    async fn test_proxy_server_backend_not_connected() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        server.tool_map.insert(
            "ghost__tool".to_string(),
            ("ghost".to_string(), "tool".to_string()),
        );
        let params = Some(serde_json::json!({"name": "ghost__tool"}));
        let resp = server
            .handle_tools_call(Value::from(7), params, &identity, &None)
            .await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("not connected"));
    }

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

    #[tokio::test]
    async fn test_handle_request_unknown_method() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "unknown/method", None);
        let resp = server.handle_request(req, &identity, &None, "test").await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert!(err.message.contains("method not found"));
    }

    #[tokio::test]
    async fn test_handle_request_initialize() {
        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "initialize", None);
        let resp = server.handle_request(req, &identity, &None, "test").await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn test_protocol_version_is_current() {
        assert_eq!(PROTOCOL_VERSION, "2025-11-25");
    }

    #[test]
    fn test_notification_has_no_id() {
        // JSON-RPC notifications have no "id" field
        let notification: Value = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert!(notification.get("id").is_none());

        // Requests have an "id" field
        let request: Value =
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        assert!(request.get("id").is_some());
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

    #[test]
    fn test_tools_list_filtered_by_acl() {
        use crate::server_auth::{AclConfig, AclPolicy, AclRule};

        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search".to_string()),
            input_schema: None,
        });
        server.tools.push(Tool {
            name: "slack__send_message".to_string(),
            description: Some("[slack] Send".to_string()),
            input_schema: None,
        });

        let acl = Some(AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        });

        let bob = AuthIdentity::new("bob", vec![]);
        let resp = server.handle_tools_list(Value::from(10), &bob, &acl);
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "slack__send_message");
    }

    #[tokio::test]
    async fn test_tools_call_denied_by_acl() {
        use crate::server_auth::{AclConfig, AclPolicy, AclRule};

        let mut server = ProxyServer::new(Arc::new(AuditLogger::Disabled));
        server.tool_map.insert(
            "sentry__search".to_string(),
            ("sentry".to_string(), "search".to_string()),
        );

        let acl = Some(AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        });

        let bob = AuthIdentity::new("bob", vec![]);
        let params = Some(serde_json::json!({"name": "sentry__search"}));
        let resp = server
            .handle_tools_call(Value::from(11), params, &bob, &acl)
            .await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("access denied"));
    }

    #[test]
    fn test_extract_tool_info() {
        let mut tool_map = HashMap::new();
        tool_map.insert(
            "sentry__search_issues".to_string(),
            ("sentry".to_string(), "search_issues".to_string()),
        );

        // tools/call with valid tool
        let req = JsonRpcRequest::new(
            1,
            "tools/call",
            Some(serde_json::json!({"name": "sentry__search_issues"})),
        );
        let info = ProxyServer::extract_tool_info(&req, &tool_map);
        assert!(info.is_some());
        let (tool, server) = info.unwrap();
        assert_eq!(tool, "sentry__search_issues");
        assert_eq!(server, "sentry");

        // non tools/call method
        let req2 = JsonRpcRequest::new(1, "tools/list", None);
        assert!(ProxyServer::extract_tool_info(&req2, &tool_map).is_none());

        // unknown tool
        let req3 = JsonRpcRequest::new(
            1,
            "tools/call",
            Some(serde_json::json!({"name": "unknown__tool"})),
        );
        assert!(ProxyServer::extract_tool_info(&req3, &tool_map).is_none());
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
}
