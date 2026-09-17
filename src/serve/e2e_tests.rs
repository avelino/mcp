//! End-to-end tests across the client ⇄ `mcp serve` seam.
//!
//! The 2026-07-28 dual stack was built as two independent slices — the
//! client (`src/client.rs`, `src/transport/**`) and the proxy
//! (`src/serve/**`) — that had never been run against each other. Every
//! assertion here therefore goes over a real TCP socket, through the real
//! [`super::http::test_router`] (same handlers `run_http` mounts: auth,
//! routing-header validation, [`dispatch_request`]) and, for the new-client
//! cases, through the real [`McpClient`]. Nothing on the request path is
//! mocked; the only stub is the *backend* the proxy fans out to, which
//! deliberately speaks the old revision because every backend in the wild
//! does.
//!
//! Coverage:
//! 1. new client ⇄ new proxy — `server/discover`, stateless agreement,
//!    `_meta` on every request, **no** `Mcp-Session-Id`.
//! 2. legacy client ⇄ new proxy — no `_meta`, no new headers, `initialize`
//!    handshake, sessions still honored.
//! 3. an unsupported revision declared in `_meta` → `-32022`.
//! 4. `Mcp-Method`/`Mcp-Name` disagreeing with the body → `-32020`; sending
//!    neither → served.
//! 5. the MRTR round trip, relayed end to end.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::cache::ToolCacheStore;
use crate::client::McpClient;
use crate::protocol::{
    error_codes, meta_keys, Prompt, Resource, Tool, HEADER_MCP_METHOD, HEADER_MCP_NAME,
    PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY,
};
use crate::server_auth::NoAuth;

use super::http::test_router;
use super::proxy::{ProxyServer, SharedProxy};

/// Session id the harness hands out on every response, exactly like every
/// pre-2026-07-28 peer does. It exists so "the new client sends no
/// `Mcp-Session-Id`" is a real assertion: the client is *given* one to echo
/// and must decline to.
const SESSION_ID: &str = "e2e-session-42";

/// A resource whose URI carries a percent escape — the single most common
/// shape of a real resource URI, and one that cannot travel verbatim in an
/// HTTP header.
const ENCODED_URI: &str = "file:///weekly%20report.txt";
/// A URI that genuinely cannot travel in a header field value, so it must
/// go through the Base64 sentinel.
const UNICODE_URI: &str = "file:///relatório semanal.txt";

/// Tool on the 2026-07-28 backend whose `region` argument carries an
/// `x-mcp-header` annotation.
const ANNOTATED_TOOL: &str = "execute_sql";

// --- harness -----------------------------------------------------------

/// One request as it arrived at the proxy, captured off the wire.
#[derive(Clone, Debug)]
struct SeenRequest {
    session_id: Option<String>,
    mcp_method: Option<String>,
    mcp_name: Option<String>,
    body: Value,
}

impl SeenRequest {
    fn method(&self) -> &str {
        self.body
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    }

    fn meta(&self) -> Option<&Value> {
        self.body.get("params")?.get("_meta")
    }
}

type SeenRequests = Arc<StdMutex<Vec<SeenRequest>>>;

/// One request as it arrived at the *backend*, headers included.
///
/// The proxy is a client on that hop, so the backwards-compatibility promise
/// applies to it in both directions: a legacy backend must not start seeing
/// 2026-07-28 metadata just because the peer in front of us speaks it.
#[derive(Clone, Debug)]
struct BackendRequest {
    method: String,
    params: Value,
    headers: HashMap<String, String>,
}

impl BackendRequest {
    /// Header names the proxy sent that belong to 2026-07-28.
    fn mcp_metadata_headers(&self) -> Vec<&str> {
        self.headers
            .keys()
            .map(String::as_str)
            .filter(|k| {
                *k == "mcp-method"
                    || *k == "mcp-name"
                    || *k == "mcp-protocol-version"
                    || k.starts_with("mcp-param-")
            })
            .collect()
    }
}

type BackendLog = Arc<Mutex<Vec<BackendRequest>>>;

fn record(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            Some((
                k.as_str().to_ascii_lowercase(),
                v.to_str().ok()?.to_string(),
            ))
        })
        .collect()
}

/// Record every inbound request, then stamp a session id on the way out.
async fn observe(State(seen): State<SeenRequests>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("test bodies are small");
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    seen.lock().unwrap().push(SeenRequest {
        session_id: header("mcp-session-id"),
        mcp_method: header(HEADER_MCP_METHOD),
        mcp_name: header(HEADER_MCP_NAME),
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    });

    let mut resp = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    resp.headers_mut()
        .insert("Mcp-Session-Id", SESSION_ID.parse().unwrap());
    resp
}

/// A running `mcp serve` HTTP endpoint plus the wire log of what reached it.
struct Harness {
    url: String,
    seen: SeenRequests,
    /// Held only to keep the SSE keepalive channel open for the router's
    /// lifetime; dropping it would signal shutdown.
    _shutdown: tokio::sync::watch::Sender<bool>,
    /// Everything the stub backend observed, in order.
    backend_seen: BackendLog,
}

impl Harness {
    fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// Requests the proxy handled after `skip` leading ones (the negotiation
    /// probe), which is where the steady-state assertions belong.
    fn seen_after(&self, skip: usize) -> Vec<SeenRequest> {
        self.seen().split_off(skip)
    }

    async fn backend(&self) -> Vec<BackendRequest> {
        self.backend_seen.lock().await.clone()
    }

    async fn backend_calls(&self, method: &str) -> Vec<BackendRequest> {
        self.backend()
            .await
            .into_iter()
            .filter(|r| r.method == method)
            .collect()
    }
}

/// Spawn a backend that speaks the **old** revision: it rejects
/// `server/discover` and answers `initialize`, which is what every MCP server
/// in the wild does today.
async fn spawn_legacy_backend() -> (String, BackendLog) {
    use axum::routing::post;

    let seen: BackendLog = Arc::new(Mutex::new(Vec::new()));
    let app =
        axum::Router::new()
            .route(
                "/",
                post(
                    |State(seen): State<BackendLog>,
                     headers: axum::http::HeaderMap,
                     body: String| async move {
                        let msg: Value = serde_json::from_str(&body).unwrap();
                        let method = msg["method"].as_str().unwrap_or_default().to_string();
                        let params = msg.get("params").cloned().unwrap_or(json!({}));
                        // Recorded for EVERY inbound message, headers included:
                        // what the proxy sends onward is as much part of the
                        // compat contract as what it answers.
                        seen.lock().await.push(BackendRequest {
                            method: method.clone(),
                            params: params.clone(),
                            headers: record(&headers),
                        });
                        let Some(id) = msg.get("id").cloned() else {
                            return axum::Json(Value::Null); // notifications/initialized
                        };
                        let result = match method.as_str() {
                            // A pre-2026-07-28 server has never heard of this.
                            "server/discover" => {
                                return axum::Json(json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": error_codes::METHOD_NOT_FOUND,
                                        "message": "method not found: server/discover"
                                    }
                                }))
                            }
                            "initialize" => json!({
                                "protocolVersion": PROTOCOL_VERSION_LEGACY,
                                "capabilities": {"tools": {}, "resources": {}},
                                "serverInfo": {"name": "stub", "version": "0"}
                            }),
                            "resources/read" => json!({
                                "contents": [{
                                    "uri": params["uri"],
                                    "text": "the weekly report",
                                    "mimeType": "text/plain"
                                }]
                            }),
                            "prompts/get" => json!({
                                "messages": [{
                                    "role": "user",
                                    "content": {"type": "text", "text": "hello"}
                                }]
                            }),
                            "tools/call" => {
                                match params["name"].as_str().unwrap_or_default() {
                                    // MRTR: keep asking until answers come back.
                                    "ask" => {
                                        if let Some(responses) = params.get("inputResponses") {
                                            json!({
                                                "resultType": "complete",
                                                "content": [{
                                                    "type": "text",
                                                    "text": responses.to_string()
                                                }],
                                                "echoedState": params.get("requestState"),
                                            })
                                        } else {
                                            json!({
                                                "resultType": "input_required",
                                                "inputRequests": [
                                                    {"id": "confirm", "prompt": "sure?"}
                                                ],
                                                "requestState": "opaque-token"
                                            })
                                        }
                                    }
                                    _ => json!({
                                        "content": [{
                                            "type": "text",
                                            "text": params["arguments"]["q"]
                                                .as_str()
                                                .unwrap_or_default()
                                        }]
                                    }),
                                }
                            }
                            other => panic!("stub backend got unexpected method {other}"),
                        };
                        axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
                    },
                ),
            )
            .with_state(Arc::clone(&seen));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/"), seen)
}

/// A proxy with one connected backend exposing `ask`, `echo` and a resource
/// whose URI needs escaping.
async fn proxy_with_backend(backend_url: &str) -> SharedProxy {
    let client = Arc::new(McpClient::connect_via_proxy(backend_url).await.unwrap());
    // The backend rejected `server/discover`, so the proxy's own client must
    // have fallen back to the handshake. If this ever flips, the proxy would
    // start sending `_meta` to servers that never agreed to it.
    assert_eq!(
        client.protocol_version(),
        PROTOCOL_VERSION_LEGACY,
        "a backend that rejects server/discover must be spoken to as legacy"
    );

    let pool = Arc::new(crate::db::DbPool::disabled());
    let mut server = ProxyServer::new(
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
        HashMap::new(),
        ToolCacheStore::new(pool),
    );
    let tool = |name: &str| Tool {
        name: name.to_string(),
        description: None,
        input_schema: None,
        annotations: None,
    };
    server.install_client(
        "stub",
        client,
        &[tool("ask"), tool("echo")],
        &[
            Resource {
                uri: ENCODED_URI.to_string(),
                name: "weekly".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                annotations: None,
            },
            Resource {
                uri: UNICODE_URI.to_string(),
                name: "relatorio".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                annotations: None,
            },
        ],
        &[] as &[Prompt],
    );
    Arc::new(Mutex::new(server))
}

/// Spawn a backend that speaks **2026-07-28**: it answers `server/discover`,
/// advertises a tool whose `region` argument is annotated with
/// `x-mcp-header`, and runs the MRTR two-leg exchange on it.
///
/// This is the intersection nothing else covers. `Mcp-Param-*` headers only
/// go to a peer on the new revision, and the MRTR continuation only exists on
/// a retry — so proving both survive the same proxied `tools/call` needs a
/// backend that is modern *and* asks a question.
async fn spawn_stateless_annotated_backend() -> (String, BackendLog) {
    use axum::routing::post;

    let seen: BackendLog = Arc::new(Mutex::new(Vec::new()));
    let app =
        axum::Router::new()
            .route(
                "/",
                post(
                    |State(seen): State<BackendLog>,
                     headers: axum::http::HeaderMap,
                     body: String| async move {
                        let msg: Value = serde_json::from_str(&body).unwrap();
                        let method = msg["method"].as_str().unwrap_or_default().to_string();
                        let params = msg.get("params").cloned().unwrap_or(json!({}));
                        seen.lock().await.push(BackendRequest {
                            method: method.clone(),
                            params: params.clone(),
                            headers: record(&headers),
                        });
                        let Some(id) = msg.get("id").cloned() else {
                            return axum::Json(Value::Null);
                        };
                        let result = match method.as_str() {
                            "server/discover" => json!({
                                "resultType": "complete",
                                "supportedVersions": [PROTOCOL_VERSION],
                                "capabilities": {"tools": {}},
                                "_meta": {
                                    meta_keys::SERVER_INFO: {"name": "sql", "version": "2.0"},
                                },
                            }),
                            "tools/list" => json!({
                                "resultType": "complete",
                                "tools": [{
                                    "name": ANNOTATED_TOOL,
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {
                                            "region": {"type": "string", "x-mcp-header": "Region"},
                                            "query": {"type": "string"},
                                        },
                                    },
                                }],
                            }),
                            "tools/call" => {
                                if params.get("inputResponses").is_some() {
                                    json!({
                                        "resultType": "complete",
                                        "content": [{"type": "text", "text": "done"}],
                                        "echoedState": params.get("requestState"),
                                    })
                                } else {
                                    json!({
                                        "resultType": "input_required",
                                        "inputRequests": [{"id": "confirm", "prompt": "sure?"}],
                                        "requestState": "opaque-token",
                                    })
                                }
                            }
                            other => panic!("sql backend got unexpected method {other}"),
                        };
                        axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
                    },
                ),
            )
            .with_state(Arc::clone(&seen));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/"), seen)
}

/// A proxy fronting the annotated 2026-07-28 backend.
///
/// Goes through the real `list_tools()` rather than installing a handcrafted
/// `Tool`: that call is what validates and *learns* the `x-mcp-header`
/// annotations, so skipping it would leave the client with nothing to mirror
/// and make the header assertions vacuous.
async fn proxy_with_stateless_backend(backend_url: &str) -> SharedProxy {
    let client = Arc::new(McpClient::connect_via_proxy(backend_url).await.unwrap());
    assert_eq!(
        client.protocol_version(),
        PROTOCOL_VERSION,
        "a backend that answers server/discover must be spoken to as 2026-07-28"
    );
    let tools = client.list_tools().await.unwrap();
    assert_eq!(tools.len(), 1, "the annotated tool must survive validation");

    let mut server = ProxyServer::new(
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
        HashMap::new(),
        ToolCacheStore::new(Arc::new(crate::db::DbPool::disabled())),
    );
    server.install_client("sql", client, &tools, &[] as &[Resource], &[] as &[Prompt]);
    Arc::new(Mutex::new(server))
}

/// Boot the real proxy router on a free port, fronting `proxy`.
async fn start_with(proxy: SharedProxy, backend_seen: BackendLog) -> Harness {
    let seen: SeenRequests = Arc::new(StdMutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let app = test_router(proxy, Arc::new(NoAuth), None, shutdown_rx).layer(
        axum::middleware::from_fn_with_state(Arc::clone(&seen), observe),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Harness {
        url: format!("http://{addr}/mcp"),
        seen,
        _shutdown: shutdown_tx,
        backend_seen,
    }
}

/// The default harness: a legacy backend, which is what every MCP server in
/// the wild is today.
async fn start_proxy() -> Harness {
    let (backend_url, backend_seen) = spawn_legacy_backend().await;
    let proxy = proxy_with_backend(&backend_url).await;
    start_with(proxy, backend_seen).await
}

/// POST a raw JSON-RPC body with an explicit header set — this is how a
/// client that is *not* ours (a legacy one, or a hostile one) reaches the
/// proxy.
async fn post_raw(url: &str, body: Value, headers: &[(&str, &str)]) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut req = client.post(url).json(&body);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

fn error_code(resp: &Value) -> Option<i64> {
    resp.get("error")?.get("code")?.as_i64()
}

// --- 1. new client ⇄ new proxy ----------------------------------------

#[tokio::test]
async fn new_client_and_new_proxy_go_stateless_end_to_end() {
    let h = start_proxy().await;

    let client = McpClient::connect_via_proxy(&h.url).await.unwrap();
    assert_eq!(
        client.protocol_version(),
        PROTOCOL_VERSION,
        "two 2026-07-28 peers must agree on 2026-07-28"
    );

    let tools = client.list_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["stub__ask", "stub__echo"]);

    let called = client
        .call_tool("stub__echo", json!({"q": "hello"}))
        .await
        .unwrap();
    assert_eq!(called.content[0].text.as_deref(), Some("hello"));

    // --- what actually went over the wire ---
    let seen = h.seen();
    assert_eq!(
        seen[0].method(),
        "server/discover",
        "negotiation must start with the discovery probe"
    );
    // The probe carries the standard `_meta`, exactly as the spec's
    // `server/discover` example does: a strict modern server MUST reject a
    // request that omits it, and an older peer rejects or ignores
    // `server/discover` either way.
    let probe_meta = seen[0]
        .meta()
        .expect("the documented probe carries the standard _meta");
    assert_eq!(probe_meta[meta_keys::PROTOCOL_VERSION], PROTOCOL_VERSION);
    assert_eq!(probe_meta[meta_keys::CLIENT_INFO]["name"], "mcp");
    assert!(probe_meta.get(meta_keys::CLIENT_CAPABILITIES).is_some());

    assert!(
        !seen.iter().any(|r| r.method() == "initialize"),
        "a stateless peer must never run the handshake"
    );

    let steady_state = h.seen_after(1);
    assert_eq!(
        steady_state.len(),
        2,
        "the tools/list + tools/call above must reach the proxy, or the loop \
         below asserts nothing: {steady_state:?}"
    );
    for r in steady_state {
        let meta = r
            .meta()
            .unwrap_or_else(|| panic!("{} carried no _meta", r.method()));
        assert_eq!(meta[meta_keys::PROTOCOL_VERSION], PROTOCOL_VERSION);
        assert_eq!(meta[meta_keys::CLIENT_INFO]["name"], "mcp");
        assert!(meta.get(meta_keys::CLIENT_CAPABILITIES).is_some());
        // The other half of the routing-header gate: a peer on the new
        // revision DOES get labelled. `legacy_client_is_served_exactly_as_before`
        // pins the negative on the backend hop; without this the gate could be
        // "never send them" and both tests would still pass.
        assert_eq!(
            r.mcp_method.as_deref(),
            Some(r.method()),
            "{} was not labelled with Mcp-Method",
            r.method()
        );
        // The exact risk the client slice flagged: the proxy handed out a
        // session id on every response, and a stateless client must ignore
        // it rather than keep a dead handshake alive.
        assert_eq!(
            r.session_id,
            None,
            "{} still sent Mcp-Session-Id after going stateless",
            r.method()
        );
    }
}

/// The proxy really does hand out a session id, so the assertion above is
/// about a client that declines one — not about a peer that never offered.
#[tokio::test]
async fn the_proxy_offers_a_session_id_the_stateless_client_declines() {
    let h = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(&h.url)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok()),
        Some(SESSION_ID)
    );
}

/// A resource URI is the one `Mcp-Name` value that routinely cannot travel
/// verbatim in an HTTP header — percent escapes, spaces and UTF-8 are all
/// legal in a URI. The client encodes it; the proxy must still recognize it
/// as naming the resource the body targets.
#[tokio::test]
async fn resource_uri_needing_header_escaping_survives_the_round_trip() {
    let h = start_proxy().await;
    let client = McpClient::connect_via_proxy(&h.url).await.unwrap();

    let namespaced = format!("stub__{ENCODED_URI}");
    let result = client
        .read_resource_raw(json!({"uri": namespaced}), &[])
        .await
        .unwrap_or_else(|e| panic!("reading {namespaced} failed: {e:#}"));

    assert_eq!(result["contents"][0]["uri"], namespaced);
    assert_eq!(result["contents"][0]["text"], "the weekly report");

    // A percent escape is an ordinary visible character in a header value,
    // so it must travel VERBATIM. Re-encoding it here is what made client
    // and server disagree and rejected this exact call with -32020.
    let read = h
        .seen()
        .into_iter()
        .find(|r| r.method() == "resources/read")
        .expect("the read reached the proxy");
    let name = read.mcp_name.expect("a name header was sent");
    assert_eq!(
        name, namespaced,
        "a percent escape must not be re-encoded on the way out"
    );
}

/// The other half of the encoding seam: a URI that genuinely cannot sit in a
/// header field value must go out Base64-wrapped and be decoded by the proxy
/// before it compares the header to the body.
#[tokio::test]
async fn resource_uri_requiring_the_sentinel_survives_the_round_trip() {
    let h = start_proxy().await;
    let client = McpClient::connect_via_proxy(&h.url).await.unwrap();

    let namespaced = format!("stub__{UNICODE_URI}");
    let result = client
        .read_resource_raw(json!({"uri": namespaced}), &[])
        .await
        .unwrap_or_else(|e| panic!("reading {namespaced} failed: {e:#}"));
    assert_eq!(result["contents"][0]["uri"], namespaced);

    let read = h
        .seen()
        .into_iter()
        .find(|r| r.method() == "resources/read")
        .expect("the read reached the proxy");
    let name = read.mcp_name.expect("a name header was sent");
    assert!(
        name.starts_with("=?base64?") && name.ends_with("?="),
        "a non-ASCII URI must use the Base64 sentinel, got {name:?}"
    );
    // Non-vacuity: the header really is a different string from the body
    // value, so the proxy genuinely had to decode it to accept the call.
    assert_ne!(name, namespaced);
    assert_eq!(
        crate::protocol::decode_header_value(&name).as_deref(),
        Some(namespaced.as_str())
    );
}

// --- 2. legacy client ⇄ new proxy -------------------------------------

#[tokio::test]
async fn legacy_client_is_served_exactly_as_before() {
    let h = start_proxy().await;

    // A pre-2026-07-28 client: `initialize`, then `notifications/initialized`,
    // then plain calls. No `_meta`, no `Mcp-Method`, no `Mcp-Name`.
    let (status, init) = post_raw(
        &h.url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION_LEGACY,
                "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "0.1"}
            }
        }),
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert!(init.get("error").is_none(), "initialize failed: {init}");
    assert_eq!(
        init["result"]["protocolVersion"], PROTOCOL_VERSION_LEGACY,
        "the proxy must answer the handshake in the revision the client asked for"
    );
    assert!(init["result"]["serverInfo"]["name"].is_string());

    let (status, _) = post_raw(
        &h.url,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        &[],
    )
    .await;
    assert_eq!(status, 202, "notifications are accepted, not answered");

    // A legacy client echoes back the session id it was handed.
    let session = [("Mcp-Session-Id", SESSION_ID)];

    let (status, list) = post_raw(
        &h.url,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        &session,
    )
    .await;
    assert_eq!(status, 200);
    assert!(list.get("error").is_none(), "tools/list failed: {list}");
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "stub__ask");

    let (status, call) = post_raw(
        &h.url,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "stub__echo", "arguments": {"q": "legacy"}}
        }),
        &session,
    )
    .await;
    assert_eq!(status, 200);
    assert!(call.get("error").is_none(), "tools/call failed: {call}");
    assert_eq!(call["result"]["content"][0]["text"], "legacy");

    // --- direction 1: the RESPONSES this client received ---
    //
    // Asserting on `h.seen()` here would be circular: those are the requests
    // this test itself built, with no headers and no `_meta`, so a loop over
    // them cannot fail. What can regress is what we send BACK. A legacy peer
    // negotiated a revision in which `resultType`, `ttlMs`, `cacheScope` and
    // `_meta.serverInfo` do not exist, and a client validating a result
    // against a closed schema is a real client.
    for (label, result) in [
        ("initialize", &init["result"]),
        ("tools/list", &list["result"]),
        ("tools/call", &call["result"]),
    ] {
        for field in ["resultType", "ttlMs", "cacheScope"] {
            assert!(
                result.get(field).is_none(),
                "{label} answered a legacy client with a 2026-07-28 {field}: {result}"
            );
        }
        assert!(
            result
                .get("_meta")
                .and_then(|m| m.get(meta_keys::SERVER_INFO))
                .is_none(),
            "{label} answered a legacy client with _meta.serverInfo: {result}"
        );
    }

    // --- direction 2: what the proxy sent onward to the legacy BACKEND ---
    //
    // The proxy is the client on that hop. `backend_tool_call_params` strips
    // `_meta` for exactly this reason, so the routing headers must be stripped
    // with it — one hop cannot be half on each revision.
    let backend = h.backend().await;
    let (probe, conversation): (Vec<_>, Vec<_>) =
        backend.iter().partition(|r| r.method == "server/discover");

    // The probe is the one message that is *allowed* to be labelled: it asks
    // "are you on 2026-07-28?" in a method that did not exist before it, and
    // a legacy backend answers -32601 either way. It is also the non-vacuity
    // check — the recorder demonstrably sees these headers when they are sent.
    assert_eq!(probe.len(), 1, "exactly one negotiation probe: {backend:?}");
    assert!(
        !probe[0].mcp_metadata_headers().is_empty(),
        "the probe must still be routable"
    );

    // Everything after the probe is the legacy conversation, and must look
    // exactly like it did before 2026-07-28 existed.
    assert!(
        conversation.len() >= 3,
        "expected initialize + initialized + the relayed call: {conversation:?}"
    );
    for r in &conversation {
        assert!(
            r.mcp_metadata_headers().is_empty(),
            "the proxy sent {:?} to a legacy backend on {}",
            r.mcp_metadata_headers(),
            r.method
        );
        assert!(
            r.params.get("_meta").is_none(),
            "the proxy leaked _meta to a legacy backend on {}",
            r.method
        );
    }

    // The session id the client sent was accepted rather than rejected as a
    // removed header.
    let with_session = h
        .seen()
        .into_iter()
        .filter(|r| r.session_id.as_deref() == Some(SESSION_ID))
        .count();
    assert_eq!(with_session, 2, "the harness does observe session ids");
}

// --- 3. unsupported protocol version ----------------------------------

#[tokio::test]
async fn unsupported_declared_version_is_rejected() {
    let h = start_proxy().await;

    let (status, resp) = post_raw(
        &h.url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {meta_keys::PROTOCOL_VERSION: "1999-01-01"}}
        }),
        &[],
    )
    .await;
    // The spec requires 400 here, and other clients' dual-era detection
    // depends on it: they inspect the body of a 400 to decide whether the
    // peer is modern or whether to fall back to `initialize`.
    assert_eq!(
        status, 400,
        "UnsupportedProtocolVersionError must ride on 400 Bad Request"
    );
    assert_eq!(
        error_code(&resp),
        Some(error_codes::UNSUPPORTED_PROTOCOL_VERSION)
    );
    // And it must name the versions we do speak, or the client has nothing
    // to downgrade to.
    let data = &resp["error"]["data"];
    assert_eq!(data["requested"], "1999-01-01");
    assert!(data["supported"]
        .as_array()
        .expect("supported list")
        .contains(&json!(crate::protocol::PROTOCOL_VERSION)));

    // The same request declaring a revision we speak is served.
    let (_, ok) = post_raw(
        &h.url,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": {meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION}}
        }),
        &[],
    )
    .await;
    assert!(ok.get("error").is_none(), "{ok}");
    assert_eq!(ok["result"]["tools"].as_array().unwrap().len(), 2);
}

// --- 4. routing header mismatch ---------------------------------------

#[tokio::test]
async fn routing_headers_must_agree_with_the_body() {
    let h = start_proxy().await;
    let call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "stub__echo", "arguments": {"q": "hi"}}
    });

    // A gateway that routed on a lie.
    for bad in [
        vec![(HEADER_MCP_METHOD, "tools/list")],
        vec![(HEADER_MCP_NAME, "stub__ask")],
        vec![
            (HEADER_MCP_METHOD, "tools/call"),
            (HEADER_MCP_NAME, "stub__ask"),
        ],
    ] {
        let (status, resp) = post_raw(&h.url, call.clone(), &bad).await;
        assert_eq!(status, 400, "{bad:?} should be rejected");
        assert_eq!(
            error_code(&resp),
            Some(error_codes::HEADER_MISMATCH),
            "{bad:?} produced {resp}"
        );
    }

    // `Mcp-Name` on a method that targets no primitive is also a lie.
    let (_, resp) = post_raw(
        &h.url,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        &[(HEADER_MCP_NAME, "stub__echo")],
    )
    .await;
    assert_eq!(error_code(&resp), Some(error_codes::HEADER_MISMATCH));

    // Headers that agree are served.
    let (status, ok) = post_raw(
        &h.url,
        call.clone(),
        &[
            (HEADER_MCP_METHOD, "tools/call"),
            (HEADER_MCP_NAME, "stub__echo"),
        ],
    )
    .await;
    assert_eq!(status, 200);
    assert!(ok.get("error").is_none(), "{ok}");

    // And a client that sends NEITHER header — every client that predates
    // 2026-07-28 — is served untouched.
    let (status, ok) = post_raw(&h.url, call, &[]).await;
    assert_eq!(status, 200);
    assert!(ok.get("error").is_none(), "{ok}");
    assert_eq!(ok["result"]["content"][0]["text"], "hi");
}

// --- 5. MRTR relay ----------------------------------------------------

#[tokio::test]
async fn mrtr_round_trip_relays_through_the_proxy() {
    let h = start_proxy().await;
    let client = McpClient::connect_via_proxy(&h.url).await.unwrap();

    // Leg 1: the backend needs more input. `call_tool` would reject an
    // interim result, so a relaying client stays on the raw call.
    let interim = client
        .call_tool_raw(json!({
            "name": "stub__ask",
            "arguments": {"q": "delete everything?"},
        }))
        .await
        .unwrap();
    assert!(
        crate::protocol::is_input_required(&interim),
        "interim result was flattened: {interim}"
    );
    assert_eq!(interim["inputRequests"][0]["id"], "confirm");
    assert_eq!(interim["requestState"], "opaque-token");

    // A typed accessor must say what happened rather than fail to parse.
    let err = client
        .call_tool("stub__ask", json!({"q": "delete everything?"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("MRTR"), "unhelpful MRTR error: {err}");

    // Leg 2: answers plus the opaque state come back through the proxy.
    let final_result = client
        .request_raw(
            "tools/call",
            Some(json!({
                "name": "stub__ask",
                "arguments": {"q": "delete everything?"},
                "inputResponses": [{"id": "confirm", "value": true}],
                "requestState": interim["requestState"],
            })),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        final_result["resultType"],
        crate::protocol::RESULT_TYPE_COMPLETE
    );
    assert_eq!(final_result["echoedState"], "opaque-token");

    // The backend saw both legs, un-namespaced, and — because it speaks the
    // old revision — never saw the stateless `_meta` the client sent us.
    let backend = h.backend_calls("tools/call").await;
    assert_eq!(backend.len(), 3, "one leg per call: {backend:?}");
    assert!(backend.iter().all(|r| r.params["name"] == "ask"));
    assert!(
        backend.iter().all(|r| r.params.get("_meta").is_none()),
        "the proxy leaked stateless _meta to a legacy backend: {backend:?}"
    );
    assert!(backend[0].params.get("inputResponses").is_none());
    assert_eq!(backend[2].params["inputResponses"][0]["value"], true);
    assert_eq!(backend[2].params["requestState"], "opaque-token");
}

// --- 6. x-mcp-header mirroring ACROSS the proxy ------------------------

/// The defect that lived exactly between two slices: the client grew
/// `Mcp-Param-*` mirroring in `call_tool_raw`, the proxy grew MRTR
/// continuation passthrough in `request_raw`, and each was complete on its
/// own. `dispatch` used the one without headers, so the entire `x-mcp-header`
/// feature was inert for every call `mcp serve` proxies — while both slices'
/// tests stayed green.
///
/// This drives the intersection: an **annotated** tool called **through the
/// proxy**, on a **retry carrying an MRTR continuation**. The backend must
/// see the header AND the continuation on the same request.
#[tokio::test]
async fn annotated_tool_called_through_the_proxy_carries_headers_and_the_mrtr_continuation() {
    let (backend_url, backend_seen) = spawn_stateless_annotated_backend().await;
    let h = start_with(
        proxy_with_stateless_backend(&backend_url).await,
        backend_seen,
    )
    .await;
    let client = McpClient::connect_via_proxy(&h.url).await.unwrap();

    let namespaced = format!("sql__{ANNOTATED_TOOL}");
    // The proxy must re-advertise the annotation, or its own client has
    // nothing to mirror on the outbound hop.
    let tools = client.list_tools().await.unwrap();
    assert_eq!(tools[0].name, namespaced);
    assert_eq!(
        tools[0].input_schema.as_ref().unwrap()["properties"]["region"]["x-mcp-header"],
        "Region"
    );

    // Leg 1: the backend asks a question.
    let interim = client
        .call_tool_raw(json!({
            "name": namespaced,
            "arguments": {"region": "us-west1", "query": "SELECT 1"},
        }))
        .await
        .unwrap();
    assert!(crate::protocol::is_input_required(&interim));

    // Leg 2: the answers plus the opaque state go back through the proxy.
    let final_result = client
        .call_tool_raw(json!({
            "name": namespaced,
            "arguments": {"region": "us-west1", "query": "SELECT 1"},
            "inputResponses": [{"id": "confirm", "value": true}],
            "requestState": interim["requestState"],
        }))
        .await
        .unwrap();
    assert_eq!(final_result["echoedState"], "opaque-token");

    let calls = h.backend_calls("tools/call").await;
    assert_eq!(calls.len(), 2, "one backend leg per call: {calls:?}");

    for (leg, r) in calls.iter().enumerate() {
        // The header the annotation exists for. Absent on both legs before
        // the fix, because the proxy never went through `call_tool_raw`.
        assert_eq!(
            r.headers.get("mcp-param-region").map(String::as_str),
            Some("us-west1"),
            "leg {leg} reached the backend with no Mcp-Param-Region: {:?}",
            r.headers
        );
        // Un-annotated arguments stay in the body only.
        assert!(!r.headers.contains_key("mcp-param-query"));
        assert_eq!(r.params["name"], ANNOTATED_TOOL, "leg {leg} name");
    }

    // And the continuation the *other* raw API was the only one preserving.
    // Rebuilding params as `{name, arguments}` — which is how the header path
    // used to work — drops both of these silently.
    assert!(calls[0].params.get("inputResponses").is_none());
    assert_eq!(calls[1].params["inputResponses"][0]["value"], true);
    assert_eq!(calls[1].params["requestState"], "opaque-token");
}

// --- forward_identity --------------------------------------------------
//
// The two halves of identity forwarding were each covered in isolation
// (`ProxyServer::identity_headers` in `proxy.rs`, the header merge in
// `client.rs`) and the seam between them was not. Replacing the headers the
// dispatcher passes with `&[]` used to leave the whole suite green, which is
// the one mistake these tests exist to catch. Each one therefore asserts on
// what reached the *backend*, over a real socket.

/// A proxy whose single backend opts into identity forwarding.
///
/// `static_headers` is the server's ordinary `headers` map, so a test can set
/// up the name collision the transport would otherwise resolve by appending.
async fn proxy_forwarding_identity(
    backend_url: &str,
    audit: Arc<AuditLogger>,
    static_headers: HashMap<String, String>,
) -> SharedProxy {
    let client = Arc::new(McpClient::connect_via_proxy(backend_url).await.unwrap());

    let mut configs = HashMap::new();
    configs.insert(
        "stub".to_string(),
        crate::config::ServerConfig::Http {
            url: backend_url.to_string(),
            headers: static_headers,
            forward_identity: Some(crate::config::ForwardIdentity {
                header: "X-MCP-Subject".to_string(),
                roles_header: Some("X-MCP-Roles".to_string()),
            }),
            tool_acl: None,
            idle_timeout: Default::default(),
            min_idle_timeout: None,
            max_idle_timeout: None,
        },
    );

    let mut server = ProxyServer::new(
        audit,
        configs,
        HashMap::new(),
        ToolCacheStore::new(Arc::new(crate::db::DbPool::disabled())),
    );
    server.install_client(
        "stub",
        client,
        &[Tool {
            name: "echo".to_string(),
            description: None,
            input_schema: None,
            annotations: None,
        }],
        &[Resource {
            uri: ENCODED_URI.to_string(),
            name: "weekly".to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
            annotations: None,
        }],
        &[Prompt {
            name: "greet".to_string(),
            description: None,
            arguments: None,
        }],
    );
    Arc::new(Mutex::new(server))
}

fn ana() -> crate::server_auth::AuthIdentity {
    crate::server_auth::AuthIdentity::new("ana", vec!["business".to_string()])
}

/// One proxied call, as `identity`.
async fn call_as(
    proxy: &SharedProxy,
    identity: &crate::server_auth::AuthIdentity,
    method: &str,
    params: Value,
) -> crate::protocol::JsonRpcResponse {
    super::dispatch::dispatch_request(
        proxy,
        crate::protocol::JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: json!(1),
            method: method.to_string(),
            params: Some(params),
        },
        identity,
        &None,
        "test",
        true,
    )
    .await
}

/// The tool call the refusal tests use: routable, allowed by the ACL, and
/// stopped only by whatever is wrong with the caller's identity.
async fn echo_as(
    proxy: &SharedProxy,
    identity: &crate::server_auth::AuthIdentity,
) -> crate::protocol::JsonRpcResponse {
    call_as(
        proxy,
        identity,
        "tools/call",
        json!({"name": "stub__echo", "arguments": {}}),
    )
    .await
}

/// Assert the backend was never called — a refusal must not reach it under
/// the shared credential.
async fn assert_backend_untouched(backend_seen: &BackendLog, why: &str) {
    assert!(
        !backend_seen
            .lock()
            .await
            .iter()
            .any(|r| r.method == "tools/call"),
        "{why}"
    );
}

/// Every method that reaches a backend carries the caller's identity.
///
/// `tools/call` was wired first and the other two were not, which left a
/// backend owning data per user reading it back as the service account.
#[tokio::test]
async fn the_caller_identity_reaches_the_backend_on_every_proxied_method() {
    let (backend_url, backend_seen) = spawn_legacy_backend().await;
    let proxy = proxy_forwarding_identity(
        &backend_url,
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
    )
    .await;

    let calls = [
        (
            "tools/call",
            json!({"name": "stub__echo", "arguments": {"q": "hi"}}),
        ),
        (
            "resources/read",
            json!({"uri": format!("stub__{ENCODED_URI}")}),
        ),
        ("prompts/get", json!({"name": "stub__greet"})),
    ];

    for (method, params) in &calls {
        let resp = call_as(&proxy, &ana(), method, params.clone()).await;
        assert!(resp.error.is_none(), "{method} failed: {:?}", resp.error);
    }

    for (method, _) in &calls {
        let seen = backend_seen
            .lock()
            .await
            .iter()
            .find(|r| r.method == *method)
            .cloned()
            .unwrap_or_else(|| panic!("{method} never reached the backend"));
        assert_eq!(
            seen.headers.get("x-mcp-subject").map(String::as_str),
            Some("ana"),
            "{method} reached the backend with no forwarded subject: {:?}",
            seen.headers
        );
        assert_eq!(
            seen.headers.get("x-mcp-roles").map(String::as_str),
            Some("business"),
            "{method} lost the forwarded roles"
        );
    }
}

/// A refusal is a response like any other, so it leaves through the same
/// funnel and lands in the audit log.
///
/// It used to leave by an early `return` that skipped `finish_audit`
/// entirely: a call the ACL had already allowed, stopped by the proxy, with
/// no audit entry, no metric, and no result envelope. That is the one event
/// an audit log is least able to do without.
#[tokio::test]
async fn a_refused_identity_is_still_audited() {
    let (backend_url, backend_seen) = spawn_legacy_backend().await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let proxy = proxy_forwarding_identity(
        &backend_url,
        Arc::new(AuditLogger::Stream { sender: tx }),
        HashMap::new(),
    )
    .await;

    // A subject carrying CRLF is header injection, so the call is refused.
    let injected = crate::server_auth::AuthIdentity::new("ana\r\nX-Admin: 1", vec![]);
    let resp = echo_as(&proxy, &injected).await;

    let err = resp.error.expect("the call must be refused");
    assert!(err.message.contains("cannot forward caller identity"));
    assert_backend_untouched(
        &backend_seen,
        "a refused call must not reach the backend anyway",
    )
    .await;

    let entry = rx.try_recv().expect("the refusal must be audited");
    assert_eq!(entry.tool_name.as_deref(), Some("stub__echo"));
    assert_eq!(entry.server_name.as_deref(), Some("stub"));
    assert!(
        !entry.success && entry.error_message.is_some(),
        "the audit entry must record the refusal, got {entry:?}"
    );
}

/// The static `headers` collision, refused end to end.
///
/// Without the check both headers go out — the transport appends rather than
/// replaces — and the backend picks which one names the caller.
#[tokio::test]
async fn a_static_header_collision_stops_the_call_before_the_backend() {
    let (backend_url, backend_seen) = spawn_legacy_backend().await;
    let mut static_headers = HashMap::new();
    static_headers.insert("X-MCP-Subject".to_string(), "svc-account".to_string());
    let proxy = proxy_forwarding_identity(
        &backend_url,
        Arc::new(AuditLogger::Disabled),
        static_headers,
    )
    .await;

    let resp = echo_as(&proxy, &ana()).await;

    assert!(resp
        .error
        .expect("the ambiguous call must be refused")
        .message
        .contains("static `headers`"));
    assert_backend_untouched(
        &backend_seen,
        "the backend must never see two subject headers",
    )
    .await;
}

/// An unauthenticated caller is refused rather than announced as `anonymous`.
#[tokio::test]
async fn an_unauthenticated_caller_never_reaches_a_forwarding_backend() {
    let (backend_url, backend_seen) = spawn_legacy_backend().await;
    let proxy = proxy_forwarding_identity(
        &backend_url,
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
    )
    .await;

    let resp = echo_as(&proxy, &crate::server_auth::AuthIdentity::anonymous()).await;

    assert!(resp
        .error
        .expect("an anonymous caller must be refused")
        .message
        .contains("not authenticated"));
    assert_backend_untouched(&backend_seen, "anonymous must not reach the backend").await;
}
