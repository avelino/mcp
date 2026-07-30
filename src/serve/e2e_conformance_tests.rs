//! End-to-end tests over the real `/mcp` router.
//!
//! The unit tests in `http` exercise `check_routing_headers` and
//! `status_for_response` in isolation, which is where the deny-heavy cases
//! live. What they cannot prove is that a request actually *survives* the
//! whole path — axum header parsing, authentication, header validation,
//! `dispatch_request`, and the HTTP status the client finally sees. Both the
//! header-encoding bug and the status-code bug were invisible to unit tests
//! and only showed up against a real socket, so these drive one.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::cache::ToolCacheStore;
use crate::client::McpClient;
use crate::protocol::{self, error_codes, Resource, Tool};
use crate::server_auth::NoAuth;

use super::http::test_router;
use super::proxy::{ProxyServer, SharedProxy};

/// A live server on a loopback port, plus the URL of its `/mcp` endpoint.
struct TestServer {
    url: String,
    /// Held so the router's shutdown receiver never sees the channel close.
    _shutdown: tokio::sync::watch::Sender<bool>,
}

impl TestServer {
    async fn start(proxy: SharedProxy) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let app = test_router(proxy, Arc::new(NoAuth), None, rx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url: format!("http://{addr}/mcp"),
            _shutdown: tx,
        }
    }

    /// POST a JSON-RPC body with the given extra headers, returning the HTTP
    /// status and the parsed body.
    async fn post(&self, body: Value, headers: &[(&str, &str)]) -> (u16, Value) {
        let client = reqwest::Client::new();
        let mut req = client
            .post(&self.url)
            .header("content-type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req.json(&body).send().await.unwrap();
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap();
        (status, body)
    }
}

/// A backend that answers `resources/read` by echoing back the URI it was
/// asked for, so the test can prove the URI survived every hop unmangled.
async fn spawn_echo_backend() -> String {
    use axum::routing::post;

    let app = axum::Router::new().route(
        "/",
        post(|body: String| async move {
            let msg: Value = serde_json::from_str(&body).unwrap();
            let Some(id) = msg.get("id").cloned() else {
                return axum::Json(Value::Null);
            };
            let params = msg.get("params").cloned().unwrap_or(json!({}));
            let result = match msg["method"].as_str().unwrap() {
                // Every backend we proxy today predates 2026-07-28 and
                // answers the discovery probe with METHOD_NOT_FOUND. Modeling
                // that keeps this an honest legacy backend.
                "server/discover" => {
                    return axum::Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": error_codes::METHOD_NOT_FOUND,
                            "message": "method not found"
                        }
                    }))
                }
                "initialize" => json!({
                    "protocolVersion": protocol::PROTOCOL_VERSION_LEGACY,
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "echo", "version": "0"}
                }),
                "resources/read" => json!({
                    "contents": [{
                        "uri": params["uri"],
                        "text": "body",
                    }]
                }),
                other => panic!("echo backend got unexpected method {other}"),
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

fn empty_proxy() -> SharedProxy {
    let server = ProxyServer::new(
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
        HashMap::new(),
        ToolCacheStore::new(Arc::new(crate::db::DbPool::disabled())),
    );
    Arc::new(Mutex::new(server))
}

/// A proxy with one live backend exposing `resource_uri` under alias `echo`.
async fn proxy_with_resource(resource_uri: &str) -> SharedProxy {
    let url = spawn_echo_backend().await;
    let client = Arc::new(McpClient::connect_via_proxy(&url).await.unwrap());
    let server = ProxyServer::new(
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
        HashMap::new(),
        ToolCacheStore::new(Arc::new(crate::db::DbPool::disabled())),
    );
    let proxy: SharedProxy = Arc::new(Mutex::new(server));
    proxy.lock().await.install_client(
        "echo",
        client,
        &[] as &[Tool],
        &[Resource {
            uri: resource_uri.to_string(),
            name: "doc".to_string(),
            description: None,
            mime_type: None,
            annotations: None,
        }],
        &[],
    );
    proxy
}

/// Whether a `Mcp-Name` value is expected to travel verbatim or wrapped in
/// the Base64 sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    Verbatim,
    Sentinel,
}

/// The bug this pins: a real resource URI holds percent escapes and spaces,
/// and an earlier pass percent-encoded them into the header while the server
/// compared against the raw body — so every `resources/read` on a real URI
/// came back as a header mismatch.
///
/// A `%` and an interior space are both legal RFC 9110 field-value
/// characters, so they travel verbatim and must not be re-encoded. Non-ASCII
/// is not, so it forces the sentinel — and there the server MUST decode
/// before comparing. Both shapes carry a `%` and a space, and both have to
/// come back intact.
#[tokio::test]
async fn resource_uri_needing_header_escaping_survives_the_round_trip() {
    for (backend_uri, expected) in [
        ("file:///reports/weekly%20draft/notes 2.txt", Wire::Verbatim),
        // Same URI plus an accent: still a `%` and a space, now unrepresentable.
        (
            "file:///relatórios/weekly%20draft/notes 2.txt",
            Wire::Sentinel,
        ),
    ] {
        let namespaced = format!("echo__{backend_uri}");
        let server = TestServer::start(proxy_with_resource(backend_uri).await).await;

        let encoded = protocol::header_value(&namespaced).expect("encodable");
        match expected {
            Wire::Verbatim => assert_eq!(
                encoded, namespaced,
                "a `%` or interior space must not be re-encoded"
            ),
            Wire::Sentinel => {
                assert!(
                    encoded.starts_with("=?base64?"),
                    "non-ASCII must force the sentinel, got {encoded}"
                );
                // The `%` is inside the Base64 payload, never percent-escaped.
                assert!(!encoded.contains("%25"), "a `%` was re-encoded: {encoded}");
            }
        }

        let (status, body) = server
            .post(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "resources/read",
                    "params": {
                        "uri": namespaced,
                        "_meta": {
                            protocol::meta_keys::PROTOCOL_VERSION: protocol::PROTOCOL_VERSION
                        }
                    }
                }),
                &[
                    (protocol::HEADER_MCP_METHOD, "resources/read"),
                    (protocol::HEADER_MCP_NAME, &encoded),
                    (
                        protocol::HEADER_MCP_PROTOCOL_VERSION,
                        protocol::PROTOCOL_VERSION,
                    ),
                ],
            )
            .await;

        assert_eq!(status, 200, "{backend_uri} was rejected: {body}");
        assert!(body.get("error").is_none(), "unexpected error: {body}");
        // The backend saw the un-namespaced URI, and the client gets its own
        // namespaced one back, byte for byte.
        assert_eq!(body["result"]["contents"][0]["uri"], namespaced);
    }
}

/// A header that names a different primitive than the body is the attack the
/// validation exists for: a gateway routes on the header, we execute the body.
#[tokio::test]
async fn header_body_mismatch_is_400_with_a_json_rpc_error() {
    let server = TestServer::start(empty_proxy()).await;
    let (status, body) = server
        .post(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo__ask"}
            }),
            &[(protocol::HEADER_MCP_NAME, "echo__delete_everything")],
        )
        .await;

    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], error_codes::HEADER_MISMATCH);
}

/// A malformed Base64 sentinel is its own rejection condition, not a value to
/// fall back to comparing literally.
#[tokio::test]
async fn malformed_sentinel_header_is_400() {
    let server = TestServer::start(empty_proxy()).await;
    let (status, body) = server
        .post(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {"uri": "echo__file:///x"}
            }),
            &[(protocol::HEADER_MCP_NAME, "=?base64?!!!nope!!!?=")],
        )
        .await;

    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], error_codes::HEADER_MISMATCH);
}

/// The spec's era-detection algorithm has clients read the *body* of a 400 to
/// decide whether to fall back to `initialize`. A 200 makes us invisible to
/// it, so the status and the `supported` list are both part of the contract.
#[tokio::test]
async fn unsupported_protocol_version_is_400_with_the_supported_list() {
    let server = TestServer::start(empty_proxy()).await;
    let (status, body) = server
        .post(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {protocol::meta_keys::PROTOCOL_VERSION: "1999-01-01"}
                }
            }),
            &[],
        )
        .await;

    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["code"],
        error_codes::UNSUPPORTED_PROTOCOL_VERSION
    );
    assert_eq!(body["error"]["data"]["requested"], "1999-01-01");
    assert!(body["error"]["data"]["supported"]
        .as_array()
        .unwrap()
        .contains(&json!(protocol::PROTOCOL_VERSION)));
}

#[tokio::test]
async fn unknown_method_is_404_for_a_peer_on_the_new_revision() {
    let server = TestServer::start(empty_proxy()).await;
    for headers in [
        vec![],
        vec![(
            protocol::HEADER_MCP_PROTOCOL_VERSION,
            protocol::PROTOCOL_VERSION,
        )],
    ] {
        let mut params = json!({});
        if headers.is_empty() {
            // Declare the revision in the body instead of the header — both
            // count as opting in.
            params = json!({
                "_meta": {protocol::meta_keys::PROTOCOL_VERSION: protocol::PROTOCOL_VERSION}
            });
        }
        let (status, body) = server
            .post(
                json!({"jsonrpc": "2.0", "id": 1, "method": "no/such/method", "params": params}),
                &headers,
            )
            .await;
        assert_eq!(status, 404, "{body}");
        assert_eq!(body["error"]["code"], error_codes::METHOD_NOT_FOUND);
    }
}

/// The compat guarantee. A pre-2026-07-28 client declares no revision, and
/// every one of them that ever asked for a method we do not implement got a
/// 200 with a `-32601` body. Turning that into a 404 would read as "wrong
/// endpoint" and break them.
#[tokio::test]
async fn unknown_method_stays_200_for_a_legacy_peer() {
    let server = TestServer::start(empty_proxy()).await;
    for headers in [
        vec![],
        vec![(
            protocol::HEADER_MCP_PROTOCOL_VERSION,
            protocol::PROTOCOL_VERSION_LEGACY,
        )],
    ] {
        let (status, body) = server
            .post(
                json!({"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel"}),
                &headers,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["error"]["code"], error_codes::METHOD_NOT_FOUND);
    }
}

/// Ordinary failures are not transport failures: an unknown tool or a denied
/// call keeps riding on 200 with a JSON-RPC error, exactly as before.
#[tokio::test]
async fn ordinary_errors_keep_their_200() {
    let server = TestServer::start(empty_proxy()).await;
    let (status, body) = server
        .post(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "ghost__tool",
                    "_meta": {
                        protocol::meta_keys::PROTOCOL_VERSION: protocol::PROTOCOL_VERSION
                    }
                }
            }),
            &[],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["error"]["code"], error_codes::INVALID_PARAMS);
}

/// A legacy client sends no metadata headers at all and must be served
/// unchanged — this is the whole backwards-compatibility promise in one test.
#[tokio::test]
async fn a_legacy_client_sending_no_metadata_headers_is_served() {
    let server = TestServer::start(empty_proxy()).await;
    let (status, body) = server
        .post(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            &[],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["result"]["tools"].is_array());
}

/// `server/discover` on the wire, not through our own decoder: the field
/// names are the entire contract with a real peer.
#[tokio::test]
async fn server_discover_wire_shape() {
    let server = TestServer::start(empty_proxy()).await;
    let (status, body) = server
        .post(
            json!({"jsonrpc": "2.0", "id": "d1", "method": "server/discover"}),
            &[],
        )
        .await;

    assert_eq!(status, 200, "{body}");
    let result = &body["result"];
    assert!(result["supportedVersions"]
        .as_array()
        .unwrap()
        .contains(&json!(protocol::PROTOCOL_VERSION)));
    assert!(result.get("protocolVersions").is_none());
    assert!(result.get("serverInfo").is_none());
    assert_eq!(
        result["_meta"][protocol::meta_keys::SERVER_INFO]["name"],
        "mcp-proxy"
    );
    assert_eq!(result["resultType"], protocol::RESULT_TYPE_COMPLETE);
    // ACL-filtered surfaces are never offered to a shared cache.
    assert_eq!(result["cacheScope"], "private");
}

/// `MCP-Protocol-Version` is a second, independent way to select 2026-07-28
/// semantics — `declares_stateless_revision` reads it, and the underlying
/// `is_stateless_version` is a bare date compare with no membership test. So
/// a revision we do not speak used to buy the new behavior and never get the
/// `-32022` that tells the client what we actually speak.
#[tokio::test]
async fn unsupported_protocol_version_header_is_400_with_the_supported_list() {
    let server = TestServer::start(empty_proxy()).await;
    for declared in ["2099-01-01", "1999-01-01", "not-a-date"] {
        let (status, body) = server
            .post(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                &[(protocol::HEADER_MCP_PROTOCOL_VERSION, declared)],
            )
            .await;

        assert_eq!(status, 400, "{declared} was accepted: {body}");
        assert_eq!(
            body["error"]["code"],
            error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            "{declared} produced {body}"
        );
        assert_eq!(body["error"]["data"]["requested"], declared);
        assert!(body["error"]["data"]["supported"]
            .as_array()
            .unwrap()
            .contains(&json!(protocol::PROTOCOL_VERSION)));
    }

    // Non-vacuity: every revision we DO speak still passes, including the
    // legacy ones a 2025-06-18-through-2025-11-25 client sends with no `_meta`.
    for declared in protocol::SUPPORTED_PROTOCOL_VERSIONS {
        let (status, body) = server
            .post(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                &[(protocol::HEADER_MCP_PROTOCOL_VERSION, declared)],
            )
            .await;
        assert_eq!(status, 200, "{declared} was rejected: {body}");
    }
}

/// The client runs every routing header through `protocol::header_value`,
/// which is sentinel-capable. The server compared `Mcp-Method` verbatim and
/// never decoded — the exact asymmetry that already rejected every real
/// `resources/read` once, latent on the other header of the pair.
#[tokio::test]
async fn sentinel_encoded_method_header_is_decoded_before_comparison() {
    use base64::Engine as _;
    let sentinel = |v: &str| {
        format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode(v)
        )
    };
    let server = TestServer::start(empty_proxy()).await;

    // `tools/list` is header-safe, so force the sentinel form a client would
    // produce for a value that was not.
    let encoded = sentinel("tools/list");
    assert_ne!(encoded, "tools/list", "the test must exercise a decode");
    let (status, body) = server
        .post(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            &[(protocol::HEADER_MCP_METHOD, &encoded)],
        )
        .await;
    assert_eq!(status, 200, "{encoded} was rejected: {body}");
    assert!(body.get("error").is_none(), "{body}");

    // Decoding widens the encoding accepted, never the target: the decoded
    // value still has to be the method the body names.
    let (status, body) = server
        .post(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            &[(protocol::HEADER_MCP_METHOD, &sentinel("tools/call"))],
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], error_codes::HEADER_MISMATCH);

    // And a sentinel we cannot decode is its own rejection condition, not a
    // value to fall back to comparing literally.
    let (status, body) = server
        .post(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            &[(protocol::HEADER_MCP_METHOD, "=?base64?!!!nope!!!?=")],
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], error_codes::HEADER_MISMATCH);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("malformed"));
}

/// Finding 2 over a real socket. The unit tests in `dispatch` cover the gate
/// itself; this covers the wiring from `mcp_handler` into it, which is where
/// the flag could silently be hardcoded to `true` and nothing would notice.
#[tokio::test]
async fn a_legacy_peer_receives_no_2026_07_28_result_fields() {
    let server = TestServer::start(empty_proxy()).await;
    for (method, params) in [
        ("tools/list", json!({})),
        ("prompts/list", json!({})),
        ("resources/list", json!({})),
        ("initialize", json!({"protocolVersion": "2024-11-05"})),
    ] {
        // Both legacy shapes: no metadata at all, and a pre-2026 version
        // header (what a 2025-06-18-through-2025-11-25 client sends).
        for headers in [
            vec![],
            vec![(
                protocol::HEADER_MCP_PROTOCOL_VERSION,
                protocol::PROTOCOL_VERSION_LEGACY,
            )],
        ] {
            let (status, body) = server
                .post(
                    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
                    &headers,
                )
                .await;
            assert_eq!(status, 200, "{method} {headers:?}: {body}");
            let result = &body["result"];
            for field in ["resultType", "ttlMs", "cacheScope"] {
                assert!(
                    result.get(field).is_none(),
                    "{method} {headers:?} leaked {field}: {result}"
                );
            }
            assert!(
                result
                    .get("_meta")
                    .and_then(|m| m.get(protocol::meta_keys::SERVER_INFO))
                    .is_none(),
                "{method} {headers:?} leaked _meta.serverInfo: {result}"
            );
        }
    }

    // Non-vacuity: the same request declaring the revision DOES get the
    // envelope, so the gate is a gate and not a deletion.
    let (_, body) = server
        .post(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {protocol::meta_keys::PROTOCOL_VERSION: protocol::PROTOCOL_VERSION}
                }
            }),
            &[],
        )
        .await;
    assert_eq!(body["result"]["resultType"], protocol::RESULT_TYPE_COMPLETE);
    assert_eq!(body["result"]["cacheScope"], "private");
    assert_eq!(
        body["result"]["_meta"][protocol::meta_keys::SERVER_INFO]["name"],
        "mcp-proxy"
    );
}
