use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Newest MCP revision we speak. Revisions are ISO dates, so string
/// ordering is chronological ordering — that is what the `>=` checks
/// below rely on.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// First stateless revision: no `initialize` handshake, no
/// `Mcp-Session-Id`, per-request `_meta`, mandatory `resultType`.
pub const PROTOCOL_VERSION_STATELESS: &str = "2026-07-28";

/// Revision we spoke before 2026-07-28. Kept because every backend we
/// proxy is still on it (or older) and MUST keep working untouched.
pub const PROTOCOL_VERSION_LEGACY: &str = "2025-11-25";

/// Revisions we accept from a peer, newest first. Anything outside this
/// set gets `UNSUPPORTED_PROTOCOL_VERSION`.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// `_meta` keys defined by the 2026-07-28 revision. Requests carry their
/// own version and identity now that there is no handshake to hold it.
pub mod meta_keys {
    pub const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
    pub const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
    pub const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
    pub const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
    // `io.modelcontextprotocol/logLevel` and `.../subscriptionId` belong to
    // per-request logging and `subscriptions/listen`, neither of which we
    // implement. They land here when those features do.
    /// W3C trace context, now a documented `_meta` convention. Carrying it
    /// here (not only as an HTTP header) is what gives stdio backends a
    /// trace at all.
    pub const TRACEPARENT: &str = "traceparent";
    pub const TRACESTATE: &str = "tracestate";
    pub const BAGGAGE: &str = "baggage";
}

/// JSON-RPC error codes. `-32000..=-32019` stays implementation-defined,
/// `-32020..=-32099` is reserved for the MCP spec.
pub mod error_codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Resource-not-found moved here from `-32002` in 2026-07-28.
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// Implementation-defined range, grandfathered for existing usage.
    pub const PROXY_ERROR: i64 = -32000;
    pub const HEADER_MISMATCH: i64 = -32020;
    pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
    // `-32021` MissingRequiredClientCapability is unused: we declare no
    // capability a peer is required to hold. It lands here when we do.
}

/// Required `resultType` discriminator on every result.
pub const RESULT_TYPE_COMPLETE: &str = "complete";
/// Interim result of a [Multi Round-Trip Request][mrtr].
///
/// [mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
pub const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

/// HTTP headers required on Streamable HTTP POSTs by 2026-07-28, so
/// gateways can route and meter without parsing the JSON body.
pub const HEADER_MCP_METHOD: &str = "Mcp-Method";
pub const HEADER_MCP_NAME: &str = "Mcp-Name";

/// Protocol version header, required on every Streamable HTTP POST and
/// required to agree with `_meta`'s `protocolVersion`.
pub const HEADER_MCP_PROTOCOL_VERSION: &str = "MCP-Protocol-Version";

/// Markers of the Base64 sentinel encoding. Case-sensitive and exact, per
/// the spec.
const SENTINEL_PREFIX: &str = "=?base64?";
const SENTINEL_SUFFIX: &str = "?=";

/// Upper bound on an encoded header value. The routing headers exist so
/// gateways can route and meter cheaply; a value longer than this is not
/// routable in practice and risks tripping a server's header-size limit, so
/// it is omitted rather than sent truncated (and therefore wrong).
pub const MAX_HEADER_VALUE_LEN: usize = 1024;

/// Whether a value may travel in a header verbatim.
///
/// RFC 9110 field values allow visible ASCII, space and horizontal tab, but
/// not leading or trailing whitespace. Anything else — non-ASCII, control
/// characters, padded edges — has to be encoded.
fn is_plain_header_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| matches!(b, 0x21..=0x7E | b' ' | b'\t'))
        && !value.starts_with([' ', '\t'])
        && !value.ends_with([' ', '\t'])
}

/// Encode a value for `Mcp-Name` (or `Mcp-Param-*`), or `None` when there is
/// nothing routable to say.
///
/// `Mcp-Name` carries a tool name or a resource URI, and neither is
/// constrained to header-safe characters: a URI can hold UTF-8 and spaces,
/// and a misbehaving backend can advertise a tool name with a newline in it.
/// The spec's answer is the Base64 sentinel `=?base64?{value}?=`, which
/// servers MUST decode before comparing against the body. A plain value that
/// happens to look like the sentinel is encoded too, so the form is never
/// ambiguous.
///
/// This lives in the shared contract, not in the client transport, because
/// the *server* validating `Mcp-Name` has to decode exactly what the client
/// encoded. Two copies of this rule that drift apart mean valid requests get
/// rejected as header mismatches — see `serve::http::header_matches`.
pub fn header_value(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }

    let looks_like_sentinel =
        value.starts_with(SENTINEL_PREFIX) && value.ends_with(SENTINEL_SUFFIX);
    let encoded = if is_plain_header_safe(value) && !looks_like_sentinel {
        value.to_string()
    } else {
        use base64::Engine as _;
        format!(
            "{SENTINEL_PREFIX}{}{SENTINEL_SUFFIX}",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    };

    if encoded.len() > MAX_HEADER_VALUE_LEN {
        return None;
    }
    Some(encoded)
}

/// Decode a header value a peer sent us, undoing [`header_value`].
///
/// A sentinel-wrapped value is decoded; anything else is already literal.
/// `None` means the sentinel was malformed — invalid Base64 or invalid
/// UTF-8 — which is a rejectable request, not a value to guess at.
pub fn decode_header_value(declared: &str) -> Option<String> {
    let Some(inner) = declared
        .strip_prefix(SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(SENTINEL_SUFFIX))
    else {
        return Some(declared.to_string());
    };

    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .ok()?;
    String::from_utf8(bytes).ok()
}

pub fn is_version_supported(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// Whether a revision uses the stateless shape (no handshake, `_meta`
/// carries version/identity, `resultType` required). Revisions are ISO
/// dates, so a lexicographic compare is a chronological one.
pub fn is_stateless_version(version: &str) -> bool {
    version >= PROTOCOL_VERSION_STATELESS
}

/// Value for the `Mcp-Name` header: the primitive a request targets.
/// `None` for methods that address no single primitive (the `*/list`
/// family), where the header is omitted rather than sent empty.
pub fn mcp_name_for(method: &str, params: Option<&Value>) -> Option<String> {
    let params = params?;
    let field = match method {
        "tools/call" | "prompts/get" => "name",
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => "uri",
        _ => return None,
    };
    params
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// `resultType` of a peer's result. A result from an earlier-revision
/// peer omits the field and MUST be read as `"complete"`.
pub fn result_type(result: &Value) -> &str {
    result
        .get("resultType")
        .and_then(|v| v.as_str())
        .unwrap_or(RESULT_TYPE_COMPLETE)
}

/// Whether a result is an MRTR interim result awaiting client input.
pub fn is_input_required(result: &Value) -> bool {
    result_type(result) == RESULT_TYPE_INPUT_REQUIRED
}

/// Cache visibility of a cacheable result.
///
/// The spec also defines `"public"`, which lets shared intermediaries cache
/// the response. We never emit it and so do not model it: every list result
/// we return is ACL-filtered per identity, so a shared cache would serve one
/// identity's tools to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScope {
    Private,
}

impl CacheScope {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheScope::Private => "private",
        }
    }
}

/// Set `resultType: "complete"` on an outgoing result, leaving an
/// already-set value (an MRTR `input_required`) alone.
pub fn set_result_type_complete(result: &mut Value) {
    if let Some(obj) = result.as_object_mut() {
        obj.entry("resultType")
            .or_insert_with(|| Value::String(RESULT_TYPE_COMPLETE.to_string()));
    }
}

/// Attach the `CacheableResult` freshness hints required on the
/// `tools/list`, `prompts/list`, `resources/list`, `resources/read` and
/// `resources/templates/list` results.
pub fn set_cache_hints(result: &mut Value, ttl_ms: u64, scope: CacheScope) {
    if let Some(obj) = result.as_object_mut() {
        obj.insert("ttlMs".to_string(), Value::from(ttl_ms));
        obj.insert(
            "cacheScope".to_string(),
            Value::String(scope.as_str().to_string()),
        );
    }
}

/// Merge a key into a result's `_meta`, creating the object when absent.
pub fn set_result_meta(result: &mut Value, key: &str, value: Value) {
    if let Some(obj) = result.as_object_mut() {
        let meta = obj
            .entry("_meta")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(meta_obj) = meta.as_object_mut() {
            meta_obj.insert(key.to_string(), value);
        }
    }
}

/// Protocol version a request declares in `params._meta`. `None` means a
/// pre-2026-07-28 peer, which is not an error — it is the legacy path.
pub fn request_protocol_version(params: Option<&Value>) -> Option<&str> {
    params?
        .get("_meta")?
        .get(meta_keys::PROTOCOL_VERSION)?
        .as_str()
}

// --- JSON-RPC 2.0 ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(id: u64, method: &str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Value::from(id),
            method: method.to_string(),
            params,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: Some("2.0".to_string()),
            id: Some(id),
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i64, message: &str) -> Self {
        Self {
            jsonrpc: Some("2.0".to_string()),
            id: Some(id),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }

    pub fn error_with_data(id: Value, code: i64, message: &str, data: Value) -> Self {
        Self {
            jsonrpc: Some("2.0".to_string()),
            id: Some(id),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: Some(data),
            }),
        }
    }

    /// `UnsupportedProtocolVersionError`, which the spec requires to carry
    /// the server's supported list so the client can pick one and retry
    /// instead of just failing.
    pub fn unsupported_protocol_version(id: Value, requested: &str) -> Self {
        Self::error_with_data(
            id,
            error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            serde_json::json!({
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
                "requested": requested,
            }),
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    pub fn new(method: &str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        }
    }
}

// --- MCP Initialize ---

#[derive(Debug, Serialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ClientCapabilities {
    /// Optional extensions beyond the core protocol, e.g.
    /// `io.modelcontextprotocol/tasks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    /// Identity this CLI reports to every server it talks to.
    pub fn this_cli() -> Self {
        Self {
            name: "mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// --- MCP server/discover (2026-07-28) ---

/// Result of `server/discover`: what a stateless server advertises in
/// place of the removed `initialize` handshake.
///
/// Field names follow the spec's `DiscoverResult` exactly: the version list
/// is `supportedVersions`, and server identity lives in
/// `_meta["io.modelcontextprotocol/serverInfo"]` rather than at the top
/// level. Getting either wrong makes discovery fail in both directions
/// while still round-tripping against ourselves, so this shape is pinned by
/// tests against the literal JSON from the spec page.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerDiscoverResult {
    #[serde(rename = "supportedVersions")]
    pub supported_versions: Vec<String>,
    pub capabilities: Value,
    /// Optional guidance for LLMs on how to use the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Carries `io.modelcontextprotocol/serverInfo`. Absent from older or
    /// terser servers, and the spec says never to make behavior depend on
    /// it, so it stays optional and unused for decisions.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl ServerDiscoverResult {
    /// Newest revision both peers speak, or `None` when the sets are
    /// disjoint. Ours is ordered newest-first, so the first match wins.
    pub fn best_common_version(&self) -> Option<&str> {
        SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .find(|ours| self.supported_versions.iter().any(|theirs| theirs == *ours))
            .copied()
    }

    /// Self-reported server identity, for display and logging only — the
    /// spec is explicit that clients must not make decisions on it.
    pub fn server_info(&self) -> Option<ServerInfo> {
        serde_json::from_value(self.meta.as_ref()?.get(meta_keys::SERVER_INFO)?.clone()).ok()
    }
}

// --- MCP Tools ---

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ToolAnnotations {
    #[serde(
        default,
        rename = "readOnlyHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only_hint: Option<bool>,
    #[serde(
        default,
        rename = "destructiveHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub destructive_hint: Option<bool>,
    #[serde(
        default,
        rename = "idempotentHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotent_hint: Option<bool>,
    #[serde(
        default,
        rename = "openWorldHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub open_world_hint: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Tool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        default,
        rename = "inputSchema",
        skip_serializing_if = "Option::is_none"
    )]
    pub input_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Serialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ToolCallResult {
    pub content: Vec<Content>,
    #[serde(default, rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Content {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

// --- MCP Resources ---

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
}

// `resources/read` and `prompts/get` results are relayed to the client
// verbatim, so the proxy never needs typed views of them — and typing them
// here would silently drop fields (`structuredContent`, MRTR's
// `inputRequests`) the way the old `ToolCallResult` round trip did. They
// come back when something actually consumes their shape.

// --- MCP Prompts ---

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Prompt {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jsonrpc_request_serialization() {
        let req = JsonRpcRequest::new(1, "initialize", Some(json!({"key": "value"})));
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "initialize");
        assert_eq!(json["params"]["key"], "value");
    }

    #[test]
    fn test_jsonrpc_request_no_params() {
        let req = JsonRpcRequest::new(1, "tools/list", None);
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("params"));
    }

    #[test]
    fn test_jsonrpc_response_with_result() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, Some(Value::from(1)));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_jsonrpc_request_with_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Value::String("abc-123".to_string()));
        assert_eq!(req.method, "tools/list");
    }

    #[test]
    fn test_jsonrpc_response_with_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","result":{"tools":[]}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, Some(Value::String("abc-123".to_string())));
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_jsonrpc_response_with_error() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32600);
        assert_eq!(err.message, "Invalid Request");
    }

    #[test]
    fn test_notification_serialization() {
        let notif = JsonRpcNotification::new("notifications/initialized", None);
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("notifications/initialized"));
        assert!(!json.contains("params"));
        assert!(!json.contains("id"));
    }

    #[test]
    fn test_tool_deserialization() {
        let json = json!({
            "name": "search",
            "description": "Search repos",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                }
            }
        });
        let tool: Tool = serde_json::from_value(json).unwrap();
        assert_eq!(tool.name, "search");
        assert_eq!(tool.description.unwrap(), "Search repos");
        assert!(tool.input_schema.is_some());
    }

    #[test]
    fn test_tool_minimal() {
        let json = json!({"name": "ping"});
        let tool: Tool = serde_json::from_value(json).unwrap();
        assert_eq!(tool.name, "ping");
        assert!(tool.description.is_none());
        assert!(tool.input_schema.is_none());
    }

    #[test]
    fn test_tool_call_params_serialization() {
        let params = ToolCallParams {
            name: "search".to_string(),
            arguments: json!({"query": "rust"}),
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["name"], "search");
        assert_eq!(json["arguments"]["query"], "rust");
    }

    #[test]
    fn test_tool_call_result() {
        let json = json!({
            "content": [
                {"type": "text", "text": "Hello world"}
            ]
        });
        let result: ToolCallResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0].content_type, "text");
        assert_eq!(result.content[0].text.as_deref().unwrap(), "Hello world");
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_tool_call_result_with_error() {
        let json = json!({
            "content": [{"type": "text", "text": "error occurred"}],
            "isError": true
        });
        let result: ToolCallResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_content_image() {
        let json = json!({
            "type": "image",
            "data": "base64data",
            "mimeType": "image/png"
        });
        let content: Content = serde_json::from_value(json).unwrap();
        assert_eq!(content.content_type, "image");
        assert_eq!(content.data.unwrap(), "base64data");
        assert_eq!(content.mime_type.unwrap(), "image/png");
    }

    #[test]
    fn test_initialize_params_serialization() {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: "mcp".to_string(),
                version: "0.1.0".to_string(),
            },
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(json["clientInfo"]["name"], "mcp");
    }

    // --- 2026-07-28 contract ---

    #[test]
    fn latest_version_is_supported_and_stateless() {
        assert!(is_version_supported(PROTOCOL_VERSION));
        assert!(is_stateless_version(PROTOCOL_VERSION));
    }

    #[test]
    fn legacy_versions_are_supported_but_not_stateless() {
        for v in ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] {
            assert!(is_version_supported(v), "{v} must stay supported");
            assert!(!is_stateless_version(v), "{v} must use the handshake path");
        }
    }

    #[test]
    fn unknown_versions_are_rejected() {
        for v in ["2023-01-01", "", "garbage", "2026-07-27"] {
            assert!(!is_version_supported(v));
        }
    }

    #[test]
    fn mcp_name_reads_the_targeted_primitive() {
        let call = json!({"name": "search", "arguments": {}});
        assert_eq!(
            mcp_name_for("tools/call", Some(&call)).as_deref(),
            Some("search")
        );
        assert_eq!(
            mcp_name_for("prompts/get", Some(&call)).as_deref(),
            Some("search")
        );
        let read = json!({"uri": "file:///x"});
        assert_eq!(
            mcp_name_for("resources/read", Some(&read)).as_deref(),
            Some("file:///x")
        );
    }

    #[test]
    fn mcp_name_absent_for_list_methods_and_missing_params() {
        assert_eq!(mcp_name_for("tools/list", Some(&json!({}))), None);
        assert_eq!(mcp_name_for("tools/call", None), None);
        // Malformed params must not panic or invent a name.
        assert_eq!(mcp_name_for("tools/call", Some(&json!({"name": 42}))), None);
        assert_eq!(mcp_name_for("tools/call", Some(&json!([1, 2]))), None);
    }

    #[test]
    fn header_value_leaves_ordinary_values_untouched() {
        assert_eq!(header_value("tools/call").as_deref(), Some("tools/call"));
        assert_eq!(
            header_value("file:///a-b_c.d").as_deref(),
            Some("file:///a-b_c.d")
        );
        assert_eq!(header_value("").as_deref(), None);
    }

    #[test]
    fn header_value_wraps_unrepresentable_bytes_in_the_sentinel() {
        // Control characters cannot travel in a header field value.
        assert_eq!(header_value("a\nb").as_deref(), Some("=?base64?YQpi?="));
        assert_eq!(header_value("é").as_deref(), Some("=?base64?w6k=?="));
        // An interior space is legal per RFC 9110, so it needs no wrapping.
        assert_eq!(header_value("a b").as_deref(), Some("a b"));
        // `%` is an ordinary visible character here. Encoding it — as an
        // earlier pass did — is what desynchronized client and server.
        assert_eq!(header_value("100%").as_deref(), Some("100%"));
        assert_eq!(header_value("%0A").as_deref(), Some("%0A"));
    }

    /// A name too long to route is dropped, not truncated: a truncated name
    /// would designate the wrong primitive, which is worse than no name.
    #[test]
    fn header_value_drops_oversized_names() {
        assert!(header_value(&"a".repeat(MAX_HEADER_VALUE_LEN)).is_some());
        assert_eq!(header_value(&"a".repeat(MAX_HEADER_VALUE_LEN + 1)), None);
    }

    #[test]
    fn result_without_result_type_reads_as_complete() {
        // The backwards-compat rule: an older server omits the field.
        let legacy = json!({"tools": []});
        assert_eq!(result_type(&legacy), RESULT_TYPE_COMPLETE);
        assert!(!is_input_required(&legacy));
    }

    #[test]
    fn input_required_result_is_detected() {
        let mrtr = json!({"resultType": "input_required", "inputRequests": []});
        assert!(is_input_required(&mrtr));
    }

    #[test]
    fn set_result_type_complete_does_not_clobber_input_required() {
        let mut mrtr = json!({"resultType": "input_required"});
        set_result_type_complete(&mut mrtr);
        assert_eq!(mrtr["resultType"], "input_required");

        let mut plain = json!({"tools": []});
        set_result_type_complete(&mut plain);
        assert_eq!(plain["resultType"], "complete");
    }

    #[test]
    fn cache_hints_are_attached() {
        let mut result = json!({"tools": []});
        set_cache_hints(&mut result, 60_000, CacheScope::Private);
        assert_eq!(result["ttlMs"], 60_000);
        assert_eq!(result["cacheScope"], "private");
    }

    /// ACL-filtered results must never invite a shared intermediary to cache
    /// them — that would serve one identity's tools to another.
    #[test]
    fn cache_scope_is_never_public() {
        assert_eq!(CacheScope::Private.as_str(), "private");
        let mut result = json!({});
        set_cache_hints(&mut result, 1, CacheScope::Private);
        assert_ne!(result["cacheScope"], "public");
    }

    #[test]
    fn result_meta_is_merged_not_replaced() {
        let mut result = json!({"_meta": {"existing": 1}});
        set_result_meta(&mut result, meta_keys::SERVER_INFO, json!({"name": "x"}));
        assert_eq!(result["_meta"]["existing"], 1);
        assert_eq!(result["_meta"][meta_keys::SERVER_INFO]["name"], "x");

        let mut bare = json!({});
        set_result_meta(&mut bare, meta_keys::SERVER_INFO, json!({"name": "y"}));
        assert_eq!(bare["_meta"][meta_keys::SERVER_INFO]["name"], "y");
    }

    #[test]
    fn request_protocol_version_reads_meta_and_tolerates_absence() {
        let params = json!({"_meta": {meta_keys::PROTOCOL_VERSION: "2026-07-28"}});
        assert_eq!(request_protocol_version(Some(&params)), Some("2026-07-28"));
        // Legacy peers send no _meta — absence is the legacy path, not an error.
        assert_eq!(request_protocol_version(Some(&json!({}))), None);
        assert_eq!(request_protocol_version(None), None);
    }

    fn discover(versions: &[&str]) -> ServerDiscoverResult {
        ServerDiscoverResult {
            supported_versions: versions.iter().map(|v| v.to_string()).collect(),
            capabilities: json!({}),
            instructions: None,
            meta: None,
        }
    }

    #[test]
    fn best_common_version_prefers_newest_shared() {
        assert_eq!(
            discover(&["2025-11-25", "2026-07-28"]).best_common_version(),
            Some("2026-07-28")
        );
        assert_eq!(
            discover(&["2025-11-25"]).best_common_version(),
            Some("2025-11-25")
        );
        assert_eq!(discover(&["1999-01-01"]).best_common_version(), None);
        assert_eq!(discover(&[]).best_common_version(), None);
    }

    /// Pinned against the literal example on the spec's `server/discover`
    /// page. The field names are the whole contract: a result that parses
    /// only against our own encoder is exactly the bug this guards.
    #[test]
    fn discover_result_parses_the_spec_example() {
        let wire = json!({
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}, "resources": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "ExampleServer",
                    "version": "1.0.0"
                }
            },
            "instructions": "This server provides weather and resource utilities.",
            "ttlMs": 3_600_000,
            "cacheScope": "public"
        });

        let parsed: ServerDiscoverResult = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.supported_versions, vec!["2026-07-28"]);
        assert_eq!(parsed.best_common_version(), Some("2026-07-28"));
        let info = parsed.server_info().expect("serverInfo lives in _meta");
        assert_eq!(info.name, "ExampleServer");
        assert!(parsed.instructions.is_some());
    }

    #[test]
    fn discover_result_serializes_with_spec_field_names() {
        let wire = serde_json::to_value(discover(&["2026-07-28"])).unwrap();
        assert!(wire.get("supportedVersions").is_some());
        // The pre-release shape we shipped by mistake must not come back.
        assert!(wire.get("protocolVersions").is_none());
        assert!(wire.get("serverInfo").is_none());
    }

    #[test]
    fn discover_result_tolerates_absent_server_info() {
        let parsed: ServerDiscoverResult = serde_json::from_value(
            json!({"supportedVersions": ["2026-07-28"], "capabilities": {}}),
        )
        .unwrap();
        assert!(parsed.server_info().is_none());
        assert_eq!(parsed.best_common_version(), Some("2026-07-28"));
    }

    // --- header value encoding (Base64 sentinel) ---

    #[test]
    fn plain_ascii_header_values_travel_verbatim() {
        assert_eq!(header_value("get_weather").as_deref(), Some("get_weather"));
        assert_eq!(header_value("tools/call").as_deref(), Some("tools/call"));
        assert_eq!(
            header_value("file:///a/b.json").as_deref(),
            Some("file:///a/b.json")
        );
    }

    #[test]
    fn unsafe_header_values_use_the_base64_sentinel() {
        // Spec's own encoding examples.
        assert_eq!(
            header_value("Hello, 世界").as_deref(),
            Some("=?base64?SGVsbG8sIOS4lueVjA==?=")
        );
        assert_eq!(
            header_value(" padded ").as_deref(),
            Some("=?base64?IHBhZGRlZCA=?=")
        );
        assert_eq!(
            header_value("line1\nline2").as_deref(),
            Some("=?base64?bGluZTEKbGluZTI=?=")
        );
        assert_eq!(
            header_value("=?base64?literal?=").as_deref(),
            Some("=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=")
        );
    }

    /// A `%` is legal in a header value, so re-encoding it (as an earlier
    /// pass did) made the client and server disagree about the same URI.
    #[test]
    fn percent_escapes_are_not_re_encoded() {
        let uri = "file:///weekly%20report.txt";
        assert_eq!(header_value(uri).as_deref(), Some(uri));
        assert_eq!(decode_header_value(uri).as_deref(), Some(uri));
    }

    #[test]
    fn header_values_round_trip_through_decode() {
        for original in [
            "get_weather",
            "file:///weekly%20report.txt",
            "Hello, 世界",
            " padded ",
            "line1\nline2",
            "=?base64?literal?=",
            "acentuação",
        ] {
            let encoded = header_value(original).expect("encodable");
            assert_eq!(
                decode_header_value(&encoded).as_deref(),
                Some(original),
                "round trip failed for {original:?}"
            );
        }
    }

    #[test]
    fn oversized_header_values_are_omitted_not_truncated() {
        assert_eq!(header_value(&"a".repeat(MAX_HEADER_VALUE_LEN + 1)), None);
        assert_eq!(header_value(""), None);
    }

    #[test]
    fn malformed_sentinel_decodes_to_nothing() {
        // Invalid base64, and valid base64 that is not UTF-8.
        assert_eq!(decode_header_value("=?base64?!!!not-base64!!!?="), None);
        assert_eq!(decode_header_value("=?base64?/w==?="), None);
        // A bare value is already literal, never an error.
        assert_eq!(decode_header_value("plain").as_deref(), Some("plain"));
    }

    #[test]
    fn unsupported_version_error_carries_the_supported_list() {
        let resp = JsonRpcResponse::unsupported_protocol_version(json!(1), "1900-01-01");
        let err = resp.error.expect("error");
        assert_eq!(err.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        let data = err.data.expect("clients need the list to retry");
        assert_eq!(data["requested"], "1900-01-01");
        assert!(data["supported"]
            .as_array()
            .unwrap()
            .contains(&json!(PROTOCOL_VERSION)));
    }
}
