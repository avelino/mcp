use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: &str = "2025-03-26";

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

#[derive(Debug, Serialize)]
pub struct ClientCapabilities {}

#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

// --- MCP Tools ---

#[derive(Debug, Deserialize, Serialize, Clone)]
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
}

#[derive(Debug, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
    #[serde(default, rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Deserialize, Serialize)]
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
    fn test_tools_list_result() {
        let json = json!({
            "tools": [
                {"name": "tool1"},
                {"name": "tool2", "description": "desc"}
            ]
        });
        let result: ToolsListResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.tools.len(), 2);
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn test_tools_list_result_with_cursor() {
        let json = json!({
            "tools": [{"name": "tool1"}],
            "nextCursor": "abc123"
        });
        let result: ToolsListResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.next_cursor.unwrap(), "abc123");
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
            capabilities: ClientCapabilities {},
            client_info: ClientInfo {
                name: "mcp".to_string(),
                version: "0.1.0".to_string(),
            },
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(json["clientInfo"]["name"], "mcp");
    }
}
