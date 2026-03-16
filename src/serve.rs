use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::client::McpClient;
use crate::config::Config;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, Tool, PROTOCOL_VERSION};

const SEPARATOR: &str = "__";

struct ProxyServer {
    backends: HashMap<String, McpClient>,
    tool_map: HashMap<String, (String, String)>, // namespaced -> (server, original_name)
    tools: Vec<Tool>,
}

impl ProxyServer {
    fn new() -> Self {
        Self {
            backends: HashMap::new(),
            tool_map: HashMap::new(),
            tools: Vec::new(),
        }
    }

    async fn connect_backends(&mut self, config: &Config) {
        for (name, server_config) in &config.servers {
            eprintln!("[serve] connecting to {name}...");
            match McpClient::connect(server_config).await {
                Ok(mut client) => {
                    match client.list_tools().await {
                        Ok(tools) => {
                            eprintln!("[serve] {name}: {} tool(s)", tools.len());
                            for tool in tools {
                                let namespaced = format!("{name}{SEPARATOR}{}", tool.name);
                                let description = match &tool.description {
                                    Some(desc) => Some(format!("[{name}] {desc}")),
                                    None => Some(format!("[{name}]")),
                                };
                                self.tool_map.insert(
                                    namespaced.clone(),
                                    (name.clone(), tool.name.clone()),
                                );
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
                    }
                }
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

    fn handle_initialize(&self, id: u64) -> JsonRpcResponse {
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

    fn handle_tools_list(&self, id: u64) -> JsonRpcResponse {
        let tools: Vec<Value> = self
            .tools
            .iter()
            .map(|t| serde_json::to_value(t).unwrap())
            .collect();
        JsonRpcResponse::success(id, json!({ "tools": tools }))
    }

    async fn handle_tools_call(&mut self, id: u64, params: Option<Value>) -> JsonRpcResponse {
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

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(json!({}));

        let (server_name, original_name) = match self.tool_map.get(&tool_name) {
            Some(mapping) => mapping.clone(),
            None => {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    &format!("unknown tool: {tool_name}"),
                );
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
            Err(e) => JsonRpcResponse::error(
                id,
                -32603,
                &format!("[{server_name}] {e:#}"),
            ),
        }
    }

    async fn shutdown_all(&mut self) {
        for (name, mut client) in self.backends.drain() {
            if let Err(e) = client.shutdown().await {
                eprintln!("[serve] {name}: shutdown error: {e:#}");
            }
        }
    }
}

pub async fn run(config: Config) -> Result<()> {
    let mut server = ProxyServer::new();

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
            let response = match req.method.as_str() {
                "initialize" => {
                    // Respond immediately — backends connect lazily
                    server.handle_initialize(req.id)
                }
                "tools/list" => {
                    if !backends_connected {
                        server.connect_backends(&config).await;
                        backends_connected = true;
                    }
                    server.handle_tools_list(req.id)
                }
                "tools/call" => {
                    if !backends_connected {
                        server.connect_backends(&config).await;
                        backends_connected = true;
                    }
                    server.handle_tools_call(req.id, req.params).await
                }
                _ => JsonRpcResponse::error(
                    req.id,
                    -32601,
                    &format!("method not found: {}", req.method),
                ),
            };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Tool;

    #[test]
    fn test_split_tool_name_via_separator() {
        assert_eq!("sentry__search_issues".split_once(SEPARATOR), Some(("sentry", "search_issues")));
        assert_eq!("slack__send_message".split_once(SEPARATOR), Some(("slack", "send_message")));
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
        let server = ProxyServer::new();
        let resp = server.handle_initialize(1);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "mcp-proxy");
    }

    #[test]
    fn test_proxy_server_empty_tools_list() {
        let server = ProxyServer::new();
        let resp = server.handle_tools_list(2);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_proxy_server_tools_list_with_tools() {
        let mut server = ProxyServer::new();
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search for issues".to_string()),
            input_schema: None,
        });
        server.tool_map.insert(
            "sentry__search_issues".to_string(),
            ("sentry".to_string(), "search_issues".to_string()),
        );

        let resp = server.handle_tools_list(3);
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "sentry__search_issues");
        assert_eq!(tools[0]["description"], "[sentry] Search for issues");
    }

    #[tokio::test]
    async fn test_proxy_server_unknown_tool() {
        let mut server = ProxyServer::new();
        let params = Some(serde_json::json!({"name": "nonexistent__tool"}));
        let resp = server.handle_tools_call(4, params).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("unknown tool"));
    }

    #[tokio::test]
    async fn test_proxy_server_missing_params() {
        let mut server = ProxyServer::new();
        let resp = server.handle_tools_call(5, None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test]
    async fn test_proxy_server_missing_name_in_params() {
        let mut server = ProxyServer::new();
        let params = Some(serde_json::json!({"arguments": {}}));
        let resp = server.handle_tools_call(6, params).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("missing 'name'"));
    }

    #[tokio::test]
    async fn test_proxy_server_backend_not_connected() {
        let mut server = ProxyServer::new();
        server.tool_map.insert(
            "ghost__tool".to_string(),
            ("ghost".to_string(), "tool".to_string()),
        );
        let params = Some(serde_json::json!({"name": "ghost__tool"}));
        let resp = server.handle_tools_call(7, params).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("not connected"));
    }
}
