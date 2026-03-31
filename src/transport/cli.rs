use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::cli_discovery;
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, Tool, PROTOCOL_VERSION,
};

use super::Transport;

/// Default max output size: 1 MB.
const DEFAULT_MAX_OUTPUT: usize = 1_048_576;
/// Max stderr to append on successful commands: 8 KB.
const MAX_STDERR_ON_SUCCESS: usize = 8_192;

fn max_output_bytes() -> usize {
    std::env::var("MCP_MAX_OUTPUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_OUTPUT)
}

fn truncate_output(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Find a valid UTF-8 char boundary
    let mut boundary = max;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!(
        "{}\n\n... [truncated, {} bytes total, showing first {}]",
        &s[..boundary],
        s.len(),
        boundary
    )
}

pub struct CliTransportConfig {
    pub command: String,
    pub base_args: Vec<String>,
    pub env: HashMap<String, String>,
    pub help_flag: String,
    pub depth: u8,
    pub only: Vec<String>,
    pub preset_tools: Vec<Tool>,
    /// Maps tool name → fixed args for preset tools defined in config.
    pub tool_args: HashMap<String, Vec<String>>,
}

pub struct CliTransport {
    command: String,
    base_args: Vec<String>,
    env: HashMap<String, String>,
    help_flag: String,
    depth: u8,
    only: Vec<String>,
    tools: Vec<Tool>,
    tool_args: HashMap<String, Vec<String>>,
    /// Maps tool name → original subcommand name (preserving hyphens).
    subcommand_map: HashMap<String, String>,
    discovered: bool,
    timeout_secs: u64,
}

impl CliTransport {
    pub fn new(config: CliTransportConfig) -> Self {
        let discovered = !config.preset_tools.is_empty();
        let timeout_secs = std::env::var("MCP_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        Self {
            command: config.command,
            base_args: config.base_args,
            env: config.env,
            help_flag: config.help_flag,
            depth: config.depth,
            only: config.only,
            tools: config.preset_tools,
            tool_args: config.tool_args,
            subcommand_map: HashMap::new(),
            discovered,
            timeout_secs,
        }
    }

    async fn ensure_discovered(&mut self) -> Result<()> {
        if self.discovered {
            return Ok(());
        }
        let results = cli_discovery::discover_tools(
            &self.command,
            &self.base_args,
            &self.env,
            &self.help_flag,
            self.depth,
            &self.only,
        )
        .await?;

        for dt in &results {
            if !dt.subcommand.is_empty() {
                self.subcommand_map
                    .insert(dt.tool.name.clone(), dt.subcommand.clone());
            }
        }
        self.tools = results.into_iter().map(|dt| dt.tool).collect();
        self.discovered = true;
        Ok(())
    }

    fn handle_initialize(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": format!("cli-{}", self.command),
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
    }

    async fn handle_tools_list(&mut self, id: Value) -> Result<JsonRpcResponse> {
        self.ensure_discovered().await?;

        let tools_json: Vec<Value> = self
            .tools
            .iter()
            .map(serde_json::to_value)
            .collect::<serde_json::Result<_>>()?;

        Ok(JsonRpcResponse::success(id, json!({ "tools": tools_json })))
    }

    async fn handle_tools_call(
        &mut self,
        id: Value,
        params: Option<Value>,
    ) -> Result<JsonRpcResponse> {
        self.ensure_discovered().await?;

        // Validate params is an object with a non-empty "name"
        let params = match params {
            Some(Value::Object(map)) => map,
            _ => {
                return Ok(JsonRpcResponse::error(
                    id,
                    -32602,
                    "Invalid params: expected object with non-empty \"name\"",
                ));
            }
        };

        let tool_name = match params
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            Some(name) => name.to_string(),
            None => {
                return Ok(JsonRpcResponse::error(
                    id,
                    -32602,
                    "Invalid params: expected object with non-empty \"name\"",
                ));
            }
        };

        // Enforce allowlist: only permit tools that were discovered or preset
        if !self.tools.iter().any(|t| t.name == tool_name)
            && !self.tool_args.contains_key(&tool_name)
        {
            return Ok(JsonRpcResponse::error(
                id,
                -32602,
                &format!("Unknown tool: {tool_name}"),
            ));
        }

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let mut cmd_args = self.base_args.clone();

        if let Some(fixed_args) = self.tool_args.get(&tool_name) {
            // Preset tool: use the exact args from config
            cmd_args.extend(fixed_args.clone());
        } else if let Some(original_sub) = self.subcommand_map.get(&tool_name) {
            // Discovered tool: use the original subcommand name (preserves hyphens)
            cmd_args.push(original_sub.clone());
        } else {
            // Fallback for tools without subcommand mapping
            let cmd_base = Path::new(&self.command)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&self.command)
                .replace('-', "_");
            let subcommand = tool_name
                .strip_prefix(&format!("{}_", cmd_base))
                .unwrap_or(&tool_name);
            cmd_args.push(subcommand.replace('_', "-"));
        }

        // Add positional args if provided (supports shell quoting, e.g. "my file.txt")
        if let Some(pos_args) = arguments.get("args").and_then(|v| v.as_str()) {
            match shell_words::split(pos_args) {
                Ok(parsed) => cmd_args.extend(parsed),
                Err(_) => {
                    // Fallback to whitespace splitting if quotes are unbalanced
                    cmd_args.extend(pos_args.split_whitespace().map(String::from));
                }
            }
        }

        // Add flags from arguments
        if let Some(obj) = arguments.as_object() {
            for (key, value) in obj {
                if key == "args" {
                    continue;
                }
                let flag_name = key.replace('_', "-");
                match value {
                    Value::Bool(true) => {
                        cmd_args.push(format!("--{flag_name}"));
                    }
                    Value::Bool(false) => {
                        cmd_args.push(format!("--{flag_name}=false"));
                    }
                    Value::Null => {}
                    Value::Array(arr) => {
                        for item in arr {
                            cmd_args.push(format!("--{flag_name}"));
                            cmd_args.push(item.as_str().unwrap_or(&item.to_string()).to_string());
                        }
                    }
                    _ => {
                        cmd_args.push(format!("--{flag_name}"));
                        cmd_args.push(value.as_str().unwrap_or(&value.to_string()).to_string());
                    }
                }
            }
        }

        // Run the command with timeout
        let mut cmd = Command::new(&self.command);
        cmd.args(&cmd_args).envs(&self.env);

        let duration = Duration::from_secs(self.timeout_secs);
        let output = match timeout(duration, cmd.output()).await {
            Ok(result) => result,
            Err(_) => {
                return Ok(JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": format!(
                            "timeout: {} did not complete within {}s",
                            self.command, self.timeout_secs
                        )}],
                        "isError": true
                    }),
                ));
            }
        };

        let max_out = max_output_bytes();
        let (text, is_error) = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if out.status.success() {
                    let mut result = truncate_output(&stdout, max_out);
                    if !stderr.trim().is_empty() {
                        let stderr_truncated = truncate_output(&stderr, MAX_STDERR_ON_SUCCESS);
                        result.push_str("\n\n--- stderr ---\n");
                        result.push_str(&stderr_truncated);
                    }
                    (result, false)
                } else {
                    let msg = if stderr.is_empty() {
                        truncate_output(&stdout, max_out)
                    } else {
                        truncate_output(&stderr, max_out)
                    };
                    (msg, true)
                }
            }
            Err(e) => (format!("failed to execute {}: {e}", self.command), true),
        };

        if is_error {
            Ok(JsonRpcResponse::error(id, -32603, &text))
        } else {
            Ok(JsonRpcResponse::success(
                id,
                json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false
                }),
            ))
        }
    }
}

#[async_trait]
impl Transport for CliTransport {
    async fn request(&mut self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        match msg.method.as_str() {
            "initialize" => Ok(self.handle_initialize(msg.id.clone())),
            "tools/list" => self.handle_tools_list(msg.id.clone()).await,
            "tools/call" => {
                self.handle_tools_call(msg.id.clone(), msg.params.clone())
                    .await
            }
            _ => Ok(JsonRpcResponse::error(
                msg.id.clone(),
                -32601,
                &format!("method not found: {}", msg.method),
            )),
        }
    }

    async fn notify(&mut self, _msg: &JsonRpcNotification) -> Result<()> {
        // CLI transport doesn't need to handle notifications
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // Nothing to clean up — each command is a separate process
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_output_within_limit() {
        let s = "hello world";
        assert_eq!(truncate_output(s, 100), "hello world");
    }

    #[test]
    fn test_truncate_output_at_limit() {
        let s = "abcde";
        assert_eq!(truncate_output(s, 5), "abcde");
    }

    #[test]
    fn test_truncate_output_exceeds_limit() {
        let s = "abcdefghij";
        let result = truncate_output(s, 5);
        assert!(result.starts_with("abcde"));
        assert!(result.contains("[truncated, 10 bytes total, showing first 5]"));
    }

    #[test]
    fn test_truncate_output_utf8_boundary() {
        // 'é' is 2 bytes in UTF-8: truncating at byte 1 should back up to 0
        let s = "é";
        let result = truncate_output(s, 1);
        // Should not panic and should find valid boundary
        assert!(result.contains("[truncated"));
    }

    fn test_transport(command: &str) -> CliTransport {
        CliTransport {
            command: command.to_string(),
            base_args: vec![],
            env: HashMap::new(),
            help_flag: "--help".to_string(),
            depth: 1,
            only: vec![],
            tools: vec![Tool {
                name: format!("{command}_test"),
                description: Some("test tool".to_string()),
                input_schema: None,
            }],
            tool_args: HashMap::new(),
            subcommand_map: HashMap::from([(format!("{command}_test"), "test".to_string())]),
            discovered: true,
            timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn test_array_flags_expand_to_repeated_args() {
        // "echo" will print all received args, so we can verify the expansion
        let mut transport = test_transport("echo");
        transport
            .subcommand_map
            .insert("echo_test".to_string(), "".to_string());

        let resp = transport
            .handle_tools_call(
                json!(1),
                Some(json!({
                    "name": "echo_test",
                    "arguments": {
                        "label": [":lib :rust", ":lib :python", ":enhancement"]
                    }
                })),
            )
            .await
            .unwrap();

        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();

        // echo should print the expanded flags
        assert!(
            text.contains("--label"),
            "should contain --label flag, got: {text}"
        );
        assert!(
            text.contains(":lib :rust"),
            "should contain first label, got: {text}"
        );
        assert!(
            text.contains(":lib :python"),
            "should contain second label, got: {text}"
        );
        assert!(
            text.contains(":enhancement"),
            "should contain third label, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_failed_command_returns_jsonrpc_error() {
        // Use a command guaranteed to fail
        let mut transport = test_transport("false");
        transport
            .subcommand_map
            .insert("false_test".to_string(), "".to_string());

        let resp = transport
            .handle_tools_call(
                json!(1),
                Some(json!({
                    "name": "false_test",
                    "arguments": {}
                })),
            )
            .await
            .unwrap();

        // Should be a JSON-RPC error, not success with isError
        assert!(
            resp.error.is_some(),
            "failed command should return JSON-RPC error"
        );
        assert!(
            resp.result.is_none(),
            "failed command should not have result"
        );
    }

    #[tokio::test]
    async fn test_successful_command_returns_success() {
        let mut transport = test_transport("echo");
        transport
            .subcommand_map
            .insert("echo_test".to_string(), "".to_string());

        let resp = transport
            .handle_tools_call(
                json!(1),
                Some(json!({
                    "name": "echo_test",
                    "arguments": { "args": "hello" }
                })),
            )
            .await
            .unwrap();

        assert!(resp.result.is_some(), "success should have result");
        assert!(resp.error.is_none(), "success should not have error");
        let is_error = resp.result.unwrap()["isError"].as_bool().unwrap();
        assert!(!is_error, "isError should be false");
    }

    #[test]
    fn test_subcommand_map_used_for_hyphenated_names() {
        let transport = CliTransport {
            command: "kubectl".to_string(),
            base_args: vec![],
            env: HashMap::new(),
            help_flag: "--help".to_string(),
            depth: 2,
            only: vec![],
            tools: vec![Tool {
                name: "kubectl_api_versions".to_string(),
                description: Some("Print API versions".to_string()),
                input_schema: None,
            }],
            tool_args: HashMap::new(),
            subcommand_map: HashMap::from([(
                "kubectl_api_versions".to_string(),
                "api-versions".to_string(),
            )]),
            discovered: true,
            timeout_secs: 5,
        };

        // Verify the subcommand map has the correct entry
        assert_eq!(
            transport.subcommand_map.get("kubectl_api_versions"),
            Some(&"api-versions".to_string())
        );
    }
}
