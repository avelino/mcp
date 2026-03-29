use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use crate::cli_discovery;
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, Tool, PROTOCOL_VERSION,
};

use super::Transport;

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
    discovered: bool,
}

impl CliTransport {
    pub fn new(config: CliTransportConfig) -> Self {
        let discovered = !config.preset_tools.is_empty();
        Self {
            command: config.command,
            base_args: config.base_args,
            env: config.env,
            help_flag: config.help_flag,
            depth: config.depth,
            only: config.only,
            tools: config.preset_tools,
            tool_args: config.tool_args,
            discovered,
        }
    }

    async fn ensure_discovered(&mut self) -> Result<()> {
        if self.discovered {
            return Ok(());
        }
        self.tools = cli_discovery::discover_tools(
            &self.command,
            &self.base_args,
            &self.env,
            &self.help_flag,
            self.depth,
            &self.only,
        )
        .await?;
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
            .map(|t| serde_json::to_value(t).unwrap())
            .collect();

        Ok(JsonRpcResponse::success(id, json!({ "tools": tools_json })))
    }

    async fn handle_tools_call(&self, id: Value, params: Option<Value>) -> Result<JsonRpcResponse> {
        let params = params.unwrap_or(json!({}));
        let tool_name = params["name"].as_str().unwrap_or_default().to_string();
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let mut cmd_args = self.base_args.clone();

        if let Some(fixed_args) = self.tool_args.get(&tool_name) {
            // Preset tool: use the exact args from config
            cmd_args.extend(fixed_args.clone());
        } else {
            // Discovered tool: extract subcommand from tool name
            // e.g. "kubectl_get" → ["get"]
            let cmd_base = self
                .command
                .rsplit('/')
                .next()
                .unwrap_or(&self.command)
                .replace('-', "_");
            let subcommand = tool_name
                .strip_prefix(&format!("{}_", cmd_base))
                .unwrap_or(&tool_name);
            for part in subcommand.split('_') {
                cmd_args.push(part.replace('_', "-"));
            }
        }

        // Add positional args if provided
        if let Some(pos_args) = arguments.get("args").and_then(|v| v.as_str()) {
            for arg in pos_args.split_whitespace() {
                cmd_args.push(arg.to_string());
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
                    Value::Bool(false) => {}
                    Value::Null => {}
                    _ => {
                        cmd_args.push(format!("--{flag_name}"));
                        cmd_args.push(value.as_str().unwrap_or(&value.to_string()).to_string());
                    }
                }
            }
        }

        // Run the command
        let mut cmd = Command::new(&self.command);
        cmd.args(&cmd_args).envs(&self.env);

        let output = cmd.output().await;

        let (text, is_error) = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if out.status.success() {
                    (stdout, false)
                } else {
                    let msg = if stderr.is_empty() { stdout } else { stderr };
                    (msg, true)
                }
            }
            Err(e) => (format!("failed to execute {}: {e}", self.command), true),
        };

        Ok(JsonRpcResponse::success(
            id,
            json!({
                "content": [{ "type": "text", "text": text }],
                "isError": is_error
            }),
        ))
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
