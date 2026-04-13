use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::config::ServerConfig;
use crate::protocol::*;
use crate::transport::cli::{CliTransport, CliTransportConfig};
use crate::transport::http::HttpTransport;
use crate::transport::stdio::StdioTransport;
use crate::transport::Transport;

/// `McpClient` wraps a transport with interior mutability so it can be shared
/// across many concurrent requests via `Arc<McpClient>`. The transport itself
/// is responsible for serializing access where needed (e.g. stdio uses a
/// writer task + per-request id multiplexing).
pub struct McpClient {
    transport: Arc<dyn Transport>,
    next_id: AtomicU64,
}

impl McpClient {
    pub async fn connect(config: &ServerConfig) -> Result<Self> {
        let transport: Arc<dyn Transport> = match config {
            ServerConfig::Cli {
                command,
                args,
                env,
                cli_help,
                cli_depth,
                cli_only,
                tools: preset_tools,
                ..
            } => {
                let mut tool_args_map = HashMap::new();
                let preset: Vec<Tool> = preset_tools
                    .iter()
                    .map(|t| {
                        if !t.args.is_empty() {
                            tool_args_map.insert(t.name.clone(), t.args.clone());
                        }
                        Tool {
                            name: t.name.clone(),
                            description: t.description.clone(),
                            input_schema: t.input_schema.clone(),
                            annotations: None,
                        }
                    })
                    .collect();
                Arc::new(CliTransport::new(CliTransportConfig {
                    command: command.clone(),
                    base_args: args.clone(),
                    env: env.clone(),
                    help_flag: cli_help.clone(),
                    depth: *cli_depth,
                    only: cli_only.clone(),
                    preset_tools: preset,
                    tool_args: tool_args_map,
                }))
            }
            ServerConfig::Stdio {
                command, args, env, ..
            } => Arc::new(StdioTransport::new(command, args, env)?),
            ServerConfig::Http { url, headers, .. } => {
                let t = HttpTransport::new(url, headers)?;
                t.load_saved_token();
                Arc::new(t)
            }
        };

        let client = McpClient {
            transport,
            next_id: AtomicU64::new(1),
        };

        client.initialize().await?;
        Ok(client)
    }

    async fn initialize(&self) -> Result<()> {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities {},
            client_info: ClientInfo {
                name: "mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        let req = JsonRpcRequest::new(
            self.next_id(),
            "initialize",
            Some(serde_json::to_value(&params)?),
        );

        let resp = self.transport.request(&req).await?;

        if let Some(err) = resp.error {
            bail!("initialize failed: {} (code {})", err.message, err.code);
        }

        let notif = JsonRpcNotification::new("notifications/initialized", None);
        self.transport.notify(&notif).await?;

        Ok(())
    }

    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        let mut all_tools = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let params = cursor.as_ref().map(|c| json!({"cursor": c}));
            let req = JsonRpcRequest::new(self.next_id(), "tools/list", params);
            let resp = self.transport.request(&req).await?;

            if let Some(err) = resp.error {
                bail!("tools/list failed: {} (code {})", err.message, err.code);
            }

            let result: ToolsListResult =
                serde_json::from_value(resp.result.context("tools/list returned no result")?)
                    .context("failed to parse tools/list result")?;

            all_tools.extend(result.tools);

            match result.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(all_tools)
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<ToolCallResult> {
        let params = ToolCallParams {
            name: name.to_string(),
            arguments,
        };

        let req = JsonRpcRequest::new(
            self.next_id(),
            "tools/call",
            Some(serde_json::to_value(&params)?),
        );

        let resp = self.transport.request(&req).await?;

        if let Some(err) = resp.error {
            bail!("tools/call failed: {} (code {})", err.message, err.code);
        }

        let result: ToolCallResult =
            serde_json::from_value(resp.result.context("tools/call returned no result")?)
                .context("failed to parse tools/call result")?;

        Ok(result)
    }

    pub async fn list_resources(&self) -> Result<Vec<Resource>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let params = cursor.as_ref().map(|c| json!({"cursor": c}));
            let req = JsonRpcRequest::new(self.next_id(), "resources/list", params);
            let resp = self.transport.request(&req).await?;

            if let Some(err) = resp.error {
                bail!("resources/list failed: {} (code {})", err.message, err.code);
            }

            let result: ResourcesListResult =
                serde_json::from_value(resp.result.context("resources/list returned no result")?)
                    .context("failed to parse resources/list result")?;

            all.extend(result.resources);

            match result.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(all)
    }

    pub async fn read_resource(&self, uri: &str) -> Result<ResourceReadResult> {
        let params = ResourceReadParams {
            uri: uri.to_string(),
        };

        let req = JsonRpcRequest::new(
            self.next_id(),
            "resources/read",
            Some(serde_json::to_value(&params)?),
        );

        let resp = self.transport.request(&req).await?;

        if let Some(err) = resp.error {
            bail!("resources/read failed: {} (code {})", err.message, err.code);
        }

        let result: ResourceReadResult =
            serde_json::from_value(resp.result.context("resources/read returned no result")?)
                .context("failed to parse resources/read result")?;

        Ok(result)
    }

    pub async fn list_prompts(&self) -> Result<Vec<Prompt>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let params = cursor.as_ref().map(|c| json!({"cursor": c}));
            let req = JsonRpcRequest::new(self.next_id(), "prompts/list", params);
            let resp = self.transport.request(&req).await?;

            if let Some(err) = resp.error {
                bail!("prompts/list failed: {} (code {})", err.message, err.code);
            }

            let result: PromptsListResult =
                serde_json::from_value(resp.result.context("prompts/list returned no result")?)
                    .context("failed to parse prompts/list result")?;

            all.extend(result.prompts);

            match result.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(all)
    }

    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<serde_json::Value>,
    ) -> Result<PromptGetResult> {
        let params = PromptGetParams {
            name: name.to_string(),
            arguments,
        };

        let req = JsonRpcRequest::new(
            self.next_id(),
            "prompts/get",
            Some(serde_json::to_value(&params)?),
        );

        let resp = self.transport.request(&req).await?;

        if let Some(err) = resp.error {
            bail!("prompts/get failed: {} (code {})", err.message, err.code);
        }

        let result: PromptGetResult =
            serde_json::from_value(resp.result.context("prompts/get returned no result")?)
                .context("failed to parse prompts/get result")?;

        Ok(result)
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.transport.close().await
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}
