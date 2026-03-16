use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::config::ServerConfig;
use crate::protocol::*;
use crate::transport::http::HttpTransport;
use crate::transport::stdio::StdioTransport;
use crate::transport::Transport;

pub struct McpClient {
    transport: Box<dyn Transport>,
    next_id: u64,
}

impl McpClient {
    pub async fn connect(config: &ServerConfig) -> Result<Self> {
        let transport: Box<dyn Transport> = match config {
            ServerConfig::Stdio { command, args, env } => {
                Box::new(StdioTransport::new(command, args, env)?)
            }
            ServerConfig::Http { url, headers } => {
                let mut t = HttpTransport::new(url, headers)?;
                t.load_saved_token();
                Box::new(t)
            }
        };

        let mut client = McpClient {
            transport,
            next_id: 1,
        };

        client.initialize().await?;
        Ok(client)
    }

    async fn initialize(&mut self) -> Result<()> {
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

    pub async fn list_tools(&mut self) -> Result<Vec<Tool>> {
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
        &mut self,
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

    pub async fn shutdown(&mut self) -> Result<()> {
        self.transport.close().await
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}
