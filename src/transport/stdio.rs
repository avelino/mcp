use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

use super::Transport;

pub struct StdioTransport {
    child: Child,
    stdin: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    timeout_secs: u64,
}

impl StdioTransport {
    pub fn new(
        command: &str,
        args: &[String],
        env: &std::collections::HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .envs(env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn process: {command}"))?;

        let stdin = child.stdin.take().context("failed to open stdin")?;
        let stdout = child.stdout.take().context("failed to open stdout")?;
        let reader = BufReader::new(stdout);

        let timeout_secs = std::env::var("MCP_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Ok(Self {
            child,
            stdin,
            reader,
            timeout_secs,
        })
    }

    async fn send(&mut self, msg: &JsonRpcRequest) -> Result<()> {
        let mut data = serde_json::to_string(msg)?;
        data.push('\n');
        self.stdin
            .write_all(data.as_bytes())
            .await
            .context("failed to write to stdin")?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<JsonRpcResponse> {
        let duration = Duration::from_secs(self.timeout_secs);
        loop {
            let mut line = String::new();
            let n = timeout(duration, self.reader.read_line(&mut line))
                .await
                .context("timeout waiting for server response")?
                .context("failed to read from stdout")?;

            if n == 0 {
                bail!("server closed stdout (EOF)");
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try to parse as response (has "id" field)
            if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(line) {
                if resp.id.is_some() {
                    return Ok(resp);
                }
            }
            // Skip notifications and other messages without id
        }
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn request(&mut self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        self.send(msg).await?;
        self.receive().await
    }

    async fn notify(&mut self, msg: &JsonRpcNotification) -> Result<()> {
        let mut data = serde_json::to_string(msg)?;
        data.push('\n');
        self.stdin
            .write_all(data.as_bytes())
            .await
            .context("failed to write notification to stdin")?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // Dropping stdin signals EOF to the child process
        let _ = timeout(Duration::from_secs(5), self.child.wait()).await;
        let _ = self.child.kill().await;
        Ok(())
    }
}
