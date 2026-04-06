use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

use super::Transport;

pub struct StdioTransport {
    child: Child,
    stdin: Option<tokio::process::ChildStdin>,
    reader: BufReader<tokio::process::ChildStdout>,
    timeout_secs: u64,
    stderr_buffer: Arc<Mutex<Vec<String>>>,
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
            .stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn process: {command}"))?;

        let stdin = child.stdin.take().context("failed to open stdin")?;
        let stdout = child.stdout.take().context("failed to open stdout")?;
        let stderr = child.stderr.take().context("failed to open stderr")?;
        let reader = BufReader::new(stdout);

        let stderr_buffer = Arc::new(Mutex::new(Vec::<String>::new()));

        // Forward stderr to the user's stderr and capture for error messages
        let buf = Arc::clone(&stderr_buffer);
        tokio::spawn(async move {
            let mut stderr_reader = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(n) = stderr_reader.read_line(&mut line).await {
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end().to_string();
                eprintln!("[server stderr] {trimmed}");
                let mut buf = buf.lock().unwrap();
                buf.push(trimmed);
                // Keep only the last 50 lines to bound memory
                if buf.len() > 50 {
                    buf.remove(0);
                }
                line.clear();
            }
        });

        let timeout_secs = std::env::var("MCP_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Ok(Self {
            child,
            stdin: Some(stdin),
            reader,
            timeout_secs,
            stderr_buffer,
        })
    }

    async fn send(&mut self, msg: &JsonRpcRequest) -> Result<()> {
        let stdin = self.stdin.as_mut().context("stdin already closed")?;
        let mut data = serde_json::to_string(msg)?;
        data.push('\n');
        stdin
            .write_all(data.as_bytes())
            .await
            .context("failed to write to stdin")?;
        stdin.flush().await?;
        Ok(())
    }

    fn stderr_context(&self) -> String {
        let buf = self.stderr_buffer.lock().unwrap();
        if buf.is_empty() {
            return String::new();
        }
        format!("\n\nserver stderr:\n{}", buf.join("\n"))
    }

    async fn receive(&mut self) -> Result<JsonRpcResponse> {
        let duration = Duration::from_secs(self.timeout_secs);
        loop {
            let mut line = String::new();
            let n = match timeout(duration, self.reader.read_line(&mut line)).await {
                Err(_) => bail!(
                    "timeout waiting for server response{}",
                    self.stderr_context()
                ),
                Ok(result) => result.context("failed to read from stdout")?,
            };

            if n == 0 {
                bail!("server closed stdout (EOF){}", self.stderr_context());
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
        let stdin = self.stdin.as_mut().context("stdin already closed")?;
        let mut data = serde_json::to_string(msg)?;
        data.push('\n');
        stdin
            .write_all(data.as_bytes())
            .await
            .context("failed to write notification to stdin")?;
        stdin.flush().await?;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // Drop stdin to close the pipe — child receives EOF and can exit gracefully
        drop(self.stdin.take());

        // Give the child time to exit gracefully before killing
        match timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(Ok(_)) => {}
            _ => {
                let _ = self.child.kill().await;
            }
        }
        Ok(())
    }
}
