use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{timeout, Duration};

use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

use super::Transport;

/// Pending requests keyed by the JSON-serialized id (works for any id type).
type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>;

/// Multiplexed stdio transport.
///
/// A single backend process is owned by this transport. A dedicated **writer
/// task** serializes writes to the child's stdin (the pipe is single-producer
/// at the OS level). A dedicated **reader task** consumes the child's stdout
/// line-by-line and dispatches each response to its caller via a `oneshot`
/// channel keyed by the JSON-RPC `id`.
///
/// This means **multiple in-flight requests can be concurrent** on the same
/// backend, all sharing one process. Callers only block waiting for their
/// own response.
pub struct StdioTransport {
    writer_tx: mpsc::Sender<Vec<u8>>,
    pending: PendingMap,
    /// Wrapped so `close()` can take ownership and force-kill the child.
    child: Mutex<Option<Child>>,
    stderr_buffer: Arc<Mutex<Vec<String>>>,
    timeout_secs: u64,
    closed: Arc<AtomicBool>,
}

impl StdioTransport {
    pub fn new(command: &str, args: &[String], env: &HashMap<String, String>) -> Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .envs(env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // Reap the child if this Transport is dropped without close()
            // (e.g. on panic, task abort, or connection error).
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn process: {command}"))?;

        let mut stdin = child.stdin.take().context("failed to open stdin")?;
        let stdout = child.stdout.take().context("failed to open stdout")?;
        let stderr = child.stderr.take().context("failed to open stderr")?;

        let stderr_buffer: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        // Stderr capture task — bounded to last 50 lines.
        {
            let buf = Arc::clone(&stderr_buffer);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 {
                        break;
                    }
                    let trimmed = line.trim_end().to_string();
                    eprintln!("[server stderr] {trimmed}");
                    let mut b = buf.lock().await;
                    b.push(trimmed);
                    if b.len() > 50 {
                        b.remove(0);
                    }
                    line.clear();
                }
            });
        }

        // Reader task — dispatches responses by id.
        {
            let pending = Arc::clone(&pending);
            let closed = Arc::clone(&closed);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                loop {
                    line.clear();
                    let n = match reader.read_line(&mut line).await {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if n == 0 {
                        break; // EOF
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                        if let Some(id) = &resp.id {
                            let key = id.to_string();
                            let tx = pending.lock().await.remove(&key);
                            if let Some(tx) = tx {
                                let _ = tx.send(resp);
                            }
                        }
                        // Notifications and id-less messages are silently dropped.
                    }
                }
                // Reader gone — mark closed and drop all pending senders so
                // their callers fail fast instead of hanging on the timeout.
                closed.store(true, Ordering::Release);
                pending.lock().await.clear();
            });
        }

        // Writer task — serializes stdin writes.
        let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(128);
        {
            let closed = Arc::clone(&closed);
            tokio::spawn(async move {
                while let Some(bytes) = writer_rx.recv().await {
                    if stdin.write_all(&bytes).await.is_err() {
                        break;
                    }
                    if stdin.flush().await.is_err() {
                        break;
                    }
                }
                closed.store(true, Ordering::Release);
                // Dropping `stdin` here closes the pipe, sending EOF to the child.
            });
        }

        let timeout_secs = std::env::var("MCP_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Ok(Self {
            writer_tx,
            pending,
            child: Mutex::new(Some(child)),
            stderr_buffer,
            timeout_secs,
            closed,
        })
    }

    async fn stderr_context(&self) -> String {
        let buf = self.stderr_buffer.lock().await;
        if buf.is_empty() {
            return String::new();
        }
        format!("\n\nserver stderr:\n{}", buf.join("\n"))
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        if self.closed.load(Ordering::Acquire) {
            bail!("transport closed{}", self.stderr_context().await);
        }

        let key = msg.id.to_string();
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.pending.lock().await;
            p.insert(key.clone(), tx);
        }

        let mut data = serde_json::to_vec(msg)?;
        data.push(b'\n');
        if self.writer_tx.send(data).await.is_err() {
            self.pending.lock().await.remove(&key);
            bail!(
                "failed to write to stdin (writer task gone){}",
                self.stderr_context().await
            );
        }

        let dur = Duration::from_secs(self.timeout_secs);
        match timeout(dur, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                // Reader dropped the sender — server closed stdout.
                self.pending.lock().await.remove(&key);
                bail!("server closed stdout (EOF){}", self.stderr_context().await)
            }
            Err(_) => {
                // Timed out — clean up and bail.
                self.pending.lock().await.remove(&key);
                bail!(
                    "timeout waiting for server response{}",
                    self.stderr_context().await
                )
            }
        }
    }

    async fn notify(&self, msg: &JsonRpcNotification) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            bail!("transport closed");
        }
        let mut data = serde_json::to_vec(msg)?;
        data.push(b'\n');
        self.writer_tx
            .send(data)
            .await
            .map_err(|_| anyhow!("writer task gone"))?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);

        // Take ownership of the child, give it a brief grace period to exit
        // gracefully after stdin closes, then force-kill if still alive.
        let mut guard = self.child.lock().await;
        if let Some(mut child) = guard.take() {
            // Wait briefly for graceful exit. The writer task will close
            // stdin when its channel is dropped (after this transport is
            // dropped). For an explicit close path, we just kill.
            match timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(_)) => {}
                _ => {
                    let _ = child.start_kill();
                    let _ = timeout(Duration::from_secs(2), child.wait()).await;
                }
            }
        }
        Ok(())
    }
}
