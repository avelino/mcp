use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::cache::ToolCacheStore;
use crate::config::Config;
use crate::protocol::JsonRpcRequest;
use crate::server_auth::AuthIdentity;

use super::discovery::discover_pending_backends;
use super::dispatch::dispatch_request;
use super::proxy::{shutdown_clients_in_parallel, ProxyServer, SharedProxy};

pub async fn run_stdio(mut config: Config) -> Result<()> {
    // In stdio mode, stdout is the JSON-RPC transport. Redirect audit to stderr
    // to avoid interleaving audit JSON lines with protocol responses.
    if config.audit.output == crate::audit::AuditOutput::Stdout {
        tracing::warn!("audit output=stdout conflicts with stdio transport, redirecting to stderr");
        config.audit.output = crate::audit::AuditOutput::Stderr;
    }

    let pool = if config.audit.output == crate::audit::AuditOutput::File {
        crate::db::create_pool(&config.audit).unwrap_or_else(|e| {
            tracing::warn!(error = format!("{e:#}"), "failed to create db pool");
            Arc::new(crate::db::DbPool::disabled())
        })
    } else {
        Arc::new(crate::db::DbPool::disabled())
    };
    let audit = AuditLogger::open(&config.audit, pool.clone()).unwrap_or(AuditLogger::Disabled);
    let cache_store = ToolCacheStore::new(pool);
    let mut server = ProxyServer::new(
        Arc::new(audit),
        config.servers.clone(),
        config.config_hashes.clone(),
        cache_store,
    );
    server.load_from_cache();
    let needs_refresh = Arc::new(std::sync::atomic::AtomicBool::new(!server.tools.is_empty()));
    let identity = AuthIdentity::anonymous();
    let acl = config.server_auth.acl.clone();

    let proxy: SharedProxy = Arc::new(Mutex::new(server));

    let stdin = tokio::io::stdin();
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut reader = BufReader::new(stdin);

    // Background reaper task: same logic as the HTTP path. Force-kills any
    // child whose graceful shutdown exceeds the timeout.
    {
        let proxy = Arc::clone(&proxy);
        let needs_refresh = Arc::clone(&needs_refresh);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                if needs_refresh.swap(false, std::sync::atomic::Ordering::AcqRel) {
                    {
                        let mut p = proxy.lock().await;
                        p.discovered_backends.clear();
                    }
                    discover_pending_backends(&proxy).await;
                }
                let idle = {
                    let mut p = proxy.lock().await;
                    p.collect_idle_backends()
                };
                shutdown_clients_in_parallel(idle).await;
            }
        });
    }

    tracing::info!("waiting for MCP client");

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF
        }
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Spawn each request so multiple in-flight requests can run in
        // parallel even on the stdio control channel.
        if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&line) {
            let proxy = Arc::clone(&proxy);
            let stdout = Arc::clone(&stdout);
            let identity = identity.clone();
            let acl = acl.clone();
            tokio::spawn(async move {
                let response = dispatch_request(&proxy, req, &identity, &acl, "serve:stdio").await;
                let mut data = match serde_json::to_string(&response) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                data.push('\n');
                let mut out = stdout.lock().await;
                let _ = out.write_all(data.as_bytes()).await;
                let _ = out.flush().await;
            });
        }
        // Notifications (no id) — silently dropped.
    }

    let drained = {
        let mut p = proxy.lock().await;
        p.drain_connected()
    };
    shutdown_clients_in_parallel(drained).await;
    tracing::info!("shutting down");
    Ok(())
}
