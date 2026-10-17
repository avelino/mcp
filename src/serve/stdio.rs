use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::cache::ToolCacheStore;
use crate::config::Config;
use crate::instances::{self, InstanceFilter};
use crate::protocol::JsonRpcRequest;
use crate::server_auth::AuthIdentity;

use super::discovery::discover_pending_backends;
use super::dispatch::dispatch_request;
use super::proxy::{shutdown_clients_in_parallel, ProxyServer, SharedProxy};
use super::reload::AuthSnapshot;
// SIGHUP is the only way into a reload on this transport, so on a platform
// without it there is no reload path to carry invariants for.
#[cfg(unix)]
use super::reload::{reload_in_place, BootInvariants};

pub async fn run_stdio(mut config: Config, filter: InstanceFilter) -> Result<()> {
    // Raw value, captured before the resolution below rewrites it: a reload
    // compares what the operator wrote, not what serve mode defaulted to.
    #[cfg(unix)]
    let boot = BootInvariants {
        oauth_as_enabled: false,
        audit_output: config.audit.output.clone(),
        bind_addr: None,
    };

    // Serve-mode default resolution: when `audit.output` is unset
    // (`None`), auto-promote to `FileAndStderr` (not `FileAndStdout`)
    // because in stdio mode stdout carries the JSON-RPC channel. Any
    // explicit value the operator set is honored verbatim.
    let mut resolved_audit = crate::audit::AuditOutput::resolve_for_serve(
        config.audit.output.clone(),
        crate::audit::ServeContext::Stdio,
    );

    // Stdio-channel safety net: if the operator explicitly picked a
    // stdout-bound mode, redirect to its stderr equivalent with a
    // warning. This applies regardless of whether the value came from
    // auto-promotion (impossible in stdio context — promotion picks
    // stderr) or from the user.
    match resolved_audit {
        crate::audit::AuditOutput::Stdout => {
            tracing::warn!(
                "audit output=stdout conflicts with stdio transport, redirecting to stderr"
            );
            resolved_audit = crate::audit::AuditOutput::Stderr;
        }
        crate::audit::AuditOutput::FileAndStdout => {
            tracing::warn!(
                "audit output=file+stdout conflicts with stdio transport, redirecting to file+stderr"
            );
            resolved_audit = crate::audit::AuditOutput::FileAndStderr;
        }
        _ => {}
    }

    config.audit.output = Some(resolved_audit.clone());

    let pool = if resolved_audit.writes_to_file() {
        crate::db::create_pool(&config.audit).unwrap_or_else(|e| {
            tracing::warn!(error = format!("{e:#}"), "failed to create db pool");
            Arc::new(crate::db::DbPool::disabled())
        })
    } else {
        Arc::new(crate::db::DbPool::disabled())
    };
    let audit = AuditLogger::open(&config.audit, pool.clone()).unwrap_or(AuditLogger::Disabled);
    let cache_store = ToolCacheStore::new(pool).with_file_fallback();
    let mut server = ProxyServer::new(
        Arc::new(audit),
        config.servers.clone(),
        config.config_hashes.clone(),
        cache_store,
    );
    server.load_from_cache();
    let needs_refresh = Arc::new(std::sync::atomic::AtomicBool::new(!server.tools.is_empty()));
    let identity = AuthIdentity::anonymous();
    // Nothing authenticates on this transport, so the provider is `NoAuth` and
    // there is no reload gate. The snapshot exists for the ACL: it is the only
    // part of `serverAuth` stdio enforces, and a reload has to be able to
    // replace it under the requests already in flight.
    let auth = AuthSnapshot::new(
        Arc::new(crate::server_auth::NoAuth),
        config.server_auth.acl.clone(),
        Vec::new(),
    )
    .shared();

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
                        p.reset_cache_loaded_for_refresh();
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

    let filter = Arc::new(filter);

    // SIGHUP → reload, installed before the instance file exists. The order is
    // the point: SIGHUP's default disposition is terminate, so a pid published
    // before the handler is taken can be signalled into killing this process —
    // and on stdio that kills the client session that spawned it, which is the
    // exact state the feature exists to preserve.
    #[cfg(unix)]
    {
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|e| anyhow::anyhow!("failed to register SIGHUP handler: {e}"))?;
        let proxy = Arc::clone(&proxy);
        let auth = Arc::clone(&auth);
        let filter = Arc::clone(&filter);
        let boot = Arc::new(boot);
        tokio::spawn(async move {
            // A loop: the second SIGHUP has to be handled too, or it falls
            // through to the default disposition and takes the session down.
            while sighup.recv().await.is_some() {
                if let Err(e) = reload_in_place(&proxy, &auth, &filter, &boot, None).await {
                    tracing::warn!(
                        error = format!("{e:#}"),
                        "SIGHUP reload rejected; serving the previous config"
                    );
                }
            }
        });
    }

    // Held until this function returns; the drop unlinks the instance file.
    let _instance = match instances::register("stdio", None, &filter) {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!(
                error = format!("{e:#}"),
                "could not register this instance — `mcp reload` will not discover it"
            );
            None
        }
    };

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
            let acl = AuthSnapshot::read(&auth).acl;
            // No headers on this transport, so the body is the only place a
            // peer can declare the revision.
            let stateless_peer = super::dispatch::body_declares_stateless(&req);
            tokio::spawn(async move {
                let response =
                    dispatch_request(&proxy, req, &identity, &acl, "serve:stdio", stateless_peer)
                        .await;
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
