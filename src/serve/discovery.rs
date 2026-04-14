use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

use crate::audit::AuditEntry;
use crate::client::McpClient;
use crate::protocol::{Prompt, Resource, Tool};

use super::proxy::{BackendState, DiscoveryFailure, SharedProxy, UsageStats};

/// Discover tools from every backend that hasn't been seen yet, running all
/// discoveries in parallel and **without** holding the proxy mutex during I/O.
///
/// Concurrency safety: a dedicated `discovery_lock` (separate from the proxy
/// mutex) is acquired so that two callers don't both spawn duplicate connect
/// attempts. The second caller blocks on `discovery_lock` only — request
/// handlers targeting already-discovered backends are not affected.
pub(crate) async fn discover_pending_backends(proxy: &SharedProxy) {
    // Grab the discovery lock without holding the proxy mutex.
    let discovery_lock = {
        let p = proxy.lock().await;
        Arc::clone(&p.discovery_lock)
    };
    let _guard = discovery_lock.lock().await;

    // After acquiring the discovery lock, re-snapshot: another caller may
    // have raced ahead while we were waiting.
    let pending = {
        let p = proxy.lock().await;
        p.snapshot_pending_discovery()
    };
    if pending.is_empty() {
        return;
    }

    for name in pending.iter().map(|(n, _)| n) {
        eprintln!("[serve] discovering tools from {name}...");
    }

    let discovery_timeout = Duration::from_secs(30);

    // Fire all discoveries in parallel WITHOUT the proxy lock held.
    type DiscoveryOutcome = std::result::Result<
        Result<(McpClient, Vec<Tool>, Vec<Resource>, Vec<Prompt>)>,
        tokio::time::error::Elapsed,
    >;
    let mut joinset: tokio::task::JoinSet<(String, DiscoveryOutcome)> = tokio::task::JoinSet::new();
    for (name, server_config) in pending {
        joinset.spawn(async move {
            let result = tokio::time::timeout(discovery_timeout, async {
                let client = McpClient::connect(&server_config).await?;
                let tools = client.list_tools().await?;
                let resources = match client.list_resources().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[serve] {name}: resources/list not supported or failed: {e:#}");
                        vec![]
                    }
                };
                let prompts = match client.list_prompts().await {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[serve] {name}: prompts/list not supported or failed: {e:#}");
                        vec![]
                    }
                };
                Ok::<_, anyhow::Error>((client, tools, resources, prompts))
            })
            .await;
            (name, result)
        });
    }

    // Commit each result under a brief proxy lock as it arrives. Backends
    // already populated by another caller are skipped (their freshly-spawned
    // child is dropped, and `kill_on_drop` reaps it).
    while let Some(joined) = joinset.join_next().await {
        let (name, result) = match joined {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[serve] discovery task panicked: {e}");
                continue;
            }
        };
        match result {
            Ok(Ok((client, tools, resources, prompts))) => {
                let mut p = proxy.lock().await;
                if p.discovered_backends.contains(&name) {
                    // Lost the race — discard our client; kill_on_drop reaps it.
                    drop(client);
                    continue;
                }
                eprintln!(
                    "[serve] {name}: {} tool(s), {} resource(s), {} prompt(s)",
                    tools.len(),
                    resources.len(),
                    prompts.len()
                );
                p.register_tools(&name, &tools);
                p.register_resources(&name, &resources);
                p.register_prompts(&name, &prompts);
                p.backends.insert(
                    name.clone(),
                    BackendState::Connected {
                        client: Arc::new(client),
                        usage_stats: UsageStats::new(),
                    },
                );
                p.discovered_backends.insert(name.clone());
                p.discovery_failures.remove(&name);
            }
            Ok(Err(e)) => {
                let mut p = proxy.lock().await;
                let msg = format!("failed to discover: {e:#}");
                eprintln!("[serve] {name}: {msg}");
                p.audit.log(AuditEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: "serve:discovery".to_string(),
                    method: "discovery/failure".to_string(),
                    tool_name: None,
                    server_name: Some(name.clone()),
                    identity: "system".to_string(),
                    duration_ms: 0,
                    success: false,
                    error_message: Some(msg),
                    arguments: None,
                    acl_decision: None,
                    acl_matched_rule: None,
                    acl_access_kind: None,
                    classification_kind: None,
                    classification_source: None,
                    classification_confidence: None,
                });
                p.discovery_failures
                    .entry(name)
                    .or_insert_with(DiscoveryFailure::new)
                    .record_failure();
            }
            Err(_) => {
                let mut p = proxy.lock().await;
                let msg = format!("discovery timed out ({}s)", discovery_timeout.as_secs());
                eprintln!("[serve] {name}: {msg}");
                p.audit.log(AuditEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: "serve:discovery".to_string(),
                    method: "discovery/timeout".to_string(),
                    tool_name: None,
                    server_name: Some(name.clone()),
                    identity: "system".to_string(),
                    duration_ms: discovery_timeout.as_millis() as u64,
                    success: false,
                    error_message: Some(msg),
                    arguments: None,
                    acl_decision: None,
                    acl_matched_rule: None,
                    acl_access_kind: None,
                    classification_kind: None,
                    classification_source: None,
                    classification_confidence: None,
                });
                p.discovery_failures
                    .entry(name)
                    .or_insert_with(DiscoveryFailure::new)
                    .record_failure();
            }
        }
    }

    // Build the cache snapshot under a brief lock, then release the lock
    // before writing to disk. Disk writes through ChronDB are synchronous
    // and would otherwise block every request handler.
    let (cache_entries, cache_store) = {
        let p = proxy.lock().await;
        eprintln!(
            "[serve] ready — {} backend(s), {} tool(s), {} resource(s), {} prompt(s)",
            p.backends.len(),
            p.tools.len(),
            p.resources.len(),
            p.prompts.len()
        );
        (p.snapshot_cache_entries(), p.cache_store.clone())
    };
    for (name, entry) in &cache_entries {
        cache_store.save_backend(name, entry);
    }

    // Persist classifier cache (fresh entries from register_tools).
    {
        let mut p = proxy.lock().await;
        p.classifier_cache.save();
    }
}

/// Discover a single named backend.  Used by `tools/call`, `resources/read`,
/// and `prompts/get` when the requested item is unknown but its backend can be
/// inferred from the namespaced name (`server__tool`).  This avoids blocking
/// on every other configured backend — only the target server is discovered.
///
/// Uses the **same** `discovery_lock` as `discover_pending_backends` so a
/// concurrent full-discovery batch and a single-backend discovery never race
/// to spawn duplicate connections for the same server.
pub(crate) async fn discover_single_backend(proxy: &SharedProxy, backend_name: &str) {
    let discovery_lock = {
        let p = proxy.lock().await;
        Arc::clone(&p.discovery_lock)
    };
    let _guard = discovery_lock.lock().await;

    // Re-check under the lock: another caller may have discovered it while
    // we were waiting.
    let config = {
        let p = proxy.lock().await;
        if p.discovered_backends.contains(backend_name) {
            return;
        }
        if let Some(failure) = p.discovery_failures.get(backend_name) {
            if !failure.should_retry() {
                return;
            }
        }
        match p.configs.get(backend_name) {
            Some(cfg) => cfg.clone(),
            None => return,
        }
    };

    eprintln!("[serve] discovering tools from {backend_name}...");
    let discovery_timeout = Duration::from_secs(30);
    let name = backend_name.to_string();

    let result = tokio::time::timeout(discovery_timeout, async {
        let client = McpClient::connect(&config).await?;
        let tools = client.list_tools().await?;
        let resources = match client.list_resources().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[serve] {name}: resources/list not supported or failed: {e:#}");
                vec![]
            }
        };
        let prompts = match client.list_prompts().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[serve] {name}: prompts/list not supported or failed: {e:#}");
                vec![]
            }
        };
        Ok::<_, anyhow::Error>((client, tools, resources, prompts))
    })
    .await;

    match result {
        Ok(Ok((client, tools, resources, prompts))) => {
            let mut p = proxy.lock().await;
            if p.discovered_backends.contains(&name) {
                drop(client);
                return;
            }
            eprintln!(
                "[serve] {name}: {} tool(s), {} resource(s), {} prompt(s)",
                tools.len(),
                resources.len(),
                prompts.len()
            );
            p.register_tools(&name, &tools);
            p.register_resources(&name, &resources);
            p.register_prompts(&name, &prompts);
            p.backends.insert(
                name.clone(),
                BackendState::Connected {
                    client: Arc::new(client),
                    usage_stats: UsageStats::new(),
                },
            );
            p.discovered_backends.insert(name.clone());
            p.discovery_failures.remove(&name);
        }
        Ok(Err(e)) => {
            let mut p = proxy.lock().await;
            let msg = format!("failed to discover: {e:#}");
            eprintln!("[serve] {name}: {msg}");
            p.audit.log(AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source: "serve:discovery".to_string(),
                method: "discovery/failure".to_string(),
                tool_name: None,
                server_name: Some(name.clone()),
                identity: "system".to_string(),
                duration_ms: 0,
                success: false,
                error_message: Some(msg),
                arguments: None,
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });
            p.discovery_failures
                .entry(name)
                .or_insert_with(DiscoveryFailure::new)
                .record_failure();
        }
        Err(_) => {
            let mut p = proxy.lock().await;
            let msg = format!("discovery timed out ({}s)", discovery_timeout.as_secs());
            eprintln!("[serve] {name}: {msg}");
            p.audit.log(AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source: "serve:discovery".to_string(),
                method: "discovery/timeout".to_string(),
                tool_name: None,
                server_name: Some(name.clone()),
                identity: "system".to_string(),
                duration_ms: discovery_timeout.as_millis() as u64,
                success: false,
                error_message: Some(msg),
                arguments: None,
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });
            p.discovery_failures
                .entry(name.clone())
                .or_insert_with(DiscoveryFailure::new)
                .record_failure();
        }
    }

    // Persist cache for this single backend outside the proxy lock.
    let (cache_entry, cache_store) = {
        let p = proxy.lock().await;
        let entries = p.snapshot_cache_entries();
        let entry = entries
            .into_iter()
            .find(|(n, _)| n == backend_name)
            .map(|(_, e)| e);
        (entry, p.cache_store.clone())
    };
    if let Some(entry) = cache_entry {
        let bname = backend_name.to_string();
        tokio::spawn(async move {
            cache_store.save_backend(&bname, &entry);
        });
    }

    // Persist classifier cache (fresh entries from register_tools).
    {
        let mut p = proxy.lock().await;
        p.classifier_cache.save();
    }
}

/// Connect (or reconnect) to a backend, doing the network/spawn I/O **without**
/// holding the proxy lock. Briefly re-acquires the lock at the end to install
/// the new client and pick up the previous one (if any) for shutdown outside
/// the lock.
pub(crate) async fn connect_backend(
    proxy: &SharedProxy,
    server_name: &str,
) -> Result<Arc<McpClient>> {
    // Acquire the per-backend connect lock. This is what prevents two
    // concurrent callers from both spawning a fresh child for the same
    // backend and racing to install it — the second caller blocks here and,
    // on the other side of the lock, finds the backend already Connected
    // and returns the shared Arc without doing any I/O.
    let (config, connect_lock) = {
        let mut p = proxy.lock().await;
        let config = p
            .configs
            .get(server_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown backend: {server_name}"))?;
        let lock = p.connect_lock_for(server_name);
        (config, lock)
    };
    let _connect_guard = connect_lock.lock().await;

    // Re-check after acquiring the connect lock: another caller may have
    // already completed the connect while we were queued.
    if let Some(existing) = {
        let mut p = proxy.lock().await;
        p.try_get_client(server_name)
    } {
        return Ok(existing);
    }

    eprintln!("[serve] connecting to {server_name}...");
    let client = McpClient::connect(&config).await?;
    let tools = client.list_tools().await?;
    let resources = match client.list_resources().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[serve] {server_name}: resources/list not supported or failed: {e:#}");
            vec![]
        }
    };
    let prompts = match client.list_prompts().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[serve] {server_name}: prompts/list not supported or failed: {e:#}");
            vec![]
        }
    };
    let client = Arc::new(client);

    let prev = {
        let mut p = proxy.lock().await;
        let prev = p.install_client(
            server_name,
            Arc::clone(&client),
            &tools,
            &resources,
            &prompts,
        );
        // Persist new classifications from register_tools.
        p.classifier_cache.save();
        prev
    };

    // Shut down any displaced previous client outside the lock.
    if let Some(prev) = prev {
        let name = server_name.to_string();
        tokio::spawn(async move {
            if tokio::time::timeout(Duration::from_secs(5), prev.shutdown())
                .await
                .is_err()
            {
                eprintln!(
                    "[serve] {name}: previous client shutdown timed out — force-killed via drop"
                );
            }
            drop(prev);
        });
    }

    Ok(client)
}
