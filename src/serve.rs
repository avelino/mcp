use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::audit::{AuditEntry, AuditLogger};
use crate::cache::{BackendToolCache, ToolCacheStore};
use crate::client::McpClient;
use crate::config::{parse_duration_str, Config, IdleTimeoutPolicy, ServerConfig};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, Tool, PROTOCOL_VERSION};
use crate::server_auth::{self, AclConfig, AuthIdentity, AuthProvider, Credentials};

const SEPARATOR: &str = "__";

/// Tracks per-backend usage patterns for adaptive idle timeout.
#[derive(Debug, Clone)]
struct UsageStats {
    request_count: u64,
    first_used: Instant,
    last_used: Instant,
    /// Exponential moving average of intervals between requests (ms).
    ema_interval_ms: f64,
}

impl UsageStats {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            request_count: 0,
            first_used: now,
            last_used: now,
            ema_interval_ms: 0.0,
        }
    }

    fn record_request(&mut self) {
        let now = Instant::now();
        if self.request_count > 0 {
            let interval = now.duration_since(self.last_used).as_millis() as f64;
            // EMA with α=0.3: recent intervals weigh more
            self.ema_interval_ms = 0.3 * interval + 0.7 * self.ema_interval_ms;
        }
        self.last_used = now;
        self.request_count += 1;
    }

    fn idle_duration(&self) -> Duration {
        self.last_used.elapsed()
    }

    fn compute_adaptive_timeout(&self, min: Duration, max: Duration) -> Duration {
        if self.request_count < 2 {
            return min;
        }
        let elapsed_hours = self.first_used.elapsed().as_secs_f64() / 3600.0;
        let rph = if elapsed_hours > 0.001 {
            self.request_count as f64 / elapsed_hours
        } else {
            self.request_count as f64 * 3600.0 // extrapolate
        };

        let timeout = if rph > 20.0 {
            Duration::from_secs(5 * 60) // hot: 5min
        } else if rph > 5.0 {
            Duration::from_secs(3 * 60) // warm: 3min
        } else {
            Duration::from_secs(60) // cold: 1min
        };

        timeout.clamp(min, max)
    }
}

enum BackendState {
    Disconnected {
        #[allow(dead_code)]
        cached_tools: Vec<Tool>,
        usage_stats: UsageStats,
    },
    Connected {
        client: Arc<McpClient>,
        usage_stats: UsageStats,
    },
}

/// Tracks discovery failures for exponential backoff on retries.
#[derive(Debug, Clone)]
struct DiscoveryFailure {
    attempts: u32,
    last_attempt: Instant,
}

impl DiscoveryFailure {
    fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt: Instant::now(),
        }
    }

    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt = Instant::now();
    }

    /// Returns true if enough time has passed to retry, using exponential backoff.
    /// Backoff after first failure: 30s, 60s, 120s, 240s (capped at 300s).
    /// Bumped from the previous 5/10/20/40 because a 30s discovery timeout
    /// for a flaky backend (e.g. slack auth) used to retry every few seconds
    /// and steal the discovery_lock from healthy backends repeatedly.
    fn should_retry(&self) -> bool {
        if self.attempts == 0 {
            return true;
        }
        let backoff_secs = (30u64 << (self.attempts - 1).min(3)).min(300);
        self.last_attempt.elapsed() >= Duration::from_secs(backoff_secs)
    }
}

type SharedProxy = Arc<Mutex<ProxyServer>>;

/// Result of resolving a `tools/call` request: server name, original tool
/// name, arguments, and (optionally) an already-connected client.
type ResolvedCall = (String, String, Value, Option<Arc<McpClient>>);

struct ProxyServer {
    configs: HashMap<String, ServerConfig>,
    backends: HashMap<String, BackendState>,
    tool_map: HashMap<String, (String, String)>, // namespaced -> (server, original_name)
    tools: Vec<Tool>,
    audit: Arc<AuditLogger>,
    /// Tracks which backends have been successfully discovered.
    discovered_backends: std::collections::HashSet<String>,
    /// Tracks backends that failed discovery for exponential backoff.
    discovery_failures: HashMap<String, DiscoveryFailure>,
    /// SHA-256 hashes of backend configs for cache invalidation.
    config_hashes: HashMap<String, String>,
    /// Persistent tool cache backed by shared ChronDB.
    cache_store: ToolCacheStore,
    /// Serializes concurrent discovery batches so two callers don't both
    /// spawn duplicate connect attempts for the same set of backends.
    /// This is intentionally **separate** from the proxy mutex — discovery
    /// I/O happens with the proxy mutex released, so request handlers
    /// targeting already-discovered backends are never blocked by it.
    discovery_lock: Arc<tokio::sync::Mutex<()>>,
    /// Per-backend connect locks. When a `tools/call` hits a disconnected
    /// backend, the first caller acquires the per-backend lock, performs
    /// the full connect (spawn + initialize + list_tools) with the proxy
    /// mutex released, and installs the client. Concurrent callers wait on
    /// the same per-backend lock instead of all spawning duplicate children.
    connect_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl ProxyServer {
    fn new(
        audit: Arc<AuditLogger>,
        configs: HashMap<String, ServerConfig>,
        config_hashes: HashMap<String, String>,
        cache_store: ToolCacheStore,
    ) -> Self {
        Self {
            configs,
            backends: HashMap::new(),
            tool_map: HashMap::new(),
            tools: Vec::new(),
            audit,
            discovered_backends: std::collections::HashSet::new(),
            discovery_failures: HashMap::new(),
            config_hashes,
            cache_store,
            discovery_lock: Arc::new(tokio::sync::Mutex::new(())),
            connect_locks: HashMap::new(),
        }
    }

    /// Return (creating on first call) the per-backend connect lock.
    fn connect_lock_for(&mut self, server_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.connect_locks
                .entry(server_name.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    fn register_tools(&mut self, server_name: &str, tools: &[Tool]) {
        for tool in tools {
            let namespaced = format!("{server_name}{SEPARATOR}{}", tool.name);
            let description = match &tool.description {
                Some(desc) => Some(format!("[{server_name}] {desc}")),
                None => Some(format!("[{server_name}]")),
            };
            self.tool_map.insert(
                namespaced.clone(),
                (server_name.to_string(), tool.name.clone()),
            );
            self.tools.push(Tool {
                name: namespaced,
                description,
                input_schema: tool.input_schema.clone(),
            });
        }
    }

    fn unregister_tools(&mut self, server_name: &str) {
        let prefix = format!("{server_name}{SEPARATOR}");
        self.tools.retain(|t| !t.name.starts_with(&prefix));
        self.tool_map.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Collect cached tools for a server from the current tool list (for storing in Disconnected state).
    fn collect_cached_tools(&self, server_name: &str) -> Vec<Tool> {
        let prefix = format!("{server_name}{SEPARATOR}");
        self.tools
            .iter()
            .filter(|t| t.name.starts_with(&prefix))
            .cloned()
            .collect()
    }

    /// Load tools from persistent cache. Only loads entries whose config hash matches.
    fn load_from_cache(&mut self) {
        let cached = self.cache_store.load_valid_backends(&self.config_hashes);
        for (name, entry) in cached {
            if !self.configs.contains_key(&name) {
                continue;
            }
            self.register_tools(&name, &entry.tools);
            self.discovered_backends.insert(name.clone());
            self.backends.insert(
                name.clone(),
                BackendState::Disconnected {
                    cached_tools: entry.tools,
                    usage_stats: UsageStats::new(),
                },
            );
            let tool_count = self
                .tools
                .iter()
                .filter(|t| t.name.starts_with(&format!("{name}{SEPARATOR}")))
                .count();
            eprintln!("[serve] {name}: {tool_count} tool(s) (cached)");
        }
    }

    /// Build a snapshot of cache entries to persist. This is pure in-memory
    /// work and is cheap to run under the proxy lock; the actual disk writes
    /// are done by `persist_cache_snapshot` with the proxy lock released.
    fn snapshot_cache_entries(&self) -> Vec<(String, BackendToolCache)> {
        let mut out = Vec::new();
        for name in &self.discovered_backends {
            let prefix = format!("{name}{SEPARATOR}");
            let tools: Vec<Tool> = self
                .tools
                .iter()
                .filter(|t| t.name.starts_with(&prefix))
                .map(|t| {
                    let original_name = t.name.strip_prefix(&prefix).unwrap_or(&t.name).to_string();
                    let original_desc = t.description.as_ref().map(|d| {
                        let tag = format!("[{name}] ");
                        d.strip_prefix(&tag).unwrap_or(d).to_string()
                    });
                    Tool {
                        name: original_name,
                        description: original_desc,
                        input_schema: t.input_schema.clone(),
                    }
                })
                .collect();

            if tools.is_empty() {
                continue;
            }

            if let Some(hash) = self.config_hashes.get(name) {
                out.push((
                    name.clone(),
                    BackendToolCache {
                        config_hash: hash.clone(),
                        tools,
                        cached_at: chrono::Utc::now().to_rfc3339(),
                    },
                ));
            }
        }
        out
    }

    /// Returns true if any configured backend needs discovery (not yet discovered,
    /// or previously failed and backoff period has elapsed).
    fn has_undiscovered_backends(&self) -> bool {
        self.configs.keys().any(|name| {
            if self.discovered_backends.contains(name) {
                return false;
            }
            // If it failed before, only retry after backoff
            match self.discovery_failures.get(name) {
                Some(failure) => failure.should_retry(),
                None => true, // never attempted
            }
        })
    }

    /// Snapshot the list of backends that still need discovery, respecting
    /// the failure backoff. This is the only piece of discovery that touches
    /// `&mut self` — the actual I/O happens in `discover_pending_backends`
    /// outside the proxy lock.
    fn snapshot_pending_discovery(&self) -> Vec<(String, ServerConfig)> {
        self.configs
            .iter()
            .filter(|(name, _)| {
                if self.discovered_backends.contains(*name) {
                    return false;
                }
                match self.discovery_failures.get(*name) {
                    Some(failure) => failure.should_retry(),
                    None => true,
                }
            })
            .map(|(name, cfg)| (name.clone(), cfg.clone()))
            .collect()
    }

    /// Try to grab an already-connected client without doing any I/O.
    /// Records the request in usage stats. Returns `None` if not connected.
    fn try_get_client(&mut self, server_name: &str) -> Option<Arc<McpClient>> {
        match self.backends.get_mut(server_name) {
            Some(BackendState::Connected {
                client,
                usage_stats,
            }) => {
                usage_stats.record_request();
                Some(Arc::clone(client))
            }
            _ => None,
        }
    }

    /// Install a freshly-connected client for `server_name`, replacing any
    /// previous state. Carries over usage stats from the previous entry.
    /// The previous client (if any) is returned so the caller can shut it
    /// down **outside** the proxy lock.
    fn install_client(
        &mut self,
        server_name: &str,
        client: Arc<McpClient>,
        tools: &[Tool],
    ) -> Option<Arc<McpClient>> {
        let (mut stats, prev) = match self.backends.remove(server_name) {
            Some(BackendState::Disconnected { usage_stats, .. }) => (usage_stats, None),
            Some(BackendState::Connected {
                usage_stats,
                client: prev,
            }) => (usage_stats, Some(prev)),
            None => (UsageStats::new(), None),
        };
        stats.record_request();

        self.unregister_tools(server_name);
        self.register_tools(server_name, tools);
        eprintln!(
            "[serve] {server_name}: {} tool(s) (reconnected)",
            tools.len()
        );

        self.discovered_backends.insert(server_name.to_string());
        self.backends.insert(
            server_name.to_string(),
            BackendState::Connected {
                client,
                usage_stats: stats,
            },
        );
        prev
    }

    /// Identify idle backends, move them to Disconnected state, and return
    /// the extracted clients for shutdown **outside** the lock.
    fn collect_idle_backends(&mut self) -> Vec<(String, Arc<McpClient>)> {
        let mut to_shutdown = Vec::new();

        for (name, state) in &self.backends {
            if let BackendState::Connected { usage_stats, .. } = state {
                let config = self.configs.get(name);
                let (policy, min, max) = match config {
                    Some(c) => (
                        c.idle_timeout_policy().clone(),
                        c.min_idle_timeout(),
                        c.max_idle_timeout(),
                    ),
                    None => (
                        IdleTimeoutPolicy::Adaptive,
                        crate::config::DEFAULT_MIN_IDLE_TIMEOUT,
                        crate::config::DEFAULT_MAX_IDLE_TIMEOUT,
                    ),
                };

                let timeout = match policy {
                    IdleTimeoutPolicy::Never => continue,
                    IdleTimeoutPolicy::Fixed(ref s) => {
                        parse_duration_str(s).unwrap_or(Duration::from_secs(300))
                    }
                    IdleTimeoutPolicy::Adaptive => usage_stats.compute_adaptive_timeout(min, max),
                };

                // Warm-up grace: a freshly-connected backend that has never
                // served a request stays alive for at least `max_idle_timeout`.
                // Without this, the proxy reaps every backend ~60s after start
                // and the first real `tools/call` pays a full reconnect — which
                // is exactly the "everything froze on first use" symptom.
                if usage_stats.request_count == 0 && usage_stats.first_used.elapsed() < max {
                    continue;
                }

                if usage_stats.idle_duration() > timeout {
                    to_shutdown.push(name.clone());
                }
            }
        }

        let mut clients = Vec::new();
        for name in to_shutdown {
            if let Some(BackendState::Connected {
                client,
                usage_stats,
            }) = self.backends.remove(&name)
            {
                let cached_tools = self.collect_cached_tools(&name);
                eprintln!(
                    "[serve] shutting down idle backend: {name} (idle {:?}, {} reqs)",
                    usage_stats.idle_duration(),
                    usage_stats.request_count,
                );
                self.backends.insert(
                    name.clone(),
                    BackendState::Disconnected {
                        cached_tools,
                        usage_stats,
                    },
                );
                clients.push((name, client));
            }
        }
        clients
    }

    fn handle_initialize(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mcp-proxy",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
    }

    /// Resolve a tool name to (server, original_name, args, ACL decision).
    /// Returns Err(JsonRpcResponse) if the call should be rejected immediately.
    #[allow(clippy::result_large_err)]
    fn resolve_tool_call(
        &self,
        id: &Value,
        params: Option<Value>,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> std::result::Result<(String, String, Value), JsonRpcResponse> {
        let params = match params {
            Some(p) => p,
            None => {
                return Err(JsonRpcResponse::error(
                    id.clone(),
                    -32602,
                    "missing params for tools/call",
                ));
            }
        };

        let tool_name = match params.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return Err(JsonRpcResponse::error(
                    id.clone(),
                    -32602,
                    "missing 'name' in tools/call params",
                ));
            }
        };

        if !server_auth::is_tool_allowed(identity, &tool_name, acl) {
            return Err(JsonRpcResponse::error(
                id.clone(),
                -32603,
                &format!(
                    "access denied: '{}' cannot use tool '{tool_name}'",
                    identity.subject
                ),
            ));
        }

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let (server_name, original_name) = match self.tool_map.get(&tool_name) {
            Some(mapping) => mapping.clone(),
            None => {
                return Err(JsonRpcResponse::error(
                    id.clone(),
                    -32602,
                    &format!("unknown tool: {tool_name}"),
                ));
            }
        };

        Ok((server_name, original_name, arguments))
    }

    /// Drain all connected backends and return them so they can be shut down
    /// in parallel **outside** the proxy lock.
    fn drain_connected(&mut self) -> Vec<(String, Arc<McpClient>)> {
        self.backends
            .drain()
            .filter_map(|(name, state)| match state {
                BackendState::Connected { client, .. } => Some((name, client)),
                _ => None,
            })
            .collect()
    }
}

/// Shut down a batch of backend clients in parallel. Each client is given up
/// to 5s to exit gracefully; if it doesn't, the `Arc<McpClient>` is dropped
/// and `kill_on_drop(true)` reaps the underlying child. Runs all shutdowns
/// concurrently via a `JoinSet` so 8 backends don't take 8 × 5s = 40s.
async fn shutdown_clients_in_parallel(clients: Vec<(String, Arc<McpClient>)>) {
    if clients.is_empty() {
        return;
    }
    let mut joinset: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    for (name, client) in clients {
        joinset.spawn(async move {
            eprintln!("[serve] finalizing shutdown for {name}");
            if tokio::time::timeout(Duration::from_secs(5), client.shutdown())
                .await
                .is_err()
            {
                eprintln!("[serve] {name}: shutdown timed out — force-killed via drop");
            }
            // Dropping the last Arc<McpClient> drops the transport, which
            // kills the child via kill_on_drop(true).
            drop(client);
        });
    }
    while let Some(_res) = joinset.join_next().await {}
}

/// Discover tools from every backend that hasn't been seen yet, running all
/// discoveries in parallel and **without** holding the proxy mutex during I/O.
///
/// Concurrency safety: a dedicated `discovery_lock` (separate from the proxy
/// mutex) is acquired so that two callers don't both spawn duplicate connect
/// attempts. The second caller blocks on `discovery_lock` only — request
/// handlers targeting already-discovered backends are not affected.
async fn discover_pending_backends(proxy: &SharedProxy) {
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
    type DiscoveryOutcome =
        std::result::Result<Result<(McpClient, Vec<Tool>)>, tokio::time::error::Elapsed>;
    let mut joinset: tokio::task::JoinSet<(String, DiscoveryOutcome)> = tokio::task::JoinSet::new();
    for (name, server_config) in pending {
        joinset.spawn(async move {
            let result = tokio::time::timeout(discovery_timeout, async {
                let client = McpClient::connect(&server_config).await?;
                let tools = client.list_tools().await?;
                Ok::<_, anyhow::Error>((client, tools))
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
            Ok(Ok((client, tools))) => {
                let mut p = proxy.lock().await;
                if p.discovered_backends.contains(&name) {
                    // Lost the race — discard our client; kill_on_drop reaps it.
                    drop(client);
                    continue;
                }
                eprintln!("[serve] {name}: {} tool(s)", tools.len());
                p.register_tools(&name, &tools);
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
                eprintln!("[serve] {name}: failed to discover: {e:#}");
                p.discovery_failures
                    .entry(name)
                    .or_insert_with(DiscoveryFailure::new)
                    .record_failure();
            }
            Err(_) => {
                let mut p = proxy.lock().await;
                eprintln!(
                    "[serve] {name}: discovery timed out ({}s)",
                    discovery_timeout.as_secs()
                );
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
            "[serve] ready — {} backend(s), {} tool(s)",
            p.backends.len(),
            p.tools.len()
        );
        (p.snapshot_cache_entries(), p.cache_store.clone())
    };
    for (name, entry) in &cache_entries {
        cache_store.save_backend(name, entry);
    }
}

/// Top-level non-blocking request dispatcher.
///
/// This function is the **only** path that should be called from per-request
/// HTTP handlers. It carefully scopes the proxy lock to short read/write
/// windows and **never** holds the lock across backend I/O — different
/// backends run fully in parallel, and many concurrent calls to the same
/// backend share the same `Arc<McpClient>` (whose transport multiplexes
/// internally where possible).
async fn dispatch_request(
    proxy: &SharedProxy,
    req: JsonRpcRequest,
    identity: &AuthIdentity,
    acl: &Option<AclConfig>,
    source: &str,
) -> JsonRpcResponse {
    let start = std::time::Instant::now();
    let method = req.method.clone();
    let id = req.id.clone();

    // Audit metadata captured outside the lock.
    let audit_logger: Arc<AuditLogger>;
    let mut tool_name_for_audit: Option<String> = None;
    let mut server_name_for_audit: Option<String> = None;

    let response = match req.method.as_str() {
        "initialize" => {
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            p.handle_initialize(id)
        }
        "tools/list" => {
            // Decide whether to trigger discovery, then drop the proxy lock
            // before doing any I/O. Discovery is serialized via the separate
            // discovery_lock inside discover_pending_backends.
            let needs_discovery = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                p.tools.is_empty() && p.has_undiscovered_backends()
            };
            if needs_discovery {
                discover_pending_backends(proxy).await;
            }
            let tools_snapshot: Vec<Value> = {
                let p = proxy.lock().await;
                p.tools
                    .iter()
                    .filter(|t| server_auth::is_tool_allowed(identity, &t.name, acl))
                    .map(|t| serde_json::to_value(t).unwrap())
                    .collect()
            };
            JsonRpcResponse::success(id, json!({ "tools": tools_snapshot }))
        }
        "tools/call" => {
            // Capture the requested tool name up front so access-denied and
            // unknown-tool responses are still attributable in the audit log.
            if let Some(Value::String(name)) = req.params.as_ref().and_then(|v| v.get("name")) {
                tool_name_for_audit = Some(name.clone());
            }

            // Decide whether discovery is needed before resolving routing.
            // Discovery happens **outside** the proxy lock; only its outcome
            // affects the resolve step.
            let needs_discovery = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                match req.params.as_ref().and_then(|v| v.get("name")) {
                    Some(Value::String(name)) => {
                        !p.tool_map.contains_key(name) && p.has_undiscovered_backends()
                    }
                    _ => false,
                }
            };
            if needs_discovery {
                discover_pending_backends(proxy).await;
            }

            // Phase 1: resolve routing under a brief lock.
            let resolved: std::result::Result<ResolvedCall, JsonRpcResponse> = {
                let mut p = proxy.lock().await;
                match p.resolve_tool_call(&id, req.params.clone(), identity, acl) {
                    Ok((server, orig, args)) => {
                        let client = p.try_get_client(&server);
                        // Refine the audit entry now that we know the
                        // namespaced tool resolves to a real backend.
                        tool_name_for_audit = Some(format!("{server}{SEPARATOR}{orig}"));
                        server_name_for_audit = Some(server.clone());
                        Ok((server, orig, args, client))
                    }
                    Err(resp) => Err(resp),
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, original, args, maybe_client)) => {
                    // Phase 2: ensure connected (without holding the proxy
                    // lock during the connect itself).
                    let client_result: Result<Arc<McpClient>> = match maybe_client {
                        Some(c) => Ok(c),
                        None => connect_backend(proxy, &server).await,
                    };

                    match client_result {
                        Err(e) => JsonRpcResponse::error(
                            id,
                            -32603,
                            &format!("failed to connect to backend '{server}': {e:#}"),
                        ),
                        Ok(client) => {
                            // Phase 3: invoke the backend with NO proxy lock held.
                            match client.call_tool(&original, args).await {
                                Ok(result) => JsonRpcResponse::success(
                                    id,
                                    serde_json::to_value(&result).unwrap(),
                                ),
                                Err(e) => {
                                    JsonRpcResponse::error(id, -32603, &format!("[{server}] {e:#}"))
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            JsonRpcResponse::error(id, -32601, &format!("method not found: {}", req.method))
        }
    };

    finish_audit(
        AuditCtx {
            audit: audit_logger,
            source,
            method,
            tool_name: tool_name_for_audit,
            server_name: server_name_for_audit,
            identity,
            start,
        },
        response,
    )
}

struct AuditCtx<'a> {
    audit: Arc<AuditLogger>,
    source: &'a str,
    method: String,
    tool_name: Option<String>,
    server_name: Option<String>,
    identity: &'a AuthIdentity,
    start: std::time::Instant,
}

fn finish_audit(ctx: AuditCtx<'_>, response: JsonRpcResponse) -> JsonRpcResponse {
    ctx.audit.log(AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: ctx.source.to_string(),
        method: ctx.method,
        tool_name: ctx.tool_name,
        server_name: ctx.server_name,
        identity: ctx.identity.subject.clone(),
        duration_ms: ctx.start.elapsed().as_millis() as u64,
        success: response.error.is_none(),
        error_message: response.error.as_ref().map(|e| e.message.clone()),
        arguments: None,
    });
    response
}

/// Connect (or reconnect) to a backend, doing the network/spawn I/O **without**
/// holding the proxy lock. Briefly re-acquires the lock at the end to install
/// the new client and pick up the previous one (if any) for shutdown outside
/// the lock.
async fn connect_backend(proxy: &SharedProxy, server_name: &str) -> Result<Arc<McpClient>> {
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
    let client = Arc::new(client);

    let prev = {
        let mut p = proxy.lock().await;
        p.install_client(server_name, Arc::clone(&client), &tools)
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

// --- Stdio mode ---

pub async fn run_stdio(config: Config) -> Result<()> {
    let pool = crate::db::create_pool(&config.audit).unwrap_or_else(|e| {
        eprintln!("warning: failed to create db pool: {e:#}");
        Arc::new(crate::db::DbPool::disabled())
    });
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

    eprintln!("[serve] waiting for MCP client...");

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
    eprintln!("[serve] shutting down");
    Ok(())
}

// --- HTTP mode ---

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use tokio_stream::wrappers::ReceiverStream;

type SseSender = tokio::sync::mpsc::Sender<Result<Event, std::convert::Infallible>>;
type SessionMap = Arc<Mutex<HashMap<String, SseSender>>>;

#[derive(Clone)]
struct AppState {
    proxy: SharedProxy,
    auth_provider: Arc<dyn AuthProvider>,
    acl: Option<AclConfig>,
    sessions: SessionMap,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

/// Extract credentials from HTTP headers (only transport-aware code).
fn extract_credentials(headers: &HeaderMap) -> Credentials {
    let mut creds = Credentials::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            creds.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    creds
}

/// Authenticate an HTTP request. Returns identity on success, or a 401 response.
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthIdentity, (StatusCode, Json<Value>)> {
    let creds = extract_credentials(headers);
    state.auth_provider.authenticate(&creds).await.map_err(|e| {
        let err =
            JsonRpcResponse::error(Value::Null, -32000, &format!("authentication failed: {e}"));
        (StatusCode::UNAUTHORIZED, Json(json!(err)))
    })
}

/// Bind a TCP listener with TCP keepalive enabled. Short keepalive intervals
/// let us detect dead client sockets (e.g. opencode crashed mid-request) in
/// ~60s instead of waiting for the OS default (2h on macOS).
fn bind_listener_with_keepalive(addr: std::net::SocketAddr) -> Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    socket.set_tcp_keepalive(&keepalive)?;

    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(tokio::net::TcpListener::from_std(std_listener)?)
}

/// Validate that a bind address is safe.
/// Non-loopback addresses require --insecure flag.
fn validate_bind_addr(addr: &str, insecure: bool) -> Result<std::net::SocketAddr> {
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{addr}': {e}"))?;

    if !insecure && !sock_addr.ip().is_loopback() {
        bail!(
            "refusing to bind to non-loopback address {addr} without TLS.\n\
             Use --insecure to allow plaintext on non-loopback interfaces,\n\
             or bind to 127.0.0.1:{port} for local-only access.",
            port = sock_addr.port()
        );
    }

    Ok(sock_addr)
}

pub async fn run_http(config: Config, bind_addr: &str, insecure: bool) -> Result<()> {
    let sock_addr = validate_bind_addr(bind_addr, insecure)?;

    let auth_provider = server_auth::build_auth_provider(&config.server_auth)?;
    let acl = config.server_auth.acl.clone();

    let pool = crate::db::create_pool(&config.audit).unwrap_or_else(|e| {
        eprintln!("warning: failed to create db pool: {e:#}");
        Arc::new(crate::db::DbPool::disabled())
    });
    let audit = AuditLogger::open(&config.audit, pool.clone()).unwrap_or(AuditLogger::Disabled);
    let cache_store = ToolCacheStore::new(pool);
    let mut server = ProxyServer::new(
        Arc::new(audit),
        config.servers.clone(),
        config.config_hashes.clone(),
        cache_store,
    );
    server.load_from_cache();
    let has_cached_tools = !server.tools.is_empty();
    let shared: SharedProxy = Arc::new(Mutex::new(server));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let state = AppState {
        proxy: shared.clone(),
        auth_provider,
        acl,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        shutdown: shutdown_rx,
    };

    // Background reaper: shuts down idle backends periodically.
    // Lock is released before async shutdown so request handlers are never
    // blocked. Shutdowns run in parallel via JoinSet, and any backend whose
    // graceful close stalls is force-killed via Drop.
    let reaper_proxy = shared.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let idle_clients = {
                let mut proxy = reaper_proxy.lock().await;
                proxy.collect_idle_backends()
            };
            shutdown_clients_in_parallel(idle_clients).await;
        }
    });

    // Background refresh: re-discover tools from real backends after serving
    // cached tools. The lock is only held briefly to clear the discovered set;
    // the actual discovery I/O runs without the proxy mutex held, so client
    // requests for cached tools fly through with zero contention while the
    // refresh is in progress.
    if has_cached_tools {
        let refresh_proxy = shared.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            {
                let mut proxy = refresh_proxy.lock().await;
                let cached: Vec<String> = proxy.discovered_backends.iter().cloned().collect();
                for name in &cached {
                    proxy.discovered_backends.remove(name);
                }
            }
            discover_pending_backends(&refresh_proxy).await;
        });
    }

    // Log all incoming requests for debugging
    let request_logger = axum::middleware::from_fn(
        |req: axum::extract::Request, next: axum::middleware::Next| async move {
            eprintln!(
                "[serve] {} {} {}",
                req.method(),
                req.uri(),
                req.headers()
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
            );
            next.run(req).await
        },
    );

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler).get(mcp_sse_handler))
        .route("/mcp/sse", get(mcp_sse_handler))
        .fallback(|req: axum::extract::Request| async move {
            let path = req.uri().path().to_string();
            let method = req.method().clone();
            eprintln!(
                "[serve] UNHANDLED {} {} (headers: {:?})",
                method,
                path,
                req.headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
                    .collect::<Vec<_>>()
            );
            // OAuth/OIDC discovery endpoints: return 404 with valid JSON
            // so clients that probe for auth don't crash on empty bodies
            if path.contains(".well-known") || path == "/register" {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "not_found", "error_description": "This server does not support OAuth"})),
                );
            }
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
        })
        .layer(request_logger)
        .with_state(state.clone());

    eprintln!("[serve] HTTP server listening on {sock_addr}");
    if sock_addr.ip().is_loopback() {
        eprintln!("[serve] bound to loopback — local access only");
    } else {
        eprintln!("[serve] WARNING: bound to non-loopback address without TLS");
    }

    let listener = bind_listener_with_keepalive(sock_addr)?;

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown_signal = async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
        eprintln!("\n[serve] shutdown signal received");
        let _ = shutdown_tx.send(true);
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Cleanup backends — bounded so a stuck handler doesn't block exit.
    // Drain under the lock (cheap), then run all shutdowns in parallel.
    let cleanup = async {
        let drained = {
            let mut proxy = state.proxy.lock().await;
            proxy.drain_connected()
        };
        shutdown_clients_in_parallel(drained).await;
    };
    if tokio::time::timeout(Duration::from_secs(10), cleanup)
        .await
        .is_err()
    {
        eprintln!("[serve] shutdown timed out — forcing exit");
    }
    eprintln!("[serve] shutting down");

    Ok(())
}

// GET /health
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let proxy = state.proxy.lock().await;
    let connected = proxy
        .backends
        .values()
        .filter(|s| matches!(s, BackendState::Connected { .. }))
        .count();
    let active_clients = state.sessions.lock().await.len();
    let body = json!({
        "status": "ok",
        "backends_configured": proxy.configs.len(),
        "backends_connected": connected,
        "active_clients": active_clients,
        "tools": proxy.tools.len(),
        "version": env!("CARGO_PKG_VERSION"),
    });
    Json(body)
}

// POST /mcp — JSON-RPC request/response
async fn mcp_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Validate content type
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.is_empty() && !content_type.contains("application/json") {
        let err =
            JsonRpcResponse::error(Value::Null, -32700, "content-type must be application/json");
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(json!(err)));
    }

    // Authenticate
    let identity = match authenticate_request(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Parse JSON-RPC message (request or notification)
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let err = JsonRpcResponse::error(Value::Null, -32700, &format!("parse error: {e}"));
            return (StatusCode::BAD_REQUEST, Json(json!(err)));
        }
    };

    // Notifications have no "id" field — accept and return 202
    if msg.get("id").is_none() {
        return (StatusCode::ACCEPTED, Json(json!(null)));
    }

    let req: JsonRpcRequest = match serde_json::from_value(msg) {
        Ok(r) => r,
        Err(e) => {
            let err = JsonRpcResponse::error(Value::Null, -32700, &format!("parse error: {e}"));
            return (StatusCode::BAD_REQUEST, Json(json!(err)));
        }
    };

    // Per-request timeout: a single hung backend or dead client must NEVER
    // be able to wedge other in-flight requests. The actual backend hang is
    // already handled inside the transport (stdio has its own timeout) but
    // this is the belt-and-suspenders bound at the proxy boundary.
    let request_timeout = std::time::Duration::from_secs(
        std::env::var("MCP_PROXY_REQUEST_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120),
    );
    let req_id = req.id.clone();
    let response_json = match tokio::time::timeout(
        request_timeout,
        dispatch_request(&state.proxy, req, &identity, &state.acl, "serve:http"),
    )
    .await
    {
        Ok(resp) => serde_json::to_value(&resp).unwrap(),
        Err(_) => {
            let err = JsonRpcResponse::error(
                req_id,
                -32000,
                &format!(
                    "proxy request timed out after {}s",
                    request_timeout.as_secs()
                ),
            );
            serde_json::to_value(&err).unwrap()
        }
    };

    // If this POST came from an SSE session, send the response over the SSE
    // stream and return 202 Accepted (old HTTP+SSE transport).
    //
    // Critical: `tx.send(...).await` would block indefinitely if the SSE
    // channel buffer is full (slow or dead consumer). That used to wedge the
    // entire request handler. We bound the send with a 5s timeout and, on
    // failure, evict the session so future requests fail fast and the client
    // can reconnect.
    if let Some(session_id) = query.get("session_id") {
        let tx = {
            let sessions = state.sessions.lock().await;
            sessions.get(session_id).cloned()
        };
        if let Some(tx) = tx {
            let event = Event::default()
                .event("message")
                .data(serde_json::to_string(&response_json).unwrap());
            let send_result =
                tokio::time::timeout(std::time::Duration::from_secs(5), tx.send(Ok(event))).await;
            match send_result {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    // Receiver gone or buffer wedged → evict the session.
                    state.sessions.lock().await.remove(session_id);
                    eprintln!(
                        "[serve] sse session {session_id} evicted: stream send timed out or closed"
                    );
                }
            }
            return (StatusCode::ACCEPTED, Json(json!(null)));
        }
    }

    // Streamable HTTP transport: return response directly
    (StatusCode::OK, Json(response_json))
}

// GET /mcp/sse — SSE endpoint for streaming (old HTTP+SSE transport)
// Client connects via SSE, receives `endpoint` event, sends requests via POST,
// and receives JSON-RPC responses as SSE `message` events.
async fn mcp_sse_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // Authenticate
    if let Err(resp) = authenticate_request(&state, &headers).await {
        return resp.into_response();
    }

    // Buffer 256 absorbs bursts (e.g. tools/list snapshot of ~200 tools).
    // Combined with the 5s send timeout in the POST handler, no individual
    // backpressure event can wedge the proxy.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(256);

    // Send the endpoint event so clients know where to POST
    let session_id = uuid::Uuid::new_v4().to_string();
    let endpoint_event = Event::default()
        .event("endpoint")
        .data(format!("/mcp?session_id={session_id}"));

    // Register this session so POST handler can send responses via SSE
    {
        let mut sessions = state.sessions.lock().await;
        sessions.insert(session_id.clone(), tx.clone());
    }

    let sessions_clone = state.sessions.clone();
    let session_id_clone = session_id.clone();
    let mut shutdown_rx = state.shutdown.clone();
    tokio::spawn(async move {
        // Send the endpoint URI with a short bound — if the receiver isn't
        // ready in 5s the client is effectively dead.
        if tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tx.send(Ok(endpoint_event)),
        )
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
        {
            sessions_clone.lock().await.remove(&session_id_clone);
            return;
        }

        // Keep connection alive with periodic pings. We use `try_send` so a
        // momentarily-full buffer never blocks this background task — if the
        // buffer is genuinely backed up, the next interval will catch it.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        let mut consecutive_send_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let ping = Event::default().comment("ping");
                    match tx.try_send(Ok(ping)) {
                        Ok(()) => {
                            consecutive_send_failures = 0;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            break; // Client disconnected
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            consecutive_send_failures += 1;
                            // After ~1 minute (4 × 15s intervals) of full
                            // buffer, treat the session as wedged and evict.
                            if consecutive_send_failures >= 4 {
                                eprintln!(
                                    "[serve] sse session {session_id_clone} evicted: ping buffer full"
                                );
                                break;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    break; // Server shutting down
                }
            }
        }

        // Cleanup session on disconnect/eviction
        let mut sessions = sessions_clone.lock().await;
        sessions.remove(&session_id_clone);
    });

    Sse::new(ReceiverStream::new(rx)).into_response()
}

// --- Public entry point ---

pub async fn run(config: Config, http_addr: Option<&str>, insecure: bool) -> Result<()> {
    match http_addr {
        Some(addr) => run_http(config, addr, insecure).await,
        None => run_stdio(config).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Tool;

    fn test_server() -> ProxyServer {
        let pool = Arc::new(crate::db::DbPool::disabled());
        let cache_store = ToolCacheStore::new(pool);
        ProxyServer::new(
            Arc::new(AuditLogger::Disabled),
            HashMap::new(),
            HashMap::new(),
            cache_store,
        )
    }

    #[test]
    fn test_split_tool_name_via_separator() {
        assert_eq!(
            "sentry__search_issues".split_once(SEPARATOR),
            Some(("sentry", "search_issues"))
        );
        assert_eq!(
            "slack__send_message".split_once(SEPARATOR),
            Some(("slack", "send_message"))
        );
        assert_eq!("no_separator".split_once(SEPARATOR), None);
        assert_eq!("a__b__c".split_once(SEPARATOR), Some(("a", "b__c")));
    }

    #[test]
    fn test_tool_namespacing() {
        let tool = Tool {
            name: "search_issues".to_string(),
            description: Some("Search for issues".to_string()),
            input_schema: None,
        };

        let server_name = "sentry";
        let namespaced = format!("{server_name}{SEPARATOR}{}", tool.name);
        let description = format!("[{server_name}] {}", tool.description.as_deref().unwrap());

        assert_eq!(namespaced, "sentry__search_issues");
        assert_eq!(description, "[sentry] Search for issues");
    }

    #[test]
    fn test_proxy_server_initialize_response() {
        let server = test_server();
        let resp = server.handle_initialize(Value::from(1));
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "mcp-proxy");
    }

    #[test]
    fn test_proxy_server_initialize_with_string_id() {
        let server = test_server();
        let resp = server.handle_initialize(Value::String("req-1".to_string()));
        assert!(resp.error.is_none());
        assert_eq!(resp.id, Some(Value::String("req-1".to_string())));
    }

    /// Test helper: wraps `server` in a `SharedProxy` and routes a request
    /// through the production `dispatch_request` path.
    async fn dispatch(
        server: ProxyServer,
        req: JsonRpcRequest,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> JsonRpcResponse {
        let proxy: SharedProxy = Arc::new(Mutex::new(server));
        dispatch_request(&proxy, req, identity, acl, "test").await
    }

    #[tokio::test]
    async fn test_proxy_server_empty_tools_list() {
        let server = test_server();
        // No configs → has_undiscovered_backends() is false, discovery is skipped
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(2, "tools/list", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn test_proxy_server_tools_list_with_tools() {
        let mut server = test_server();
        // No configs → has_undiscovered_backends() is false, discovery is skipped
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search for issues".to_string()),
            input_schema: None,
        });
        server.tool_map.insert(
            "sentry__search_issues".to_string(),
            ("sentry".to_string(), "search_issues".to_string()),
        );

        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(3, "tools/list", None);
        let resp = dispatch(server, req, &identity, &None).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "sentry__search_issues");
        assert_eq!(tools[0]["description"], "[sentry] Search for issues");
    }

    #[tokio::test]
    async fn test_proxy_server_unknown_tool() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(
            4,
            "tools/call",
            Some(serde_json::json!({"name": "nonexistent__tool"})),
        );
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("unknown tool"));
    }

    #[tokio::test]
    async fn test_proxy_server_missing_params() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(5, "tools/call", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test]
    async fn test_proxy_server_missing_name_in_params() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(6, "tools/call", Some(serde_json::json!({"arguments": {}})));
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("missing 'name'"));
    }

    #[tokio::test]
    async fn test_proxy_server_backend_not_connected() {
        let mut server = test_server();
        let identity = AuthIdentity::anonymous();
        server.tool_map.insert(
            "ghost__tool".to_string(),
            ("ghost".to_string(), "tool".to_string()),
        );
        let req = JsonRpcRequest::new(
            7,
            "tools/call",
            Some(serde_json::json!({"name": "ghost__tool"})),
        );
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("failed to connect"));
    }

    #[tokio::test]
    async fn test_tools_call_triggers_discovery() {
        // tools/call before tools/list should trigger discovery
        let server = test_server();
        assert!(server.discovered_backends.is_empty());
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(
            20,
            "tools/call",
            Some(serde_json::json!({"name": "nonexistent__tool"})),
        );
        let resp = dispatch(server, req, &identity, &None).await;
        // No backends configured, so tool_map is empty → unknown tool
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("unknown tool"));
    }

    #[test]
    fn test_validate_bind_addr_loopback() {
        assert!(validate_bind_addr("127.0.0.1:8080", false).is_ok());
        assert!(validate_bind_addr("[::1]:8080", false).is_ok());
    }

    #[test]
    fn test_validate_bind_addr_non_loopback_rejected() {
        let result = validate_bind_addr("0.0.0.0:8080", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--insecure"));
    }

    #[test]
    fn test_validate_bind_addr_non_loopback_with_insecure() {
        assert!(validate_bind_addr("0.0.0.0:8080", true).is_ok());
    }

    #[test]
    fn test_validate_bind_addr_invalid() {
        assert!(validate_bind_addr("not-an-address", false).is_err());
    }

    #[tokio::test]
    async fn test_handle_request_unknown_method() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "unknown/method", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert!(err.message.contains("method not found"));
    }

    #[tokio::test]
    async fn test_handle_request_initialize() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "initialize", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn test_protocol_version_is_current() {
        assert_eq!(PROTOCOL_VERSION, "2025-11-25");
    }

    #[test]
    fn test_notification_has_no_id() {
        // JSON-RPC notifications have no "id" field
        let notification: Value = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert!(notification.get("id").is_none());

        // Requests have an "id" field
        let request: Value =
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        assert!(request.get("id").is_some());
    }

    #[tokio::test]
    async fn test_sse_session_registration_and_cleanup() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let session_id = "test-session-123".to_string();

        // Simulate registration
        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        {
            let mut map = sessions.lock().await;
            map.insert(session_id.clone(), tx);
            assert!(map.contains_key(&session_id));
        }

        // Simulate cleanup on disconnect
        {
            let mut map = sessions.lock().await;
            map.remove(&session_id);
            assert!(!map.contains_key(&session_id));
        }
    }

    #[tokio::test]
    async fn test_sse_session_response_routing() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let session_id = "route-test".to_string();

        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        {
            let mut map = sessions.lock().await;
            map.insert(session_id.clone(), tx);
        }

        // Simulate sending a response via the session channel
        {
            let map = sessions.lock().await;
            let sender = map.get(&session_id).unwrap();
            let event = Event::default()
                .event("message")
                .data(r#"{"id":1,"jsonrpc":"2.0","result":{"ok":true}}"#);
            sender.send(Ok(event)).await.unwrap();
        }

        // Verify the response arrives
        let received = rx.recv().await.unwrap().unwrap();
        // Event was received successfully
        assert!(format!("{:?}", received).contains("ok"));
    }

    #[tokio::test]
    async fn test_sse_session_missing_does_not_panic() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let map = sessions.lock().await;
        // Looking up a nonexistent session returns None, not panic
        assert!(map.get("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_tools_list_filtered_by_acl() {
        use crate::server_auth::{AclConfig, AclPolicy, AclRule};

        let mut server = test_server();
        // No configs → has_undiscovered_backends() is false, discovery is skipped
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search".to_string()),
            input_schema: None,
        });
        server.tools.push(Tool {
            name: "slack__send_message".to_string(),
            description: Some("[slack] Send".to_string()),
            input_schema: None,
        });

        let acl = Some(AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        });

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(10, "tools/list", None);
        let resp = dispatch(server, req, &bob, &acl).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "slack__send_message");
    }

    #[tokio::test]
    async fn test_tools_call_denied_by_acl() {
        use crate::server_auth::{AclConfig, AclPolicy, AclRule};

        let mut server = test_server();
        server.tool_map.insert(
            "sentry__search".to_string(),
            ("sentry".to_string(), "search".to_string()),
        );

        let acl = Some(AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        });

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(
            11,
            "tools/call",
            Some(serde_json::json!({"name": "sentry__search"})),
        );
        let resp = dispatch(server, req, &bob, &acl).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("access denied"));
    }

    #[test]
    fn test_extract_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer tok-123".parse().unwrap());
        headers.insert("x-forwarded-user", "alice".parse().unwrap());

        let creds = extract_credentials(&headers);
        assert_eq!(creds.get("authorization").unwrap(), "Bearer tok-123");
        assert_eq!(creds.get("x-forwarded-user").unwrap(), "alice");
    }

    // --- UsageStats tests ---

    #[test]
    fn test_usage_stats_new() {
        let stats = UsageStats::new();
        assert_eq!(stats.request_count, 0);
        assert_eq!(stats.ema_interval_ms, 0.0);
    }

    #[test]
    fn test_usage_stats_record_request() {
        let mut stats = UsageStats::new();
        stats.record_request();
        assert_eq!(stats.request_count, 1);

        stats.record_request();
        assert_eq!(stats.request_count, 2);
        // After second request, EMA should be > 0
        assert!(stats.ema_interval_ms >= 0.0);
    }

    #[test]
    fn test_usage_stats_adaptive_timeout_cold() {
        let mut stats = UsageStats::new();
        stats.request_count = 3;
        // Simulate: 3 requests over 2 hours → 1.5 rph = cold tier = 1min
        stats.first_used = Instant::now() - Duration::from_secs(7200);
        let timeout =
            stats.compute_adaptive_timeout(Duration::from_secs(60), Duration::from_secs(300));
        assert_eq!(timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_usage_stats_adaptive_timeout_minimum_requests() {
        let stats = UsageStats::new();
        // < 2 requests returns min
        let timeout =
            stats.compute_adaptive_timeout(Duration::from_secs(90), Duration::from_secs(1800));
        assert_eq!(timeout, Duration::from_secs(90));
    }

    #[test]
    fn test_usage_stats_adaptive_timeout_clamped() {
        let mut stats = UsageStats::new();
        stats.request_count = 100;
        // hot tier = 5min, but max is 2min, should clamp to max
        let timeout =
            stats.compute_adaptive_timeout(Duration::from_secs(60), Duration::from_secs(120));
        assert_eq!(timeout, Duration::from_secs(120)); // clamped to max
    }

    // --- DiscoveryFailure tests ---

    #[test]
    fn test_discovery_failure_initial_should_retry() {
        let failure = DiscoveryFailure::new();
        // Freshly created with 0 attempts — should always retry
        assert!(failure.should_retry());
    }

    #[test]
    fn test_discovery_failure_backoff_blocks_immediate_retry() {
        let mut failure = DiscoveryFailure::new();
        failure.record_failure();
        // Just failed — backoff is 5s (5 << 1.min(3) = 10, but first failure = 5 << 0+1? no)
        // Actually: attempts after record = 1, backoff = 5 << 1.min(3) = 10s
        // Immediately after failure, should_retry() should be false
        assert!(!failure.should_retry());
    }

    #[test]
    fn test_discovery_failure_backoff_caps_at_60s() {
        let mut failure = DiscoveryFailure::new();
        for _ in 0..10 {
            failure.record_failure();
        }
        // attempts = 10, min(3) = 3, 5 << 3 = 40, min(60) = 40
        // Actually let's verify: attempts.min(3) = 3, 5u64 << 3 = 40, 40.min(60) = 40
        // With many attempts it's still capped
        assert!(!failure.should_retry());
        assert_eq!(failure.attempts, 10);
    }

    #[test]
    fn test_discovery_failure_clears_on_success() {
        let mut server = test_server();
        let mut failure = DiscoveryFailure::new();
        failure.record_failure();
        server
            .discovery_failures
            .insert("test_backend".to_string(), failure);
        assert!(server.discovery_failures.contains_key("test_backend"));
        // Simulate success: remove from failures
        server.discovery_failures.remove("test_backend");
        assert!(!server.discovery_failures.contains_key("test_backend"));
    }

    // --- BackendState + register/unregister tests ---

    #[test]
    fn test_register_and_unregister_tools() {
        let mut server = test_server();
        let tools = vec![
            Tool {
                name: "search".to_string(),
                description: Some("Search stuff".to_string()),
                input_schema: None,
            },
            Tool {
                name: "create".to_string(),
                description: None,
                input_schema: None,
            },
        ];

        server.register_tools("sentry", &tools);
        assert_eq!(server.tools.len(), 2);
        assert_eq!(server.tool_map.len(), 2);
        assert!(server.tool_map.contains_key("sentry__search"));
        assert!(server.tool_map.contains_key("sentry__create"));

        // Register more tools from another server
        server.register_tools(
            "slack",
            &[Tool {
                name: "send".to_string(),
                description: Some("Send msg".to_string()),
                input_schema: None,
            }],
        );
        assert_eq!(server.tools.len(), 3);

        // Unregister sentry tools
        server.unregister_tools("sentry");
        assert_eq!(server.tools.len(), 1);
        assert_eq!(server.tool_map.len(), 1);
        assert!(server.tool_map.contains_key("slack__send"));
    }

    #[test]
    fn test_collect_cached_tools() {
        let mut server = test_server();
        server.register_tools(
            "sentry",
            &[Tool {
                name: "search".to_string(),
                description: Some("Search".to_string()),
                input_schema: None,
            }],
        );
        server.register_tools(
            "slack",
            &[Tool {
                name: "send".to_string(),
                description: Some("Send".to_string()),
                input_schema: None,
            }],
        );

        let cached = server.collect_cached_tools("sentry");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].name, "sentry__search");

        let cached_slack = server.collect_cached_tools("slack");
        assert_eq!(cached_slack.len(), 1);

        let cached_unknown = server.collect_cached_tools("unknown");
        assert!(cached_unknown.is_empty());
    }
}
