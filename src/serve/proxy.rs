use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::cache::{BackendToolCache, ToolCacheStore};
use crate::classifier::{classify, Kind, ToolClassification};
use crate::classifier_cache::{cache_key, ClassifierCache};
use crate::client::McpClient;
use crate::config::{parse_duration_str, IdleTimeoutPolicy, ServerConfig};
use crate::protocol::{JsonRpcResponse, Prompt, Resource, Tool, PROTOCOL_VERSION};
use crate::server_auth::{self, AclConfig, AuthIdentity};

pub(crate) const SEPARATOR: &str = "__";

/// Tracks per-backend usage patterns for adaptive idle timeout.
#[derive(Debug, Clone)]
pub(crate) struct UsageStats {
    pub(crate) request_count: u64,
    pub(crate) first_used: Instant,
    pub(crate) last_used: Instant,
    /// Exponential moving average of intervals between requests (ms).
    pub(crate) ema_interval_ms: f64,
}

impl UsageStats {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            request_count: 0,
            first_used: now,
            last_used: now,
            ema_interval_ms: 0.0,
        }
    }

    pub(crate) fn record_request(&mut self) {
        let now = Instant::now();
        if self.request_count > 0 {
            let interval = now.duration_since(self.last_used).as_millis() as f64;
            // EMA with α=0.3: recent intervals weigh more
            self.ema_interval_ms = 0.3 * interval + 0.7 * self.ema_interval_ms;
        }
        self.last_used = now;
        self.request_count += 1;
    }

    pub(crate) fn idle_duration(&self) -> Duration {
        self.last_used.elapsed()
    }

    pub(crate) fn compute_adaptive_timeout(&self, min: Duration, max: Duration) -> Duration {
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

pub(crate) enum BackendState {
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
pub(crate) struct DiscoveryFailure {
    pub(crate) attempts: u32,
    pub(crate) last_attempt: Instant,
}

impl DiscoveryFailure {
    pub(crate) fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt: Instant::now(),
        }
    }

    pub(crate) fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt = Instant::now();
    }

    /// Returns true if enough time has passed to retry, using exponential backoff.
    /// Backoff after first failure: 30s, 60s, 120s, 240s (capped at 300s).
    /// Bumped from the previous 5/10/20/40 because a 30s discovery timeout
    /// for a flaky backend (e.g. slack auth) used to retry every few seconds
    /// and steal the discovery_lock from healthy backends repeatedly.
    pub(crate) fn should_retry(&self) -> bool {
        if self.attempts == 0 {
            return true;
        }
        let backoff_secs = (30u64 << (self.attempts - 1).min(3)).min(300);
        self.last_attempt.elapsed() >= Duration::from_secs(backoff_secs)
    }
}

pub(crate) type SharedProxy = Arc<Mutex<ProxyServer>>;

/// Result of resolving a `tools/call` request: server name, original tool
/// name, arguments, and (optionally) an already-connected client.
pub(crate) type ResolvedCall = (
    String,
    String,
    Value,
    Option<Arc<McpClient>>,
    server_auth::Decision,
);
/// Ok: (server, tool, args, decision). Err: (optional decision for audit, error response).
pub(crate) type ResolveResult = std::result::Result<
    (String, String, Value, server_auth::Decision),
    (Option<server_auth::Decision>, JsonRpcResponse),
>;
/// Resolved resource read: (server, original_uri, client, decision).
pub(crate) type ResolvedResourceRead = (
    String,
    String,
    Option<Arc<McpClient>>,
    server_auth::Decision,
);
/// Resolved prompt get: (server, original_name, arguments, client, decision).
pub(crate) type ResolvedPromptGet = (
    String,
    String,
    Option<Value>,
    Option<Arc<McpClient>>,
    server_auth::Decision,
);

pub(crate) struct ProxyServer {
    pub(crate) configs: HashMap<String, ServerConfig>,
    pub(crate) backends: HashMap<String, BackendState>,
    pub(crate) tool_map: HashMap<String, (String, String)>, // namespaced -> (server, original_name)
    pub(crate) tools: Vec<Tool>,
    pub(crate) resource_map: HashMap<String, (String, String)>, // namespaced_uri -> (server, original_uri)
    pub(crate) resources: Vec<Resource>,
    pub(crate) prompt_map: HashMap<String, (String, String)>, // namespaced_name -> (server, original_name)
    pub(crate) prompts: Vec<Prompt>,
    /// Per-tool read/write classification, keyed by namespaced tool name.
    /// Populated after each successful `tools/list` from an upstream and
    /// consumed by future ACL enforcement (issue #54 only produces it).
    pub(crate) classifications: HashMap<String, ToolClassification>,
    /// Persistent classifier cache. Loaded at startup, saved after each
    /// successful discovery batch. Overrides are never cached.
    pub(crate) classifier_cache: ClassifierCache,
    pub(crate) audit: Arc<AuditLogger>,
    /// Tracks which backends have been successfully discovered.
    pub(crate) discovered_backends: std::collections::HashSet<String>,
    /// Tracks backends that failed discovery for exponential backoff.
    pub(crate) discovery_failures: HashMap<String, DiscoveryFailure>,
    /// SHA-256 hashes of backend configs for cache invalidation.
    pub(crate) config_hashes: HashMap<String, String>,
    /// Persistent tool cache backed by shared ChronDB.
    pub(crate) cache_store: ToolCacheStore,
    /// Serializes concurrent discovery batches so two callers don't both
    /// spawn duplicate connect attempts for the same set of backends.
    /// This is intentionally **separate** from the proxy mutex — discovery
    /// I/O happens with the proxy mutex released, so request handlers
    /// targeting already-discovered backends are never blocked by it.
    pub(crate) discovery_lock: Arc<tokio::sync::Mutex<()>>,
    /// Per-backend connect locks. When a `tools/call` hits a disconnected
    /// backend, the first caller acquires the per-backend lock, performs
    /// the full connect (spawn + initialize + list_tools) with the proxy
    /// mutex released, and installs the client. Concurrent callers wait on
    /// the same per-backend lock instead of all spawning duplicate children.
    pub(crate) connect_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl ProxyServer {
    pub(crate) fn new(
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
            resource_map: HashMap::new(),
            resources: Vec::new(),
            prompt_map: HashMap::new(),
            prompts: Vec::new(),
            classifications: HashMap::new(),
            classifier_cache: ClassifierCache::load(),
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
    pub(crate) fn connect_lock_for(&mut self, server_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.connect_locks
                .entry(server_name.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    pub(crate) fn register_tools(&mut self, server_name: &str, tools: &[Tool]) {
        let overrides = self
            .configs
            .get(server_name)
            .and_then(|c| c.tool_acl())
            .filter(|o| !o.read.is_empty() || !o.write.is_empty())
            .cloned();
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
            // Classify against raw tool (with annotations + original description).
            // Consult the persistent cache first — overrides are NEVER cached,
            // so re-classify when an override is defined for this server.
            let classification = if overrides.is_none() {
                let key = cache_key(
                    server_name,
                    &tool.name,
                    tool.description.as_deref(),
                    tool.annotations.as_ref(),
                );
                if let Some(cached) = self.classifier_cache.get(&key).cloned() {
                    cached
                } else {
                    let c = classify(tool, None);
                    self.classifier_cache.put(key, c.clone());
                    c
                }
            } else {
                classify(tool, overrides.as_ref())
            };
            if classification.kind == Kind::Ambiguous {
                eprintln!(
                    "[serve] {server_name}:{tool_name}: classification ambiguous → treated as write (reasons: {reasons})",
                    tool_name = tool.name,
                    reasons = classification.reasons.join("; "),
                );
            }
            self.classifications
                .insert(namespaced.clone(), classification);
            self.tools.push(Tool {
                name: namespaced,
                description,
                input_schema: tool.input_schema.clone(),
                annotations: tool.annotations.clone(),
            });
        }
    }

    pub(crate) fn unregister_tools(&mut self, server_name: &str) {
        let prefix = format!("{server_name}{SEPARATOR}");
        self.tools.retain(|t| !t.name.starts_with(&prefix));
        self.tool_map.retain(|k, _| !k.starts_with(&prefix));
        self.classifications.retain(|k, _| !k.starts_with(&prefix));
    }

    pub(crate) fn register_resources(&mut self, server_name: &str, resources: &[Resource]) {
        for r in resources {
            let namespaced_uri = format!("{server_name}{SEPARATOR}{}", r.uri);
            let description = r
                .description
                .as_ref()
                .map(|d| format!("[{server_name}] {d}"));
            self.resource_map.insert(
                namespaced_uri.clone(),
                (server_name.to_string(), r.uri.clone()),
            );
            self.resources.push(Resource {
                uri: namespaced_uri,
                name: format!("{server_name}{SEPARATOR}{}", r.name),
                description,
                mime_type: r.mime_type.clone(),
                annotations: r.annotations.clone(),
            });
        }
    }

    pub(crate) fn unregister_resources(&mut self, server_name: &str) {
        let prefix = format!("{server_name}{SEPARATOR}");
        self.resources.retain(|r| !r.uri.starts_with(&prefix));
        self.resource_map.retain(|k, _| !k.starts_with(&prefix));
    }

    pub(crate) fn register_prompts(&mut self, server_name: &str, prompts: &[Prompt]) {
        for p in prompts {
            let namespaced_name = format!("{server_name}{SEPARATOR}{}", p.name);
            let description = p
                .description
                .as_ref()
                .map(|d| format!("[{server_name}] {d}"));
            self.prompt_map.insert(
                namespaced_name.clone(),
                (server_name.to_string(), p.name.clone()),
            );
            self.prompts.push(Prompt {
                name: namespaced_name,
                description,
                arguments: p.arguments.clone(),
            });
        }
    }

    pub(crate) fn unregister_prompts(&mut self, server_name: &str) {
        let prefix = format!("{server_name}{SEPARATOR}");
        self.prompts.retain(|p| !p.name.starts_with(&prefix));
        self.prompt_map.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Collect cached tools for a server from the current tool list (for storing in Disconnected state).
    pub(crate) fn collect_cached_tools(&self, server_name: &str) -> Vec<Tool> {
        let prefix = format!("{server_name}{SEPARATOR}");
        self.tools
            .iter()
            .filter(|t| t.name.starts_with(&prefix))
            .cloned()
            .collect()
    }

    /// Load tools from persistent cache. Only loads entries whose config hash matches.
    pub(crate) fn load_from_cache(&mut self) {
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
    pub(crate) fn snapshot_cache_entries(&self) -> Vec<(String, BackendToolCache)> {
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
                        annotations: t.annotations.clone(),
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
    pub(crate) fn has_undiscovered_backends(&self) -> bool {
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
    pub(crate) fn snapshot_pending_discovery(&self) -> Vec<(String, ServerConfig)> {
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
    pub(crate) fn try_get_client(&mut self, server_name: &str) -> Option<Arc<McpClient>> {
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
    pub(crate) fn install_client(
        &mut self,
        server_name: &str,
        client: Arc<McpClient>,
        tools: &[Tool],
        resources: &[Resource],
        prompts: &[Prompt],
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
        self.unregister_resources(server_name);
        self.register_resources(server_name, resources);
        self.unregister_prompts(server_name);
        self.register_prompts(server_name, prompts);
        eprintln!(
            "[serve] {server_name}: {} tool(s), {} resource(s), {} prompt(s) (reconnected)",
            tools.len(),
            resources.len(),
            prompts.len()
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
    pub(crate) fn collect_idle_backends(&mut self) -> Vec<(String, Arc<McpClient>)> {
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

    pub(crate) fn handle_initialize(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
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
    pub(crate) fn resolve_tool_call(
        &self,
        id: &Value,
        params: Option<Value>,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> ResolveResult {
        let params = match params {
            Some(p) => p,
            None => {
                return Err((
                    None,
                    JsonRpcResponse::error(id.clone(), -32602, "missing params for tools/call"),
                ));
            }
        };

        let tool_name = match params.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return Err((
                    None,
                    JsonRpcResponse::error(
                        id.clone(),
                        -32602,
                        "missing 'name' in tools/call params",
                    ),
                ));
            }
        };

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let (server_name, original_name) = match self.tool_map.get(&tool_name) {
            Some(mapping) => mapping.clone(),
            None => {
                return Err((
                    None,
                    JsonRpcResponse::error(
                        id.clone(),
                        -32602,
                        &format!("unknown tool: {tool_name}"),
                    ),
                ));
            }
        };

        let classification = self.classifications.get(&tool_name);
        let ctx = server_auth::ToolContext {
            server_alias: &server_name,
            tool_name: &original_name,
            classification,
        };

        let decision = server_auth::is_tool_allowed(identity, &tool_name, acl, Some(&ctx));
        if !decision.allowed {
            return Err((
                Some(decision),
                JsonRpcResponse::error(
                    id.clone(),
                    -32603,
                    &format!(
                        "access denied: '{}' cannot use tool '{tool_name}'",
                        identity.subject
                    ),
                ),
            ));
        }

        Ok((server_name, original_name, arguments, decision))
    }

    /// Drain all connected backends and return them so they can be shut down
    /// in parallel **outside** the proxy lock.
    pub(crate) fn drain_connected(&mut self) -> Vec<(String, Arc<McpClient>)> {
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
pub(crate) async fn shutdown_clients_in_parallel(clients: Vec<(String, Arc<McpClient>)>) {
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
            annotations: None,
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
                annotations: None,
            },
            Tool {
                name: "create".to_string(),
                description: None,
                input_schema: None,
                annotations: None,
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
                annotations: None,
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
                annotations: None,
            }],
        );
        server.register_tools(
            "slack",
            &[Tool {
                name: "send".to_string(),
                description: Some("Send".to_string()),
                input_schema: None,
                annotations: None,
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

    // --- Registration tests ---

    #[test]
    fn test_register_unregister_resources() {
        let mut server = test_server();
        server.register_resources(
            "sentry",
            &[
                Resource {
                    uri: "issue://1".to_string(),
                    name: "Issue 1".to_string(),
                    description: Some("First".to_string()),
                    mime_type: None,
                    annotations: None,
                },
                Resource {
                    uri: "issue://2".to_string(),
                    name: "Issue 2".to_string(),
                    description: None,
                    mime_type: None,
                    annotations: None,
                },
            ],
        );
        assert_eq!(server.resources.len(), 2);
        assert_eq!(server.resource_map.len(), 2);
        assert!(server.resource_map.contains_key("sentry__issue://1"));
        assert_eq!(server.resources[0].uri, "sentry__issue://1");
        assert_eq!(
            server.resources[0].description.as_deref(),
            Some("[sentry] First")
        );

        server.unregister_resources("sentry");
        assert!(server.resources.is_empty());
        assert!(server.resource_map.is_empty());
    }

    #[test]
    fn test_register_unregister_prompts() {
        let mut server = test_server();
        server.register_prompts(
            "ai",
            &[Prompt {
                name: "summarize".to_string(),
                description: Some("Summarize text".to_string()),
                arguments: None,
            }],
        );
        assert_eq!(server.prompts.len(), 1);
        assert_eq!(server.prompt_map.len(), 1);
        assert!(server.prompt_map.contains_key("ai__summarize"));
        assert_eq!(server.prompts[0].name, "ai__summarize");
        assert_eq!(
            server.prompts[0].description.as_deref(),
            Some("[ai] Summarize text")
        );

        server.unregister_prompts("ai");
        assert!(server.prompts.is_empty());
        assert!(server.prompt_map.is_empty());
    }

    #[test]
    fn test_initialize_includes_resources_and_prompts_capabilities() {
        let server = test_server();
        let resp = server.handle_initialize(Value::from(1));
        let result = resp.result.unwrap();
        assert!(result["capabilities"]["resources"].is_object());
        assert!(result["capabilities"]["prompts"].is_object());
    }
}
