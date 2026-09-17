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
use crate::protocol::{
    error_codes, JsonRpcResponse, Prompt, Resource, ServerDiscoverResult, ServerInfo, Tool,
    PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::server_auth::{self, AclConfig, AuthIdentity};

pub(crate) const SEPARATOR: &str = "__";

/// Extract the backend server name from a namespaced identifier (e.g.
/// `"gh__issue"` → `"gh"`).  Returns `None` when the name contains no
/// separator or the prefix does not match any configured backend — callers
/// should fall back to full discovery in that case.
pub(crate) fn infer_backend_name<'a>(
    name: &'a str,
    configs: &HashMap<String, ServerConfig>,
) -> Option<&'a str> {
    let (prefix, _) = name.split_once(SEPARATOR)?;
    if configs.contains_key(prefix) {
        Some(prefix)
    } else {
        None
    }
}

/// Capabilities this proxy advertises. Shared by `initialize` and
/// `server/discover` so the two answers can never drift apart.
pub(crate) fn proxy_capabilities() -> Value {
    json!({
        "tools": {},
        "resources": {},
        "prompts": {}
    })
}

pub(crate) fn proxy_server_info() -> ServerInfo {
    ServerInfo {
        name: "mcp-proxy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// `server/discover` (2026-07-28): the stateless replacement for the
/// `initialize` handshake. We advertise every revision we accept, newest
/// first, so a client can pick without a round-trip negotiation.
pub(crate) fn handle_server_discover(id: Value) -> JsonRpcResponse {
    let result = ServerDiscoverResult {
        supported_versions: SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .map(|v| v.to_string())
            .collect(),
        capabilities: proxy_capabilities(),
        instructions: None,
        // Identity belongs in `_meta`, not at the top level.
        meta: Some(serde_json::json!({
            crate::protocol::meta_keys::SERVER_INFO: proxy_server_info(),
        })),
    };
    JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
}

/// Fields a [MRTR][mrtr] retry carries so the backend can resume the
/// exchange it started. Both are opaque to the proxy: `requestState` is
/// explicitly "meaningful only to the server", and `inputResponses` is the
/// client's answers to that server's questions.
///
/// [mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
pub(crate) const MRTR_CONTINUATION_FIELDS: [&str; 2] = ["inputResponses", "requestState"];

/// Which MRTR continuation fields a client's params carry, for the audit
/// entry. A relayed continuation is still a privileged call, so it has to
/// stay attributable rather than looking like a fresh one.
pub(crate) fn mrtr_continuation_fields(params: Option<&Value>) -> Vec<&'static str> {
    let Some(params) = params else {
        return Vec::new();
    };
    MRTR_CONTINUATION_FIELDS
        .into_iter()
        .filter(|f| params.get(f).is_some())
        .collect()
}

/// Copy the MRTR continuation fields, when present, into params bound for a
/// backend.
fn copy_mrtr_continuation(params: Option<&Value>, out: &mut serde_json::Map<String, Value>) {
    let Some(params) = params else { return };
    for field in MRTR_CONTINUATION_FIELDS {
        if let Some(value) = params.get(field) {
            out.insert(field.to_string(), value.clone());
        }
    }
}

/// Rebuild `tools/call` params for the backend: the namespaced tool name
/// swapped for the backend's own, plus exactly the fields the spec defines
/// for this method.
///
/// Forwarding `inputResponses`/`requestState` is what makes [MRTR][mrtr]
/// work through the proxy — a retry carries them alongside `arguments`, and
/// rebuilding from `{name, arguments}` alone would drop them silently.
///
/// The list is an allowlist rather than "everything except `_meta`" so a
/// client cannot smuggle an arbitrary top-level key into a backend request
/// through us: the proxy is the peer on that hop, and a backend must only
/// ever see fields this hop actually means.
///
/// `_meta` is excluded for the same reason it always was: it is per-hop
/// state (our client's protocol version, its client info). Backends never
/// received it before, and a legacy backend must not suddenly start seeing
/// 2026-07-28 keys it cannot interpret.
///
/// [mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
pub(crate) fn backend_tool_call_params(params: &Value, original_name: &str) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("name".to_string(), Value::String(original_name.to_string()));
    // Backends have always been handed an `arguments` object, even when the
    // client omitted one. Keep that so this stays a no-op for legacy peers.
    out.insert(
        "arguments".to_string(),
        params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
    );
    copy_mrtr_continuation(Some(params), &mut out);
    Value::Object(out)
}

/// `resources/read` params for the backend: the un-namespaced URI plus any
/// MRTR continuation. `resources/read` may return an `InputRequiredResult`
/// too, so a retry's answers have to reach the backend the same way a
/// `tools/call` retry's do.
pub(crate) fn backend_resource_read_params(params: Option<&Value>, original_uri: &str) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("uri".to_string(), Value::String(original_uri.to_string()));
    copy_mrtr_continuation(params, &mut out);
    Value::Object(out)
}

/// `prompts/get` params for the backend. `arguments` is omitted when the
/// client omitted it — that is the shape every backend has always seen.
pub(crate) fn backend_prompt_get_params(params: Option<&Value>, original_name: &str) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("name".to_string(), Value::String(original_name.to_string()));
    if let Some(arguments) = params.and_then(|p| p.get("arguments")) {
        out.insert("arguments".to_string(), arguments.clone());
    }
    copy_mrtr_continuation(params, &mut out);
    Value::Object(out)
}

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
/// name, the params to forward to the backend, and (optionally) an
/// already-connected client.
pub(crate) type ResolvedCall = (
    String,
    String,
    Value,
    Option<Arc<McpClient>>,
    server_auth::Decision,
);
/// Ok: (server, tool, backend params, decision). Err: (optional decision for
/// audit, error response).
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
/// Resolved prompt get: (server, original_name, backend params, client,
/// decision). The third element is the whole params object rewritten for the
/// backend (see [`backend_prompt_get_params`]), not just `arguments`, so an
/// MRTR retry's continuation fields travel with it.
pub(crate) type ResolvedPromptGet = (
    String,
    String,
    Value,
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

    /// Register a backend's tools, **replacing** whatever was registered for it
    /// before. `self.tools` is a Vec: appending meant every re-discovery
    /// (background refresh, reconnect) added another copy of the whole list,
    /// which `snapshot_cache_entries` then persisted — so the duplication
    /// survived restarts and grew on each one (issue #106).
    ///
    /// Skipping names already in `tool_map` — emptied for this server one line
    /// above — drops repeats *within* `tools` too, which is what heals a cache
    /// already poisoned by the old behavior.
    pub(crate) fn register_tools(&mut self, server_name: &str, tools: &[Tool]) {
        self.unregister_tools(server_name);
        let overrides = self
            .configs
            .get(server_name)
            .and_then(|c| c.tool_acl())
            .filter(|o| !o.read.is_empty() || !o.write.is_empty())
            .cloned();
        for tool in tools {
            let namespaced = format!("{server_name}{SEPARATOR}{}", tool.name);
            if self.tool_map.contains_key(&namespaced) {
                continue;
            }
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
                    if let Some(m) = crate::telemetry::metrics() {
                        m.classifier_hits.add(
                            1,
                            &[opentelemetry::KeyValue::new(
                                "mcp.server",
                                server_name.to_string(),
                            )],
                        );
                    }
                    cached
                } else {
                    if let Some(m) = crate::telemetry::metrics() {
                        m.classifier_misses.add(
                            1,
                            &[opentelemetry::KeyValue::new(
                                "mcp.server",
                                server_name.to_string(),
                            )],
                        );
                    }
                    let c = classify(tool, None);
                    self.classifier_cache.put(key, c.clone());
                    c
                }
            } else {
                classify(tool, overrides.as_ref())
            };
            if classification.kind == Kind::Ambiguous {
                tracing::warn!(
                    server = %server_name,
                    tool = %tool.name,
                    reasons = %classification.reasons.join("; "),
                    "classification ambiguous — treated as write",
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

    /// Same replace-don't-append contract as [`Self::register_tools`].
    pub(crate) fn register_resources(&mut self, server_name: &str, resources: &[Resource]) {
        self.unregister_resources(server_name);
        for r in resources {
            let namespaced_uri = format!("{server_name}{SEPARATOR}{}", r.uri);
            if self.resource_map.contains_key(&namespaced_uri) {
                continue;
            }
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

    /// Same replace-don't-append contract as [`Self::register_tools`].
    pub(crate) fn register_prompts(&mut self, server_name: &str, prompts: &[Prompt]) {
        self.unregister_prompts(server_name);
        for p in prompts {
            let namespaced_name = format!("{server_name}{SEPARATOR}{}", p.name);
            if self.prompt_map.contains_key(&namespaced_name) {
                continue;
            }
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
            tracing::info!(server = %name, tool_count, "tools loaded from cache");
        }
    }

    /// Mark cache-loaded backends as pending discovery again so a background
    /// refresh re-reads their tool list from the live backend.
    ///
    /// Only backends that are *not* connected in this process are reset:
    /// clearing the whole `discovered_backends` set would also re-discover
    /// healthy live backends, replacing a working client with a fresh child
    /// for no reason.
    pub(crate) fn reset_cache_loaded_for_refresh(&mut self) {
        let backends = &self.backends;
        self.discovered_backends
            .retain(|name| !matches!(backends.get(name), Some(BackendState::Disconnected { .. })));
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

    /// Returns true if a **specific** backend needs discovery: it exists in
    /// configs, has not been discovered yet, and is eligible for retry
    /// (respects backoff).  Used by `tools/call` / `resources/read` /
    /// `prompts/get` to trigger per-server lazy discovery instead of
    /// discovering every pending backend.
    pub(crate) fn is_backend_undiscovered(&self, name: &str) -> bool {
        if !self.configs.contains_key(name) {
            return false;
        }
        if self.discovered_backends.contains(name) {
            return false;
        }
        match self.discovery_failures.get(name) {
            Some(failure) => failure.should_retry(),
            None => true,
        }
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

        self.register_tools(server_name, tools);
        self.register_resources(server_name, resources);
        self.register_prompts(server_name, prompts);
        tracing::info!(
            server = %server_name,
            tools = tools.len(),
            resources = resources.len(),
            prompts = prompts.len(),
            "reconnected",
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
                tracing::info!(
                    server = %name,
                    idle = ?usage_stats.idle_duration(),
                    request_count = usage_stats.request_count,
                    "shutting down idle backend",
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

    /// Answer `initialize`, echoing back a revision the **client** can
    /// speak rather than blindly the newest one we know.
    ///
    /// A 2025-06-18 client that gets told "2026-07-28" has to either
    /// disconnect or guess; echoing its own revision back is what keeps
    /// every pre-2026-07-28 client working untouched. `None` (no params,
    /// or params without `protocolVersion`) and an unknown revision both
    /// fall back to our newest, which is the pre-existing behavior.
    pub(crate) fn handle_initialize(
        &self,
        id: Value,
        requested_version: Option<&str>,
    ) -> JsonRpcResponse {
        let negotiated = match requested_version {
            Some(v) if crate::protocol::is_version_supported(v) => v,
            _ => PROTOCOL_VERSION,
        };
        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": negotiated,
                "capabilities": proxy_capabilities(),
                "serverInfo": proxy_server_info(),
            }),
        )
    }

    /// Headers carrying the caller's identity for one backend call, or empty
    /// when the server did not opt in via `forward_identity`.
    ///
    /// Empty is the default and the safe answer: a backend that never asked for
    /// identity must not start receiving one, and a backend that DID ask is
    /// trusting the header — see `config::ForwardIdentity` for the condition
    /// that makes that safe.
    ///
    /// Values are checked here, not at load time, because the subject is
    /// runtime data (it comes from a bearer token or an upstream SSO header).
    /// A subject with CR/LF in it would be header injection into the backend
    /// request, so such a call is refused rather than sent without identity —
    /// sending it anyway would land the write under the shared credential,
    /// which is exactly the silent-wrong-owner outcome this feature removes.
    ///
    /// Every refusal below is a refusal to *guess*. The backend trusts this
    /// header, so anything that leaves the subject ambiguous — unauthenticated,
    /// injectable, or duplicated by a second header of the same name — has to
    /// stop the call rather than resolve itself into a plausible answer.
    pub(crate) fn identity_headers(
        &self,
        server: &str,
        identity: &AuthIdentity,
    ) -> std::result::Result<Vec<(String, String)>, String> {
        let Some(entry) = self.configs.get(server) else {
            return Ok(Vec::new());
        };
        let Some(cfg) = entry.forward_identity() else {
            return Ok(Vec::new());
        };

        // Nothing authenticated this caller, so there is no identity to
        // assert. `NoAuth` is the default for stdio and for a config with no
        // `serverAuth` block, so this is reachable by omission rather than by
        // mistake — and forwarding the placeholder would have the backend
        // record `anonymous` as the author, in good faith.
        if identity.is_anonymous() {
            return Err(
                "the caller is not authenticated, so there is no identity to forward; \
                 configure serverAuth.providers, or drop forward_identity from this server"
                    .to_string(),
            );
        }

        let static_headers = entry.static_headers();
        let subject_name = valid_header_name(&cfg.header)?;
        reject_transport_owned(&subject_name, "header")?;
        reject_static_collision(static_headers, &subject_name, "header")?;

        let mut out = Vec::with_capacity(2);
        out.push((
            subject_name.clone(),
            valid_header_value(&identity.subject, "subject")?,
        ));
        if let Some(roles_header) = &cfg.roles_header {
            let roles_name = valid_header_name(roles_header)?;
            reject_transport_owned(&roles_name, "roles_header")?;
            reject_static_collision(static_headers, &roles_name, "roles_header")?;
            // The same name for both sends two same-named headers with
            // unrelated values, and the receiver is the one that resolves a
            // duplicate — it could take the roles value as the subject. Refused
            // for the same reason as a control character: the alternative is
            // recording the wrong owner, silently.
            //
            // Checked here rather than at load time because the existing config
            // validation (`validate_server_names`) only warns at boot, and a
            // warning would let the ambiguous call go out anyway.
            if roles_name.eq_ignore_ascii_case(&subject_name) {
                return Err(format!(
                    "forward_identity: header and roles_header have the same name \
                     ({subject_name}) — use distinct names or drop roles_header"
                ));
            }
            out.push((
                roles_name,
                valid_header_value(&identity.roles.join(","), "roles")?,
            ));
        }
        Ok(out)
    }

    /// Resolve a tool name to (server, original_name, backend params, ACL
    /// decision). The third element is the **whole** params object rewritten
    /// for the backend (see [`backend_tool_call_params`]), not just
    /// `arguments`. Returns Err(JsonRpcResponse) if the call should be
    /// rejected immediately.
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
                    JsonRpcResponse::error(
                        id.clone(),
                        error_codes::INVALID_PARAMS,
                        "missing params for tools/call",
                    ),
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
                        error_codes::INVALID_PARAMS,
                        "missing 'name' in tools/call params",
                    ),
                ));
            }
        };

        let (server_name, original_name) = match self.tool_map.get(&tool_name) {
            Some(mapping) => mapping.clone(),
            None => {
                return Err((
                    None,
                    JsonRpcResponse::error(
                        id.clone(),
                        error_codes::INVALID_PARAMS,
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
                    error_codes::INTERNAL_ERROR,
                    &format!(
                        "access denied: '{}' cannot use tool '{tool_name}'",
                        identity.subject
                    ),
                ),
            ));
        }

        let backend_params = backend_tool_call_params(&params, &original_name);
        Ok((server_name, original_name, backend_params, decision))
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
            tracing::info!(server = %name, "finalizing shutdown");
            if tokio::time::timeout(Duration::from_secs(5), client.shutdown())
                .await
                .is_err()
            {
                tracing::warn!(server = %name, "shutdown timed out — force-killed via drop");
            }
            // Dropping the last Arc<McpClient> drops the transport, which
            // kills the child via kill_on_drop(true).
            drop(client);
        });
    }
    while let Some(_res) = joinset.join_next().await {}
}

/// RFC 9110 field-name token check, same rule the `x-mcp-header` annotation
/// path uses. Rejects CR, LF and every other control character by construction.
fn valid_header_name(name: &str) -> std::result::Result<String, String> {
    if name.is_empty() {
        return Err("forward_identity header name must not be empty".to_string());
    }
    if !name.bytes().all(crate::client::is_tchar) {
        return Err(format!(
            "forward_identity header name {name:?} is not an RFC 9110 field-name token"
        ));
    }
    Ok(name.to_string())
}

/// Refuse when a forwarded header shares its name with one of the server's
/// static `headers`.
///
/// Both would be sent: the HTTP transport appends every header it is given
/// (`reqwest`'s builder calls `HeaderMap::append`, not `insert`), so the two
/// travel as two lines of the same field and the backend picks the winner —
/// Go's `Header.Get` takes the first, several proxies and frameworks take the
/// last. That is the receiver deciding who the caller is, which is precisely
/// the decision this feature exists to take away from it.
///
/// This is the reachable twin of the `roles_header == header` collision, and
/// it arrives the same way: an operator moving a backend off a hardcoded
/// subject header onto `forward_identity` and leaving the old entry behind.
fn reject_static_collision(
    headers: Option<&HashMap<String, String>>,
    name: &str,
    field: &str,
) -> std::result::Result<(), String> {
    let collides = headers.is_some_and(|h| h.keys().any(|k| k.eq_ignore_ascii_case(name)));
    if !collides {
        return Ok(());
    }
    Err(format!(
        "forward_identity: {field} {name:?} is also set in this server's static `headers`; \
         both would be sent and the backend would choose between them — remove it from \
         `headers` or give {field} a different name"
    ))
}

/// Field values are laxer than names (spaces and most printable bytes are
/// legal), so the check is narrower: no control characters, which is what an
/// injected header line would need.
fn valid_header_value(value: &str, what: &str) -> std::result::Result<String, String> {
    // An empty value is a header that asserts nothing. Many backends read it
    // as no identity at all, which puts the write back under the shared
    // credential without anyone noticing, so it is refused like the rest.
    // Reachable through a bearer token configured with an empty subject.
    if value.is_empty() {
        return Err(format!("caller {what} is empty"));
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("caller {what} contains a control character"));
    }
    Ok(value.to_string())
}

/// Header names the HTTP transport writes on its own, which `forward_identity`
/// may not claim.
///
/// The static `headers` check cannot see these. `Authorization` is the one that
/// bites: the transport re-adds a saved OAuth token whenever the config map has
/// no usable `Authorization`, and the 401 retry path *removes* the config entry
/// before doing so. A forwarded header of that name would then travel beside a
/// bearer token the collision check never saw.
///
/// The rest are the routing and session fields. A forwarded value there does
/// not leak a credential, it corrupts routing, and `-32020` from the far side
/// is a worse way to learn about it than a refusal here.
const TRANSPORT_OWNED_HEADERS: &[&str] = &[
    "authorization",
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-method",
    "mcp-name",
    "mcp-protocol-version",
    "traceparent",
    "tracestate",
];

fn reject_transport_owned(name: &str, field: &str) -> std::result::Result<(), String> {
    let lower = name.to_ascii_lowercase();
    if !TRANSPORT_OWNED_HEADERS.contains(&lower.as_str()) {
        return Ok(());
    }
    Err(format!(
        "forward_identity: {field} {name:?} is a header the HTTP transport sets itself; \
         the caller's identity would travel beside the transport's own value and the \
         backend would choose between them"
    ))
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
        let resp = server.handle_initialize(Value::from(1), None);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "mcp-proxy");
    }

    #[test]
    fn test_proxy_server_initialize_with_string_id() {
        let server = test_server();
        let resp = server.handle_initialize(Value::String("req-1".to_string()), None);
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

    // --- Idempotent registration (issue #106) ---

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(format!("does {name}")),
            input_schema: None,
            annotations: None,
        }
    }

    /// A background refresh or a reconnect re-registers a backend that is
    /// already registered. Appending there is what multiplied one backend's
    /// tool list by the number of refreshes.
    #[test]
    fn re_registering_a_backend_replaces_its_previous_entries() {
        let mut server = test_server();
        let tools = vec![tool("search"), tool("create")];

        for _ in 0..5 {
            server.register_tools("ai-memory", &tools);
        }

        assert_eq!(server.tools.len(), 2);
        assert_eq!(server.tool_map.len(), 2);
        assert_eq!(server.classifications.len(), 2);
    }

    /// A backend that dropped a tool between two discoveries must lose it from
    /// the registry — replacing, not merging, is what makes that work.
    #[test]
    fn re_registering_drops_tools_the_backend_no_longer_exposes() {
        let mut server = test_server();
        server.register_tools("ai-memory", &[tool("search"), tool("create")]);
        server.register_tools("ai-memory", &[tool("search")]);

        assert_eq!(server.tools.len(), 1);
        assert_eq!(server.tools[0].name, "ai-memory__search");
        assert!(!server.tool_map.contains_key("ai-memory__create"));
    }

    /// The duplicates reached the on-disk tool cache, so a fixed build still
    /// loads a poisoned list at startup. Collapsing same-name repeats is what
    /// heals it without asking anyone to wipe the cache.
    #[test]
    fn a_poisoned_cached_list_collapses_to_one_copy() {
        let mut server = test_server();
        let poisoned: Vec<Tool> = (0..28)
            .flat_map(|_| [tool("search"), tool("create")])
            .collect();

        server.register_tools("ai-memory", &poisoned);

        assert_eq!(server.tools.len(), 2);
    }

    /// ...and the healed list is what gets written back, so the next start is
    /// clean too.
    #[test]
    fn the_persisted_cache_snapshot_carries_no_duplicates() {
        let mut server = test_server_with_configs(&["ai-memory"]);
        server
            .config_hashes
            .insert("ai-memory".to_string(), "hash".to_string());
        server.discovered_backends.insert("ai-memory".to_string());

        server.register_tools("ai-memory", &[tool("search"), tool("search")]);
        server.register_tools("ai-memory", &[tool("search"), tool("search")]);

        let entries = server.snapshot_cache_entries();
        let (_, entry) = entries
            .iter()
            .find(|(n, _)| n == "ai-memory")
            .expect("ai-memory snapshot");
        assert_eq!(entry.tools.len(), 1);
        assert_eq!(entry.tools[0].name, "search");
    }

    /// The refresh only re-discovers what came off the cache. Clearing the
    /// whole discovered set also re-discovered live backends, replacing a
    /// working client with a fresh child for nothing.
    #[test]
    fn refresh_resets_only_backends_that_were_not_connected() {
        let mut server = test_server_with_configs(&["ai-memory", "outl"]);
        server.discovered_backends.insert("ai-memory".to_string());
        server.discovered_backends.insert("outl".to_string());
        server.backends.insert(
            "ai-memory".to_string(),
            BackendState::Disconnected {
                cached_tools: vec![],
                usage_stats: UsageStats::new(),
            },
        );
        // `outl` has no `backends` entry — it was never loaded from cache.

        server.reset_cache_loaded_for_refresh();

        assert!(!server.discovered_backends.contains("ai-memory"));
        assert!(server.discovered_backends.contains("outl"));
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
        let resp = server.handle_initialize(Value::from(1), None);
        let result = resp.result.unwrap();
        assert!(result["capabilities"]["resources"].is_object());
        assert!(result["capabilities"]["prompts"].is_object());
    }

    // --- infer_backend_name tests ---

    fn make_configs(names: &[&str]) -> HashMap<String, ServerConfig> {
        names
            .iter()
            .map(|n| {
                (
                    n.to_string(),
                    ServerConfig::Stdio {
                        command: "echo".to_string(),
                        args: vec![],
                        env: HashMap::new(),
                        tool_acl: None,
                        idle_timeout: crate::config::IdleTimeoutPolicy::default(),
                        min_idle_timeout: None,
                        max_idle_timeout: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn test_infer_backend_name_valid() {
        let configs = make_configs(&["gh", "sentry", "slack"]);
        assert_eq!(infer_backend_name("gh__issue", &configs), Some("gh"));
        assert_eq!(
            infer_backend_name("sentry__search_issues", &configs),
            Some("sentry")
        );
    }

    #[test]
    fn test_infer_backend_name_no_separator() {
        let configs = make_configs(&["gh"]);
        assert_eq!(infer_backend_name("my_tool", &configs), None);
        assert_eq!(infer_backend_name("notool", &configs), None);
    }

    #[test]
    fn test_infer_backend_name_unknown_prefix() {
        let configs = make_configs(&["gh"]);
        assert_eq!(infer_backend_name("fake__tool", &configs), None);
    }

    #[test]
    fn test_infer_backend_name_multi_separator() {
        let configs = make_configs(&["a"]);
        // split_once gives ("a", "b__c") — prefix "a" is in configs
        assert_eq!(infer_backend_name("a__b__c", &configs), Some("a"));
    }

    // --- forwardIdentity tests ---

    fn http_server(forward: Option<crate::config::ForwardIdentity>) -> ProxyServer {
        http_server_with_headers(forward, HashMap::new())
    }

    fn http_server_with_headers(
        forward: Option<crate::config::ForwardIdentity>,
        headers: HashMap<String, String>,
    ) -> ProxyServer {
        let pool = Arc::new(crate::db::DbPool::disabled());
        let mut configs = HashMap::new();
        configs.insert(
            "hub".to_string(),
            ServerConfig::Http {
                url: "http://hub.internal/mcp".to_string(),
                headers,
                forward_identity: forward,
                tool_acl: None,
                idle_timeout: crate::config::IdleTimeoutPolicy::default(),
                min_idle_timeout: None,
                max_idle_timeout: None,
            },
        );
        ProxyServer::new(
            Arc::new(AuditLogger::Disabled),
            configs,
            HashMap::new(),
            ToolCacheStore::new(pool),
        )
    }

    fn forward(header: &str, roles_header: Option<&str>) -> crate::config::ForwardIdentity {
        crate::config::ForwardIdentity {
            header: header.to_string(),
            roles_header: roles_header.map(str::to_string),
        }
    }

    fn identity(subject: &str, roles: &[&str]) -> AuthIdentity {
        AuthIdentity::new(subject, roles.iter().map(|r| r.to_string()).collect())
    }

    #[test]
    fn no_forward_identity_config_sends_nothing() {
        // The default has to be "no header": a backend that never asked for
        // identity must not start receiving one on upgrade.
        let p = http_server(None);
        let out = p
            .identity_headers("hub", &identity("ana", &["business"]))
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn stdio_backend_never_forwards() {
        // HTTP-only by construction: there is no per-request channel into a
        // long-lived stdin pipe.
        let p = test_server_with_configs(&["local"]);
        let out = p.identity_headers("local", &identity("ana", &[])).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn unknown_server_sends_nothing() {
        let p = http_server(Some(forward("X-MCP-Subject", None)));
        let out = p
            .identity_headers("nao-existe", &identity("ana", &[]))
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn subject_travels_under_the_configured_header() {
        let p = http_server(Some(forward("X-MCP-Subject", None)));
        let out = p
            .identity_headers("hub", &identity("ana", &["business"]))
            .unwrap();
        assert_eq!(out, vec![("X-MCP-Subject".to_string(), "ana".to_string())]);
    }

    #[test]
    fn roles_header_is_opt_in_and_comma_separated() {
        let p = http_server(Some(forward("X-Who", Some("X-Roles"))));
        let out = p
            .identity_headers("hub", &identity("ana", &["business", "dev"]))
            .unwrap();
        assert_eq!(
            out,
            vec![
                ("X-Who".to_string(), "ana".to_string()),
                ("X-Roles".to_string(), "business,dev".to_string()),
            ]
        );
    }

    #[test]
    fn roles_header_equal_to_the_subject_header_is_refused() {
        // Two same-named headers with unrelated values: the receiver resolves
        // the duplicate, and it could take the roles value as the subject.
        // Refused rather than sent ambiguous.
        let p = http_server(Some(forward("X-Who", Some("X-Who"))));
        let err = p
            .identity_headers("hub", &identity("ana", &["business"]))
            .unwrap_err();
        assert!(
            err.contains("same name"),
            "the error must name the problem, got: {err}"
        );
    }

    #[test]
    fn roles_header_equal_ignoring_case_is_also_refused() {
        // Header names are case-insensitive, so "x-who" collides with "X-Who".
        let p = http_server(Some(forward("X-Who", Some("x-who"))));
        assert!(p
            .identity_headers("hub", &identity("ana", &["business"]))
            .is_err());
    }

    #[test]
    fn crlf_in_subject_is_refused_not_forwarded() {
        // Header injection into the backend request. The call is refused rather
        // than sent without identity: falling back to the shared credential
        // would record the write under the wrong owner, silently.
        let p = http_server(Some(forward("X-MCP-Subject", None)));
        let err = p
            .identity_headers("hub", &identity("ana\r\nX-Admin: 1", &[]))
            .unwrap_err();
        assert!(err.contains("control character"), "{err}");
    }

    #[test]
    fn control_character_in_roles_is_refused() {
        let p = http_server(Some(forward("X-Who", Some("X-Roles"))));
        let err = p
            .identity_headers("hub", &identity("ana", &["biz\nX-Admin: 1"]))
            .unwrap_err();
        assert!(err.contains("control character"), "{err}");
    }

    #[test]
    fn bad_header_name_is_refused() {
        for name in ["", "X Subject", "X:Subject", "X\r\nY"] {
            let p = http_server(Some(forward(name, None)));
            assert!(
                p.identity_headers("hub", &identity("ana", &[])).is_err(),
                "header name {name:?} deveria ser recusado"
            );
        }
    }

    #[test]
    fn an_unauthenticated_caller_is_refused_not_forwarded_as_anonymous() {
        // `NoAuth` is the default for stdio and for a config with no
        // `serverAuth` block, so this arrives by omission. Forwarding the
        // placeholder would have the backend record `anonymous` as the
        // author and believe it — the same silent-wrong-owner outcome the
        // feature exists to remove, wearing a different name.
        let p = http_server(Some(forward("X-MCP-Subject", None)));
        let err = p
            .identity_headers("hub", &AuthIdentity::anonymous())
            .unwrap_err();
        assert!(err.contains("not authenticated"), "{err}");
    }

    #[test]
    fn an_unauthenticated_caller_is_fine_when_the_server_did_not_opt_in() {
        // The refusal is scoped to servers that asked for identity. Every
        // other backend keeps working unauthenticated exactly as before.
        let p = http_server(None);
        let out = p
            .identity_headers("hub", &AuthIdentity::anonymous())
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn a_static_header_of_the_same_name_is_refused() {
        // The transport appends rather than replaces, so both would go out as
        // two lines of the same field and the backend would pick a winner.
        // This is the reachable twin of `roles_header == header`: an operator
        // moving off a hardcoded subject header and leaving the old entry.
        let mut headers = HashMap::new();
        headers.insert("X-MCP-Subject".to_string(), "svc-account".to_string());
        let p = http_server_with_headers(Some(forward("X-MCP-Subject", None)), headers);
        let err = p
            .identity_headers("hub", &identity("ana", &["business"]))
            .unwrap_err();
        assert!(err.contains("static `headers`"), "{err}");
    }

    #[test]
    fn a_static_header_colliding_on_case_is_also_refused() {
        // Field names are case-insensitive on the wire, so `x-mcp-subject`
        // and `X-MCP-Subject` are one header, not two.
        let mut headers = HashMap::new();
        headers.insert("x-mcp-subject".to_string(), "svc-account".to_string());
        let p = http_server_with_headers(Some(forward("X-MCP-Subject", None)), headers);
        assert!(p.identity_headers("hub", &identity("ana", &[])).is_err());
    }

    #[test]
    fn a_static_header_colliding_with_the_roles_header_is_refused() {
        let mut headers = HashMap::new();
        headers.insert("X-Roles".to_string(), "admin".to_string());
        let p = http_server_with_headers(Some(forward("X-Who", Some("X-Roles"))), headers);
        let err = p
            .identity_headers("hub", &identity("ana", &["business"]))
            .unwrap_err();
        assert!(err.contains("roles_header"), "{err}");
    }

    #[test]
    fn unrelated_static_headers_do_not_block_forwarding() {
        // Only a name collision matters. The shared credential travels on
        // every one of these calls and must keep doing so.
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer svc".to_string());
        let p = http_server_with_headers(Some(forward("X-MCP-Subject", None)), headers);
        let out = p.identity_headers("hub", &identity("ana", &[])).unwrap();
        assert_eq!(out, vec![("X-MCP-Subject".to_string(), "ana".to_string())]);
    }

    #[test]
    fn a_transport_owned_header_name_is_refused() {
        // `Authorization` is the one that bites. The transport re-adds a saved
        // OAuth token whenever the config map has no usable one, and the 401
        // retry path removes the config entry first, so the static-headers
        // check would find nothing to collide with and the identity would go
        // out beside a bearer token anyway.
        for name in [
            "Authorization",
            "authorization",
            "Mcp-Session-Id",
            "Mcp-Method",
            "Mcp-Name",
            "Mcp-Protocol-Version",
            "traceparent",
        ] {
            let p = http_server(Some(forward(name, None)));
            let err = p
                .identity_headers("hub", &identity("ana", &[]))
                .unwrap_err();
            assert!(
                err.contains("transport sets itself"),
                "header name {name:?} should be refused, got: {err}"
            );
        }
    }

    #[test]
    fn a_transport_owned_roles_header_is_refused_too() {
        let p = http_server(Some(forward("X-Who", Some("Authorization"))));
        let err = p
            .identity_headers("hub", &identity("ana", &["business"]))
            .unwrap_err();
        assert!(err.contains("roles_header"), "{err}");
    }

    #[test]
    fn an_empty_subject_is_refused() {
        // A bearer token can be configured with an empty subject. An empty
        // header asserts nothing, and a backend that reads it as "no identity"
        // silently falls back to the shared credential.
        let p = http_server(Some(forward("X-MCP-Subject", None)));
        let err = p.identity_headers("hub", &identity("", &[])).unwrap_err();
        assert!(err.contains("subject is empty"), "{err}");
    }

    #[test]
    fn an_authenticated_caller_named_anonymous_is_still_forwarded() {
        // `anonymous` is a legal subject for a bearer token, and such a caller
        // WAS authenticated. The unauthenticated check reads provenance, not
        // the subject string, so this one goes through.
        let p = http_server(Some(forward("X-MCP-Subject", None)));
        let out = p
            .identity_headers("hub", &identity(crate::server_auth::ANONYMOUS_SUBJECT, &[]))
            .unwrap();
        assert_eq!(
            out,
            vec![("X-MCP-Subject".to_string(), "anonymous".to_string())]
        );
    }

    #[test]
    fn a_refusal_names_the_config_key_that_exists() {
        // The operator has to be able to grep for what the message blames.
        // `forwardIdentity` is not a key in any config file.
        let p = http_server(Some(forward("X Subject", None)));
        let err = p
            .identity_headers("hub", &identity("ana", &[]))
            .unwrap_err();
        assert!(err.contains("forward_identity"), "{err}");
        assert!(!err.contains("forwardIdentity"), "{err}");
    }

    // --- is_backend_undiscovered tests ---

    fn test_server_with_configs(names: &[&str]) -> ProxyServer {
        let pool = Arc::new(crate::db::DbPool::disabled());
        let cache_store = ToolCacheStore::new(pool);
        ProxyServer::new(
            Arc::new(AuditLogger::Disabled),
            make_configs(names),
            HashMap::new(),
            cache_store,
        )
    }

    #[test]
    fn test_is_backend_undiscovered_never_seen() {
        let server = test_server_with_configs(&["gh"]);
        assert!(server.is_backend_undiscovered("gh"));
    }

    #[test]
    fn test_is_backend_undiscovered_already_discovered() {
        let mut server = test_server_with_configs(&["gh"]);
        server.discovered_backends.insert("gh".to_string());
        assert!(!server.is_backend_undiscovered("gh"));
    }

    #[test]
    fn test_is_backend_undiscovered_in_backoff() {
        let mut server = test_server_with_configs(&["gh"]);
        let mut failure = DiscoveryFailure::new();
        failure.record_failure();
        server.discovery_failures.insert("gh".to_string(), failure);
        // Just failed — backoff blocks retry
        assert!(!server.is_backend_undiscovered("gh"));
    }

    #[test]
    fn test_is_backend_undiscovered_not_in_configs() {
        let server = test_server_with_configs(&["gh"]);
        assert!(!server.is_backend_undiscovered("nonexistent"));
    }

    // --- initialize version negotiation ---

    #[test]
    fn test_initialize_echoes_a_revision_the_client_speaks() {
        let server = test_server();
        for requested in SUPPORTED_PROTOCOL_VERSIONS {
            let resp = server.handle_initialize(Value::from(1), Some(requested));
            assert_eq!(resp.result.unwrap()["protocolVersion"], *requested);
        }
    }

    #[test]
    fn test_initialize_without_a_request_answers_newest() {
        let server = test_server();
        // A client that sends no protocolVersion gets the pre-existing
        // answer — this is the shape every legacy handshake had.
        let resp = server.handle_initialize(Value::from(1), None);
        assert_eq!(resp.result.unwrap()["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn test_initialize_ignores_a_revision_we_cannot_speak() {
        let server = test_server();
        for bogus in ["1999-01-01", "", "not-a-date"] {
            let resp = server.handle_initialize(Value::from(1), Some(bogus));
            assert_eq!(resp.result.unwrap()["protocolVersion"], PROTOCOL_VERSION);
        }
    }

    // --- server/discover ---

    #[test]
    fn test_server_discover_shape() {
        let resp = handle_server_discover(Value::from(7));
        assert_eq!(resp.id, Some(Value::from(7)));
        let raw = resp.result.unwrap();
        // Pin the wire shape, not just the round trip through our own types.
        assert!(raw.get("supportedVersions").is_some());
        assert!(raw.get("protocolVersions").is_none());
        assert_eq!(
            raw["_meta"][crate::protocol::meta_keys::SERVER_INFO]["name"],
            "mcp-proxy"
        );

        let result: ServerDiscoverResult = serde_json::from_value(raw).unwrap();
        let info = result.server_info().expect("serverInfo in _meta");
        assert_eq!(info.name, "mcp-proxy");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        // A legacy-only client still finds common ground with us.
        let legacy_only = ServerDiscoverResult {
            supported_versions: vec![crate::protocol::PROTOCOL_VERSION_LEGACY.to_string()],
            ..result
        };
        assert_eq!(
            legacy_only.best_common_version(),
            Some(crate::protocol::PROTOCOL_VERSION_LEGACY)
        );
    }

    // --- backend_tool_call_params (MRTR passthrough) ---

    #[test]
    fn test_backend_params_preserve_mrtr_fields() {
        let params = json!({
            "name": "stub__ask",
            "arguments": {"q": 1},
            "inputResponses": [{"id": "confirm", "value": true}],
            "requestState": "opaque",
        });
        let out = backend_tool_call_params(&params, "ask");
        assert_eq!(out["name"], "ask");
        assert_eq!(out["arguments"]["q"], 1);
        assert_eq!(out["inputResponses"][0]["value"], true);
        assert_eq!(out["requestState"], "opaque");
    }

    /// Legacy shape must come out byte-for-byte as before: `{name, arguments}`
    /// with `arguments` defaulted to an empty object.
    #[test]
    fn test_backend_params_legacy_shape_is_unchanged() {
        assert_eq!(
            backend_tool_call_params(&json!({"name": "sentry__search"}), "search"),
            json!({"name": "search", "arguments": {}})
        );
        assert_eq!(
            backend_tool_call_params(&json!({"name": "s__t", "arguments": {"a": 1}}), "t"),
            json!({"name": "t", "arguments": {"a": 1}})
        );
    }

    /// `_meta` is our hop's state. Forwarding a 2026-07-28 protocolVersion to
    /// a 2025-11-25 backend is exactly the kind of leak that breaks it.
    #[test]
    fn test_backend_params_drop_client_meta() {
        let params = json!({
            "name": "s__t",
            "arguments": {},
            "_meta": {crate::protocol::meta_keys::PROTOCOL_VERSION: "2026-07-28"},
        });
        let out = backend_tool_call_params(&params, "t");
        assert!(out.get("_meta").is_none());
    }

    #[test]
    fn test_backend_params_tolerate_non_object_params() {
        let out = backend_tool_call_params(&json!([1, 2]), "t");
        assert_eq!(out, json!({"name": "t", "arguments": {}}));
    }

    /// Defense in depth: only the fields the spec defines for `tools/call`
    /// cross the hop. A client cannot use us as a courier for a top-level key
    /// a backend might act on.
    #[test]
    fn test_backend_params_forward_only_spec_fields() {
        let params = json!({
            "name": "s__t",
            "arguments": {"a": 1},
            "inputResponses": {"k": {}},
            "requestState": "opaque",
            // Not defined for tools/call — must stop at the proxy.
            "elicitation": {"bypass": true},
            "cursor": "sneaky",
            "_meta": {"anything": 1},
        });
        let out = backend_tool_call_params(&params, "t");
        let keys: Vec<&str> = out
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            keys,
            ["arguments", "inputResponses", "name", "requestState"]
        );
    }

    // --- resources/read + prompts/get backend params (MRTR) ---

    #[test]
    fn test_backend_resource_read_params_legacy_shape_is_unchanged() {
        assert_eq!(
            backend_resource_read_params(Some(&json!({"uri": "sentry__issue://1"})), "issue://1"),
            json!({"uri": "issue://1"})
        );
        assert_eq!(
            backend_resource_read_params(None, "issue://1"),
            json!({"uri": "issue://1"})
        );
    }

    #[test]
    fn test_backend_resource_read_params_carry_mrtr_continuation() {
        let out = backend_resource_read_params(
            Some(&json!({
                "uri": "sentry__issue://1",
                "inputResponses": {"login": {"action": "accept"}},
                "requestState": "opaque",
                "smuggled": true,
            })),
            "issue://1",
        );
        assert_eq!(out["uri"], "issue://1");
        assert_eq!(out["inputResponses"]["login"]["action"], "accept");
        assert_eq!(out["requestState"], "opaque");
        assert!(out.get("smuggled").is_none());
    }

    #[test]
    fn test_backend_prompt_get_params_legacy_shape_is_unchanged() {
        assert_eq!(
            backend_prompt_get_params(Some(&json!({"name": "ai__sum"})), "sum"),
            json!({"name": "sum"})
        );
        assert_eq!(
            backend_prompt_get_params(
                Some(&json!({"name": "ai__sum", "arguments": {"a": 1}})),
                "sum"
            ),
            json!({"name": "sum", "arguments": {"a": 1}})
        );
    }

    #[test]
    fn test_backend_prompt_get_params_carry_mrtr_continuation() {
        let out = backend_prompt_get_params(
            Some(&json!({
                "name": "ai__sum",
                "arguments": {"a": 1},
                "requestState": "opaque",
                "smuggled": true,
            })),
            "sum",
        );
        assert_eq!(
            out,
            json!({"name": "sum", "arguments": {"a": 1}, "requestState": "opaque"})
        );
    }

    #[test]
    fn test_mrtr_continuation_fields_reports_presence() {
        assert!(mrtr_continuation_fields(None).is_empty());
        assert!(mrtr_continuation_fields(Some(&json!({"name": "x"}))).is_empty());
        assert_eq!(
            mrtr_continuation_fields(Some(&json!({"requestState": "s"}))),
            vec!["requestState"]
        );
        assert_eq!(
            mrtr_continuation_fields(Some(&json!({"inputResponses": {}, "requestState": "s"}))),
            vec!["inputResponses", "requestState"]
        );
    }
}
