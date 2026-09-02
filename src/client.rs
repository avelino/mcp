use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::config::ServerConfig;
use crate::protocol::*;
use crate::transport::cli::{CliTransport, CliTransportConfig};
use crate::transport::http::HttpTransport;
use crate::transport::stdio::StdioTransport;
use crate::transport::Transport;

/// `McpClient` wraps a transport with interior mutability so it can be shared
/// across many concurrent requests via `Arc<McpClient>`. The transport itself
/// is responsible for serializing access where needed (e.g. stdio uses a
/// writer task + per-request id multiplexing).
pub struct McpClient {
    transport: Arc<dyn Transport>,
    next_id: AtomicU64,
    /// Revision agreed with this peer. Fixed during `connect`, before the
    /// client is shared, so it needs no interior mutability.
    protocol_version: String,
    /// Human label for this peer — a command or a URL. Error messages only.
    peer: String,
    /// Validated `x-mcp-header` annotations per tool, learned from
    /// `tools/list`. Shared across concurrent calls, hence the mutex.
    header_params: Mutex<HashMap<String, Vec<x_mcp_header::HeaderParam>>>,
}

/// How to obtain a fresh transport, for the one case that needs it: the
/// discovery probe killing the transport we already had.
type TransportFactory<'a> = dyn Fn() -> Result<Arc<dyn Transport>> + Send + Sync + 'a;

/// How long the `server/discover` probe may take before we stop waiting.
///
/// The probe is best-effort, and a peer that never heard of the method may
/// simply not answer at all. On the full `MCP_TIMEOUT` (60s by default) that
/// silence costs a minute of startup on *every* connection to such a peer,
/// for a request we already expect to fail. A few seconds is plenty for a
/// server that does implement it.
const DISCOVER_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Outcome of the `server/discover` probe. The three failure shapes are not
/// interchangeable: only one of them means the connection is now unusable.
enum Probe {
    Discovered(Box<ServerDiscoverResult>),
    /// The peer answered, just not with a discovery result — a JSON-RPC
    /// error, no result, or a result of some other shape. An old peer.
    Unsupported(anyhow::Error),
    /// Nothing came back inside the probe budget. The peer is most likely
    /// alive and ignoring a method it never heard of, so we leave it running
    /// and fall back on the same transport.
    TimedOut,
    /// The transport itself failed under the probe. A stdio backend that
    /// exits on an unknown method takes the connection down with it, so the
    /// fallback handshake would otherwise run on a dead pipe.
    Died(anyhow::Error),
}

/// Build the transport for `config`. Separate from `connect` so the discovery
/// probe has a way to re-open one it killed.
fn build_transport(config: &ServerConfig) -> Result<Arc<dyn Transport>> {
    let transport: Arc<dyn Transport> = match config {
        ServerConfig::Cli {
            command,
            args,
            env,
            cli_help,
            cli_depth,
            cli_only,
            tools: preset_tools,
            ..
        } => {
            let mut tool_args_map = HashMap::new();
            let preset: Vec<Tool> = preset_tools
                .iter()
                .map(|t| {
                    if !t.args.is_empty() {
                        tool_args_map.insert(t.name.clone(), t.args.clone());
                    }
                    Tool {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        input_schema: t.input_schema.clone(),
                        annotations: None,
                    }
                })
                .collect();
            Arc::new(CliTransport::new(CliTransportConfig {
                command: command.clone(),
                base_args: args.clone(),
                env: env.clone(),
                help_flag: cli_help.clone(),
                depth: *cli_depth,
                only: cli_only.clone(),
                preset_tools: preset,
                tool_args: tool_args_map,
            }))
        }
        ServerConfig::Stdio {
            command, args, env, ..
        } => Arc::new(StdioTransport::new(command, args, env)?),
        ServerConfig::Http { url, headers, .. } => {
            let t = HttpTransport::new(url, headers)?;
            t.load_saved_token();
            Arc::new(t)
        }
    };
    Ok(transport)
}

/// Label for a peer in error messages: the command we spawn or the URL we POST
/// to, whichever identifies it to the person reading the error.
fn peer_label(config: &ServerConfig) -> String {
    match config {
        ServerConfig::Cli { command, .. } | ServerConfig::Stdio { command, .. } => command.clone(),
        ServerConfig::Http { url, .. } => url.clone(),
    }
}

impl McpClient {
    pub async fn connect(config: &ServerConfig) -> Result<Self> {
        let mut client = McpClient::new(build_transport(config)?, peer_label(config));
        client.negotiate(&|| build_transport(config)).await?;
        Ok(client)
    }

    /// Connect to a running `mcp serve` proxy over HTTP instead of spawning a
    /// backend locally. The proxy keeps backends warm across calls, so the
    /// per-call cold start (npx/Node/handshake) is paid once, not every time.
    /// Tools are addressed by their namespaced `{server}__{tool}` name.
    pub async fn connect_via_proxy(proxy_url: &str) -> Result<Self> {
        let open = || -> Result<Arc<dyn Transport>> {
            Ok(Arc::new(HttpTransport::new(proxy_url, &HashMap::new())?))
        };
        let mut client = McpClient::new(open()?, proxy_url.to_string());
        client.negotiate(&open).await?;
        Ok(client)
    }

    fn new(transport: Arc<dyn Transport>, peer: String) -> Self {
        Self {
            transport,
            next_id: AtomicU64::new(1),
            // Conservative default: until we know better, behave like the
            // revision every backend in the wild speaks today.
            protocol_version: PROTOCOL_VERSION_LEGACY.to_string(),
            peer,
            header_params: Mutex::new(HashMap::new()),
        }
    }

    /// Revision agreed with this peer.
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    fn is_stateless(&self) -> bool {
        is_stateless_version(&self.protocol_version)
    }

    /// Agree on a protocol revision with the peer.
    ///
    /// 2026-07-28 replaced the `initialize` handshake with a `server/discover`
    /// probe and explicitly sanctions probing first — including on STDIO —
    /// precisely so one client can talk to both generations. Every backend we
    /// proxy today predates that revision and answers the probe with
    /// `METHOD_NOT_FOUND`, some other JSON-RPC error, a transport-level
    /// failure, or a result that is not a discovery result at all. All four
    /// mean the same thing: old peer. None of them may fail the connection —
    /// we fall back to the handshake and end up exactly where we are today.
    async fn negotiate(&mut self, reopen: &TransportFactory<'_>) -> Result<()> {
        let version = match self.discover().await {
            Probe::Discovered(discovered) => {
                let best = discovered
                    .best_common_version()
                    .with_context(|| {
                        format!(
                            "no common MCP protocol version with server '{}': \
                             it offers [{}], we speak [{}]",
                            // Identity is optional and self-reported; the spec
                            // says never to make behavior depend on it, so it
                            // only ever decorates a message.
                            discovered
                                .server_info()
                                .map(|i| i.name)
                                .unwrap_or_else(|| "unknown".to_string()),
                            discovered.supported_versions.join(", "),
                            SUPPORTED_PROTOCOL_VERSIONS.join(", "),
                        )
                    })?
                    .to_string();

                // Stateless revisions have no handshake to run at all.
                if is_stateless_version(&best) {
                    best
                } else {
                    self.handshake(&best).await?
                }
            }
            Probe::Unsupported(e) => {
                tracing::debug!(
                    error = %e,
                    "server/discover unavailable — falling back to the initialize handshake"
                );
                self.handshake(PROTOCOL_VERSION_LEGACY).await?
            }
            Probe::TimedOut => {
                tracing::debug!(
                    peer = %self.peer,
                    "server/discover went unanswered — falling back to the initialize handshake"
                );
                self.handshake(PROTOCOL_VERSION_LEGACY).await?
            }
            Probe::Died(probe_error) => {
                // The fallback cannot run on the transport the probe just
                // killed, so try for a fresh one first. Re-opening is cheap
                // and idempotent for every transport we build.
                let reopened = match reopen() {
                    Ok(fresh) => {
                        self.transport = fresh;
                        true
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "could not re-open the transport after a fatal server/discover probe"
                        );
                        false
                    }
                };
                match self.handshake(PROTOCOL_VERSION_LEGACY).await {
                    Ok(version) => version,
                    Err(handshake_error) => {
                        let hint =
                            fatal_probe_hint(&self.peer, &probe_error, &handshake_error, reopened);
                        return Err(handshake_error.context(hint));
                    }
                }
            }
        };

        self.transport.set_protocol_version(&version);
        self.protocol_version = version;
        Ok(())
    }

    /// The 2026-07-28 discovery probe.
    ///
    /// Bounded by its own short timeout rather than the request timeout: the
    /// likeliest answer from the backends we proxy today is no answer at all,
    /// and that is not worth a minute of startup.
    async fn discover(&self) -> Probe {
        let req = JsonRpcRequest::new(self.next_id(), "server/discover", Some(discover_params()));

        // Abandoning the request leaves one entry behind in a multiplexing
        // transport's pending map. That is harmless: ids are never reused, so
        // a late answer is dropped rather than mistaken for another call's.
        let resp = match tokio::time::timeout(DISCOVER_PROBE_TIMEOUT, self.transport.request(&req))
            .await
        {
            Err(_) => return Probe::TimedOut,
            Ok(Err(e)) => return Probe::Died(e),
            Ok(Ok(resp)) => resp,
        };

        if let Some(err) = resp.error {
            return Probe::Unsupported(anyhow!(
                "server/discover failed: {} (code {})",
                err.message,
                err.code
            ));
        }
        let Some(result) = resp.result else {
            return Probe::Unsupported(anyhow!("server/discover returned no result"));
        };
        match serde_json::from_value::<ServerDiscoverResult>(result) {
            Ok(discovered) => Probe::Discovered(Box::new(discovered)),
            Err(e) => Probe::Unsupported(anyhow!("failed to parse server/discover result: {e}")),
        }
    }

    /// Legacy `initialize` + `notifications/initialized`, byte-identical to
    /// what we sent before 2026-07-28 existed — which is the point, since any
    /// peer reaching this path predates it. Returns the revision actually
    /// agreed on.
    async fn handshake(&self, version: &str) -> Result<String> {
        let params = InitializeParams {
            protocol_version: version.to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo::this_cli(),
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

        Ok(agreed_handshake_version(resp.result.as_ref(), version))
    }

    /// Build an outgoing request, attaching the per-request `_meta` that the
    /// stateless revision requires in place of the handshake state.
    ///
    /// On an older peer we attach nothing at all: absence of `_meta` is the
    /// legacy wire shape, and adding keys a pre-2026-07-28 server never
    /// agreed to is exactly the kind of "harmless" change that breaks strict
    /// schema validators.
    fn build_request(&self, method: &str, params: Option<Value>) -> JsonRpcRequest {
        let params = if self.is_stateless() {
            Some(self.stateless_params(params))
        } else {
            params
        };
        JsonRpcRequest::new(self.next_id(), method, params)
    }

    /// Merge the stateless `_meta` block into `params`, preserving anything
    /// the caller already put there.
    fn stateless_params(&self, params: Option<Value>) -> Value {
        let mut params = match params {
            Some(v) if v.is_object() => v,
            // A non-object `params` is not something we can decorate, and
            // silently reshaping it would corrupt the call. MCP params are
            // always objects, so this only guards against garbage.
            Some(v) => return v,
            None => json!({}),
        };

        let meta = params
            .as_object_mut()
            .expect("checked object above")
            .entry("_meta")
            .or_insert_with(|| json!({}));
        let Some(meta) = meta.as_object_mut() else {
            return params;
        };

        meta.insert(
            meta_keys::PROTOCOL_VERSION.to_string(),
            Value::String(self.protocol_version.clone()),
        );
        meta.insert(
            meta_keys::CLIENT_CAPABILITIES.to_string(),
            serde_json::to_value(ClientCapabilities::default()).unwrap_or_else(|_| json!({})),
        );
        meta.insert(
            meta_keys::CLIENT_INFO.to_string(),
            serde_json::to_value(ClientInfo::this_cli()).unwrap_or_else(|_| json!({})),
        );

        // W3C trace context now travels in `_meta`, which is the only way a
        // stdio backend ever sees a trace — it has no headers to carry one.
        // Skip the propagator call entirely when telemetry is off; this runs
        // on every request.
        if crate::telemetry::should_inject_traceparent() {
            let mut carrier = HashMap::<String, String>::new();
            crate::telemetry::inject_traceparent(&mut carrier);
            merge_trace_context(meta, &carrier);
        }

        params
    }

    /// Send a request and return its raw `result`.
    async fn send(&self, method: &str, params: Option<Value>) -> Result<Value> {
        self.send_with_headers(method, params, &[]).await
    }

    /// Same, mirroring `headers` into the transport's own header mechanism
    /// (the `Mcp-Param-*` family; see [`x_mcp_header`]).
    async fn send_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        headers: &[(String, String)],
    ) -> Result<Value> {
        let req = self.build_request(method, params);
        let resp = self.transport.request_with_headers(&req, headers).await?;

        if let Some(err) = resp.error {
            bail!("{method} failed: {} (code {})", err.message, err.code);
        }

        resp.result
            .with_context(|| format!("{method} returned no result"))
    }

    /// Send a request whose result we are about to deserialize into a typed
    /// shape, rejecting an [MRTR][mrtr] interim result first.
    ///
    /// An `input_required` result carries `inputRequests` instead of the
    /// payload these accessors expect, so deserializing it would surface as
    /// an unrelated serde error ("missing field `tools`"). Say what actually
    /// happened instead.
    ///
    /// [mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
    async fn send_complete(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let result = self.send(method, params).await?;
        if is_input_required(&result) {
            bail!(
                "{method} returned an interim '{RESULT_TYPE_INPUT_REQUIRED}' result (MRTR); \
                 use request_raw to relay it"
            );
        }
        Ok(result)
    }

    /// Walk a paginated `*/list` method to the end.
    ///
    /// The three list methods differ only in what they call the array, so
    /// they share one cursor loop instead of three copies of it. The field
    /// name is passed rather than inferred so a backend answering
    /// `tools/list` with a `resources` array is still an error.
    async fn list_all<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        field: &str,
    ) -> Result<Vec<T>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let params = cursor.as_ref().map(|c| json!({"cursor": c}));
            let mut raw = self.send_complete(method, params).await?;

            let items = raw.get_mut(field).map(Value::take).unwrap_or(Value::Null);
            let page: Vec<T> = serde_json::from_value(items)
                .with_context(|| format!("failed to parse {method} result"))?;
            all.extend(page);

            cursor = match raw.get("nextCursor") {
                None | Some(Value::Null) => None,
                Some(c) => Some(
                    serde_json::from_value::<String>(c.clone())
                        .with_context(|| format!("failed to parse {method} nextCursor"))?,
                ),
            };
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        let tools = self.list_all("tools/list", "tools").await?;
        Ok(self.accept_tools(tools))
    }

    /// Drop tools whose `x-mcp-header` annotations break the spec's
    /// constraints, and remember the valid ones so `tools/call` can mirror
    /// them into headers.
    ///
    /// The spec puts this on the client: an invalid annotation invalidates the
    /// whole tool definition, which the client MUST exclude from `tools/list`
    /// and SHOULD warn about — one bad tool must not sink the rest. It is a
    /// security boundary, not a formality: the annotation names the header, so
    /// an unchecked one lets a backend pick `Authorization` (or smuggle a CRLF)
    /// into every request we send on its behalf.
    ///
    /// Unlike the mirroring below, this runs on every transport rather than
    /// only on HTTP. `mcp serve` re-exports these tools over Streamable HTTP,
    /// so a stdio backend's malformed annotation still reaches an HTTP
    /// boundary — one hop later. Well-formed definitions pass through
    /// untouched, so nothing a legacy peer sends today changes shape.
    fn accept_tools(&self, tools: Vec<Tool>) -> Vec<Tool> {
        let mut learned = HashMap::new();
        let accepted = tools
            .into_iter()
            .filter(
                |tool| match x_mcp_header::params_of(tool.input_schema.as_ref()) {
                    Ok(params) => {
                        if !params.is_empty() {
                            learned.insert(tool.name.clone(), params);
                        }
                        true
                    }
                    Err(reason) => {
                        tracing::warn!(
                            tool = %tool.name,
                            peer = %self.peer,
                            %reason,
                            "rejecting tool definition: invalid x-mcp-header annotation"
                        );
                        false
                    }
                },
            )
            .collect();

        // Replace rather than merge: an annotation the server has dropped must
        // stop producing a header.
        *self.header_params.lock().unwrap() = learned;
        accepted
    }

    /// `Mcp-Param-*` headers for one call, from the annotations learned in
    /// `tools/list`.
    ///
    /// Empty for a tool we never listed — we have no schema to read, and
    /// inventing a header would only earn a `-32020` header mismatch. Empty
    /// for a legacy peer too: `x-mcp-header` arrived with 2026-07-28, and a
    /// peer that predates it never agreed to receive these headers.
    fn param_headers(&self, tool: &str, arguments: &Value) -> Vec<(String, String)> {
        if !self.is_stateless() {
            return Vec::new();
        }
        self.header_params
            .lock()
            .unwrap()
            .get(tool)
            .map(|params| x_mcp_header::headers_for(params, arguments))
            .unwrap_or_default()
    }

    /// Send a request and return the raw `result` value, untouched.
    ///
    /// The proxy needs this: under [MRTR][mrtr] a backend may answer
    /// `tools/call` with an interim `resultType: "input_required"` result
    /// that has no `content` and therefore does not fit [`ToolCallResult`].
    /// Deserializing eagerly would turn a valid protocol exchange into a
    /// parse error, so relaying paths stay on the raw value.
    ///
    /// Not for `tools/call`: that method also has to mirror `x-mcp-header`
    /// annotations into `Mcp-Param-*` headers, which only
    /// [`Self::call_tool_raw`] does. Sending one through here silently drops
    /// them.
    ///
    /// [mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
    pub async fn request_raw(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.send(method, params).await
    }

    /// `tools/call` returning the raw result, preserving MRTR interim
    /// results for the caller to relay.
    ///
    /// This is also where `x-mcp-header` annotations turn into headers: the
    /// spec requires the mirroring on `tools/call` specifically, and this is
    /// the one path every `tools/call` goes through.
    ///
    /// Takes whole `params` rather than `(name, arguments)` — like
    /// [`Self::read_resource_raw`] — because an MRTR retry carries
    /// `inputResponses`/`requestState` alongside `arguments`, and rebuilding
    /// params from the two fields we happen to name would drop the
    /// continuation and stall the exchange. Rebuilding is what let the proxy
    /// bypass this method entirely, taking the header mirroring with it.
    /// `call_tool_raw` plus headers the caller supplies — today, the caller's
    /// identity (see `config::ForwardIdentity`).
    ///
    /// The extras go FIRST so a backend's own `x-mcp-header` annotation cannot
    /// silently shadow the identity header: a tool that declares an argument
    /// mapping to `X-MCP-Subject` would otherwise let the caller pick their own
    /// subject, which is precisely the bypass this feature must not create.
    pub async fn call_tool_raw_with(
        &self,
        params: serde_json::Value,
        extra_headers: &[(String, String)],
    ) -> Result<serde_json::Value> {
        let empty = serde_json::Value::Object(serde_json::Map::new());
        let from_params = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => self.param_headers(name, params.get("arguments").unwrap_or(&empty)),
            None => Vec::new(),
        };

        let reserved: Vec<String> = extra_headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        let mut headers = extra_headers.to_vec();
        headers.extend(
            from_params
                .into_iter()
                .filter(|(k, _)| !reserved.contains(&k.to_ascii_lowercase())),
        );

        self.send_with_headers("tools/call", Some(params), &headers)
            .await
    }

    pub async fn call_tool_raw(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        // Read the header inputs out of the params we are about to send, so
        // the headers can never describe a different call than the body.
        let empty = serde_json::Value::Object(serde_json::Map::new());
        let headers = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => self.param_headers(name, params.get("arguments").unwrap_or(&empty)),
            None => Vec::new(),
        };
        self.send_with_headers("tools/call", Some(params), &headers)
            .await
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<ToolCallResult> {
        let params = ToolCallParams {
            name: name.to_string(),
            arguments,
        };
        let result = self.call_tool_raw(serde_json::to_value(&params)?).await?;

        if crate::protocol::is_input_required(&result) {
            bail!(
                "tools/call on '{name}' needs additional input (MRTR); \
                 use call_tool_raw to relay it"
            );
        }

        serde_json::from_value(result).context("failed to parse tools/call result")
    }

    pub async fn list_resources(&self) -> Result<Vec<Resource>> {
        self.list_all("resources/list", "resources").await
    }

    /// `resources/read` returning the raw result, preserving MRTR interim
    /// results for the caller to relay.
    ///
    /// The spec's MRTR *Supported Requests* table lists `prompts/get` and
    /// `resources/read` alongside `tools/call`, so a caller that can only
    /// relay interim results for `tools/call` breaks the other two.
    ///
    /// Takes whole `params` rather than a bare `uri` because the proxy's
    /// retry has to carry `inputResponses`/`requestState` through untouched;
    /// rebuilding params from the one field we happen to know would drop the
    /// continuation and stall the exchange.
    pub async fn read_resource_raw(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        self.request_raw("resources/read", Some(params)).await
    }

    pub async fn list_prompts(&self) -> Result<Vec<Prompt>> {
        self.list_all("prompts/list", "prompts").await
    }

    /// `prompts/get` returning the raw result, preserving MRTR interim
    /// results for the caller to relay. See [`Self::read_resource_raw`] for
    /// why this takes whole `params`.
    pub async fn get_prompt_raw(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        self.request_raw("prompts/get", Some(params)).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.transport.close().await
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// `params` for the discovery probe, matching the spec's `server/discover`
/// example exactly.
///
/// The probe used to send `params: None`. That is not the request the spec
/// documents, and a strict modern server MUST reject one that omits the
/// required `_meta`. Sending it costs nothing with an older peer, which
/// rejects or ignores `server/discover` either way.
///
/// The version declared here is the newest we speak rather than the negotiated
/// one — negotiating is what this request is for.
fn discover_params() -> Value {
    json!({
        "_meta": {
            meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
            meta_keys::CLIENT_INFO: ClientInfo::this_cli(),
            meta_keys::CLIENT_CAPABILITIES: ClientCapabilities::default(),
        }
    })
}

/// Context for the worst probe outcome: the peer died on `server/discover`
/// and the fallback handshake could not recover either.
///
/// Without this the operator sees a bare "transport closed" and has no way to
/// guess that our own compatibility probe is what killed their backend.
fn fatal_probe_hint(
    peer: &str,
    probe_error: &anyhow::Error,
    handshake_error: &anyhow::Error,
    reopened: bool,
) -> String {
    // A fresh connection that fails exactly like the probe did refutes the
    // "our probe killed it" theory: the backend is simply unreachable, and
    // blaming the probe sends the reader chasing the wrong thing. Not
    // hypothetical — an expired VPN session makes every request redirect, and
    // the first version of this message pointed at the probe instead of at the
    // auth gateway doing the redirecting.
    //
    // The re-open is what makes the comparison mean anything. Without it the
    // handshake ran on the connection the probe already killed, so an
    // identical error is exactly what a probe-caused death looks like.
    if reopened && format!("{probe_error:#}") == format!("{handshake_error:#}") {
        return format!("backend '{peer}' is unreachable");
    }

    let recovery = if reopened {
        "the transport was re-opened and the initialize handshake still failed"
    } else {
        "the transport could not be re-opened, so the handshake ran on the dead connection"
    };
    format!(
        "backend '{peer}' failed during the server/discover compatibility probe \
         ({probe_error:#}), and {recovery}; a backend that exits on an unknown \
         JSON-RPC method is the usual cause"
    )
}

/// Client-side handling of the 2026-07-28 `x-mcp-header` annotation, which
/// lets a server mirror chosen `tools/call` arguments into HTTP headers so
/// intermediaries can route on them without parsing the body.
///
/// Both halves are client obligations. Mirroring is the visible one;
/// validation is the one that matters, because the *server* picks the header
/// name. Unvalidated, a backend names its header `Authorization`, or hides a
/// CRLF in it, and every intermediary between us and the server sees whatever
/// it wanted there. The spec's answer is to treat a violating annotation as
/// invalidating the whole tool definition.
pub(crate) mod x_mcp_header {
    use serde_json::Value;

    /// The annotation keyword, as it appears inside a property's schema.
    const KEYWORD: &str = "x-mcp-header";

    /// Largest integer that survives an IEEE754 double intact — the spec's
    /// safe range for a mirrored integer.
    const SAFE_INT_MAX: i64 = 9_007_199_254_740_991;

    /// One validated annotation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HeaderParam {
        /// Chain of `properties` keys from the schema root to the annotated
        /// property — the exact path the value is read from at call time.
        pub path: Vec<String>,
        /// The `{Name}` in `Mcp-Param-{Name}`.
        pub name: String,
    }

    /// Validated annotations of a tool's `inputSchema`, or the reason the
    /// definition must be rejected.
    ///
    /// A tool with no `inputSchema`, or none carrying the keyword, yields an
    /// empty list — the overwhelmingly common case, and never an error.
    pub fn params_of(schema: Option<&Value>) -> Result<Vec<HeaderParam>, String> {
        let Some(schema) = schema else {
            return Ok(Vec::new());
        };

        let mut found = Vec::new();
        let mut seen = Vec::new();
        collect(schema, &mut Vec::new(), &mut found, &mut seen)?;

        // Everything `collect` found is statically reachable by construction,
        // so any surplus the scan sees sits somewhere the spec forbids:
        // behind `items`, `oneOf`/`anyOf`/`allOf`/`not`, `if`/`then`/`else`,
        // `$ref`, or on the root schema itself.
        let total = count(schema);
        if total > found.len() {
            return Err(format!(
                "{} `{KEYWORD}` annotation(s) are not statically reachable \
                 through `properties` alone",
                total - found.len()
            ));
        }
        Ok(found)
    }

    /// Walk the statically reachable properties, validating every annotation
    /// on the way. Nested objects are fine as long as every step is a
    /// `properties` key.
    fn collect(
        schema: &Value,
        path: &mut Vec<String>,
        out: &mut Vec<HeaderParam>,
        seen: &mut Vec<String>,
    ) -> Result<(), String> {
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            return Ok(());
        };

        for (property, subschema) in properties {
            path.push(property.clone());
            if let Some(annotation) = subschema.get(KEYWORD) {
                let name = validate(annotation, subschema, seen)?;
                out.push(HeaderParam {
                    path: path.clone(),
                    name,
                });
            }
            collect(subschema, path, out, seen)?;
            path.pop();
        }
        Ok(())
    }

    /// Check one annotation against the spec's constraints.
    fn validate(
        annotation: &Value,
        subschema: &Value,
        seen: &mut Vec<String>,
    ) -> Result<String, String> {
        let name = annotation
            .as_str()
            .ok_or_else(|| format!("`{KEYWORD}` must be a string, got {annotation}"))?;

        if name.is_empty() {
            return Err(format!("`{KEYWORD}` must not be empty"));
        }
        // RFC 9110 `tchar` excludes control characters, CR and LF by
        // construction, so this single check covers both constraints — and it
        // is what stops header injection.
        if !name.bytes().all(is_tchar) {
            return Err(format!(
                "`{KEYWORD}` {name:?} is not an RFC 9110 field-name token"
            ));
        }

        let lowercased = name.to_ascii_lowercase();
        if seen.contains(&lowercased) {
            return Err(format!(
                "`{KEYWORD}` {name:?} is not case-insensitively unique in the inputSchema"
            ));
        }
        seen.push(lowercased);

        // Primitive types only, and `number` is called out as excluded. A type
        // we cannot see is a type we cannot confirm is primitive, so it is
        // rejected rather than assumed.
        match subschema.get("type").and_then(Value::as_str) {
            Some("string" | "integer" | "boolean") => Ok(name.to_string()),
            other => Err(format!(
                "`{KEYWORD}` {name:?} annotates type {}, but only string, integer \
                 and boolean may be mirrored",
                other.unwrap_or("<unspecified>")
            )),
        }
    }

    /// RFC 9110 §5.1 `tchar`. `pub(crate)` so the identity-forwarding path in
    /// `serve::proxy` validates header names with the SAME rule — two copies of
    /// a header-injection check is how one of them drifts.
    pub(crate) fn is_tchar(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    }

    /// Count annotations anywhere in a schema, so ones the reachable walk did
    /// not pick up can be spotted.
    ///
    /// Schema-aware on purpose: under `properties` the map keys are property
    /// *names*, so a property literally called `x-mcp-header` is not an
    /// annotation and must not be counted as one.
    fn count(schema: &Value) -> usize {
        let Some(object) = schema.as_object() else {
            // Arrays hold subschemas (`allOf`, `prefixItems`); scalars hold
            // none.
            return match schema.as_array() {
                Some(items) => items.iter().map(count).sum(),
                None => 0,
            };
        };

        let mut total = usize::from(object.contains_key(KEYWORD));
        for (key, value) in object {
            total += match key.as_str() {
                // Maps of name -> subschema.
                "properties" | "patternProperties" | "$defs" | "definitions" => {
                    match value.as_object() {
                        Some(map) => map.values().map(count).sum(),
                        None => 0,
                    }
                }
                // A subschema, or an array of them.
                "items"
                | "prefixItems"
                | "additionalProperties"
                | "contains"
                | "propertyNames"
                | "not"
                | "if"
                | "then"
                | "else"
                | "oneOf"
                | "anyOf"
                | "allOf" => count(value),
                _ => 0,
            };
        }
        total
    }

    /// `Mcp-Param-*` headers for a call's `arguments`.
    ///
    /// A header is omitted when the argument is absent, null, or not the
    /// primitive its schema promised — the spec's own rule for a missing
    /// value, and the only safe answer for a value we cannot represent, since
    /// a header that disagrees with the body is a `-32020` rejection.
    pub fn headers_for(params: &[HeaderParam], arguments: &Value) -> Vec<(String, String)> {
        params
            .iter()
            .filter_map(|param| {
                let mut value = arguments;
                for step in &param.path {
                    value = value.get(step)?;
                }
                let encoded = crate::protocol::header_value(&stringify(value)?)?;
                Some((format!("Mcp-Param-{}", param.name), encoded))
            })
            .collect()
    }

    /// The spec's type conversion for a mirrored value.
    fn stringify(value: &Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => {
                let i = n.as_i64()?;
                (-SAFE_INT_MAX..=SAFE_INT_MAX)
                    .contains(&i)
                    .then(|| i.to_string())
            }
            _ => None,
        }
    }
}

/// Copy the W3C trace context out of a propagator carrier into a request's
/// `_meta`.
///
/// Only the three documented keys move across: the carrier is whatever the
/// configured propagators produced, and `_meta` is not a dumping ground for
/// vendor headers a backend never asked for.
fn merge_trace_context(
    meta: &mut serde_json::Map<String, Value>,
    carrier: &HashMap<String, String>,
) {
    for key in [
        meta_keys::TRACEPARENT,
        meta_keys::TRACESTATE,
        meta_keys::BAGGAGE,
    ] {
        if let Some(value) = carrier.get(key) {
            meta.insert(key.to_string(), Value::String(value.clone()));
        }
    }
}

/// Revision to record after a successful `initialize`.
///
/// The server echoes the revision it picked; we honor it when we speak it.
/// A server that answers `initialize` at all is stateful by construction —
/// we just completed a handshake with it — so an echo we do not recognize,
/// or one claiming a stateless revision, is pinned back to the legacy
/// revision rather than silently switching us onto the stateless wire shape
/// mid-connection.
fn agreed_handshake_version(result: Option<&Value>, requested: &str) -> String {
    let echoed = result
        .and_then(|r| r.get("protocolVersion"))
        .and_then(|v| v.as_str());

    match echoed {
        Some(v) if is_version_supported(v) && !is_stateless_version(v) => v.to_string(),
        _ => requested.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// What a scripted peer answers for one method.
    enum Reply {
        Result(Value),
        Error(i64, &'static str),
        /// Transport-level failure — the request never gets an answer. This
        /// is how an old stdio backend that dislikes an unknown method
        /// behaves in the worst case.
        Dead,
        /// One result per call, in order, so a paginated method can be driven
        /// to the end. The last page repeats if asked for more.
        Pages(Vec<Value>),
    }

    /// Scripted transport that records every message it was asked to send,
    /// so tests can assert on the exact wire output.
    struct MockTransport {
        replies: HashMap<String, Reply>,
        sent: Mutex<Vec<Value>>,
        notified: Mutex<Vec<String>>,
        version: Mutex<Option<String>>,
        /// Headers the client asked the transport to mirror, per method.
        headers: Mutex<HashMap<String, Vec<(String, String)>>>,
    }

    impl MockTransport {
        fn new(replies: Vec<(&str, Reply)>) -> Arc<Self> {
            Arc::new(Self {
                replies: replies
                    .into_iter()
                    .map(|(m, r)| (m.to_string(), r))
                    .collect(),
                sent: Mutex::new(Vec::new()),
                notified: Mutex::new(Vec::new()),
                version: Mutex::new(None),
                headers: Mutex::new(HashMap::new()),
            })
        }

        /// Mirrored headers recorded for `method`, sorted so assertions do not
        /// depend on schema iteration order.
        fn headers_for(&self, method: &str) -> Vec<(String, String)> {
            let mut headers = self
                .headers
                .lock()
                .unwrap()
                .get(method)
                .cloned()
                .unwrap_or_default();
            headers.sort();
            headers
        }

        fn sent(&self) -> Vec<Value> {
            self.sent.lock().unwrap().clone()
        }

        fn methods_sent(&self) -> Vec<String> {
            self.sent()
                .iter()
                .map(|m| m["method"].as_str().unwrap_or_default().to_string())
                .collect()
        }

        fn notified(&self) -> Vec<String> {
            self.notified.lock().unwrap().clone()
        }

        /// The recorded request for `method`. Panics when it was never sent —
        /// callers have already asserted otherwise.
        fn request_for(&self, method: &str) -> Value {
            self.sent()
                .into_iter()
                .find(|m| m["method"] == method)
                .unwrap_or_else(|| panic!("{method} was never sent"))
        }
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
            self.sent.lock().unwrap().push(serde_json::to_value(msg)?);
            match self.replies.get(&msg.method) {
                Some(Reply::Result(v)) => Ok(JsonRpcResponse::success(msg.id.clone(), v.clone())),
                Some(Reply::Error(code, message)) => {
                    Ok(JsonRpcResponse::error(msg.id.clone(), *code, message))
                }
                Some(Reply::Dead) => bail!("transport closed"),
                Some(Reply::Pages(pages)) => {
                    // `sent` already holds this call, so the count is 1-based.
                    let n = self
                        .sent()
                        .iter()
                        .filter(|m| m["method"] == msg.method)
                        .count()
                        - 1;
                    let page = pages.get(n).or_else(|| pages.last()).expect("a page");
                    Ok(JsonRpcResponse::success(msg.id.clone(), page.clone()))
                }
                // An unscripted method is an unknown method, which is what a
                // server that never heard of it would say.
                None => Ok(JsonRpcResponse::error(
                    msg.id.clone(),
                    error_codes::METHOD_NOT_FOUND,
                    "Method not found",
                )),
            }
        }

        async fn request_with_headers(
            &self,
            msg: &JsonRpcRequest,
            extra_headers: &[(String, String)],
        ) -> Result<JsonRpcResponse> {
            self.headers
                .lock()
                .unwrap()
                .insert(msg.method.clone(), extra_headers.to_vec());
            self.request(msg).await
        }

        async fn notify(&self, msg: &JsonRpcNotification) -> Result<()> {
            self.notified.lock().unwrap().push(msg.method.clone());
            Ok(())
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }

        fn set_protocol_version(&self, version: &str) {
            *self.version.lock().unwrap() = Some(version.to_string());
        }
    }

    fn init_ok(version: &str) -> Reply {
        Reply::Result(json!({
            "protocolVersion": version,
            "capabilities": {},
            "serverInfo": {"name": "legacy-backend", "version": "1.0.0"},
        }))
    }

    /// A `server/discover` result in the real wire shape: `supportedVersions`,
    /// and identity inside `_meta` rather than at the top level. Fixtures that
    /// bake in the wrong shape are how a green suite hid a broken handshake,
    /// so this mirrors [`discover_result_matches_the_spec_example`].
    fn discover_ok(versions: &[&str]) -> Reply {
        Reply::Result(json!({
            "resultType": RESULT_TYPE_COMPLETE,
            "supportedVersions": versions,
            "capabilities": {},
            "_meta": {
                meta_keys::SERVER_INFO: {"name": "new-backend", "version": "2.0.0"},
            },
        }))
    }

    /// Re-opening yields the same scripted peer, which is what a real re-spawn
    /// approximates: a fresh process running the same program.
    async fn connect_mock(transport: Arc<MockTransport>) -> Result<McpClient> {
        let reopen = || Ok(Arc::clone(&transport) as Arc<dyn Transport>);
        let mut client = McpClient::new(reopen()?, "mock".to_string());
        client.negotiate(&reopen).await?;
        Ok(client)
    }

    /// Connect with a re-open that fails, i.e. a transport we cannot rebuild.
    async fn connect_mock_without_reopen(transport: Arc<MockTransport>) -> Result<McpClient> {
        let mut client = McpClient::new(transport, "flaky-backend".to_string());
        client
            .negotiate(&|| bail!("re-spawn refused"))
            .await
            .map(|()| client)
    }

    // --- negotiation: the legacy fallback ---

    /// The single most important guarantee: a backend that has never heard of
    /// `server/discover` ends up fully working via `initialize`.
    #[tokio::test]
    async fn method_not_found_on_discover_falls_back_to_initialize() {
        let t = MockTransport::new(vec![
            (
                "server/discover",
                Reply::Error(error_codes::METHOD_NOT_FOUND, "Method not found"),
            ),
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "tools/list",
                Reply::Result(json!({"tools": [{"name": "a"}]})),
            ),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        assert_eq!(client.protocol_version(), PROTOCOL_VERSION_LEGACY);
        assert_eq!(t.notified(), vec!["notifications/initialized"]);
        assert_eq!(
            t.methods_sent(),
            vec!["server/discover", "initialize"],
            "the probe must be followed by the legacy handshake"
        );

        // …and the connection actually works afterwards.
        let tools = client.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
    }

    /// A backend that reacts badly to the probe — killed connection, HTTP 404
    /// surfacing as a transport error — must still connect.
    #[tokio::test]
    async fn transport_error_on_discover_falls_back_to_initialize() {
        let t = MockTransport::new(vec![
            ("server/discover", Reply::Dead),
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        assert_eq!(client.protocol_version(), PROTOCOL_VERSION_LEGACY);
        assert_eq!(t.notified(), vec!["notifications/initialized"]);
    }

    /// A backend that answers `server/discover` with something that is not a
    /// discovery result (an echo, an empty object, a tools list) is an old
    /// backend behaving oddly, not a protocol violation worth failing on.
    #[tokio::test]
    async fn malformed_discover_result_falls_back_to_initialize() {
        for garbage in [json!({}), json!({"tools": []}), json!("pong"), json!(null)] {
            let t = MockTransport::new(vec![
                ("server/discover", Reply::Result(garbage.clone())),
                ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ]);
            let client = connect_mock(Arc::clone(&t)).await.unwrap();
            assert_eq!(
                client.protocol_version(),
                PROTOCOL_VERSION_LEGACY,
                "garbage {garbage} must fall back, not fail"
            );
            assert_eq!(t.notified(), vec!["notifications/initialized"]);
        }
    }

    /// A `server/discover` that fails for any other reason is still just an
    /// old peer.
    #[tokio::test]
    async fn internal_error_on_discover_falls_back_to_initialize() {
        let t = MockTransport::new(vec![
            (
                "server/discover",
                Reply::Error(error_codes::INTERNAL_ERROR, "boom"),
            ),
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
        ]);
        let client = connect_mock(t).await.unwrap();
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION_LEGACY);
    }

    /// The fallback advertises the legacy revision, not our newest one: a peer
    /// that fails the probe predates 2026-07-28 by construction.
    #[tokio::test]
    async fn fallback_initialize_advertises_the_legacy_revision() {
        let t = MockTransport::new(vec![("initialize", init_ok(PROTOCOL_VERSION_LEGACY))]);
        connect_mock(Arc::clone(&t)).await.unwrap();

        let init = t.request_for("initialize");
        assert_eq!(init["params"]["protocolVersion"], PROTOCOL_VERSION_LEGACY);
        assert_eq!(init["params"]["clientInfo"]["name"], "mcp");
        // No `_meta` on the handshake itself.
        assert!(init["params"].get("_meta").is_none());
    }

    /// A legacy server may pick an older revision than we asked for; we honor
    /// what it picked so long as we speak it.
    #[tokio::test]
    async fn handshake_honors_the_revision_the_server_picked() {
        let t = MockTransport::new(vec![("initialize", init_ok("2024-11-05"))]);
        let client = connect_mock(t).await.unwrap();
        assert_eq!(client.protocol_version(), "2024-11-05");
    }

    /// An echo we do not speak must not become the negotiated version.
    #[tokio::test]
    async fn handshake_ignores_unknown_or_stateless_echo() {
        for echo in ["1999-01-01", PROTOCOL_VERSION_STATELESS, ""] {
            let t = MockTransport::new(vec![("initialize", init_ok(echo))]);
            let client = connect_mock(t).await.unwrap();
            assert_eq!(
                client.protocol_version(),
                PROTOCOL_VERSION_LEGACY,
                "echo {echo} must not switch us off the handshake path"
            );
        }
    }

    // --- negotiation: the 2026-07-28 path ---

    #[tokio::test]
    async fn discover_success_skips_the_handshake_entirely() {
        let t = MockTransport::new(vec![("server/discover", discover_ok(&[PROTOCOL_VERSION]))]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        assert_eq!(client.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(t.methods_sent(), vec!["server/discover"]);
        assert!(
            t.notified().is_empty(),
            "a stateless peer gets no notifications/initialized"
        );
        assert_eq!(
            t.version.lock().unwrap().as_deref(),
            Some(PROTOCOL_VERSION),
            "the transport must learn the negotiated revision"
        );
    }

    #[tokio::test]
    async fn discover_picks_the_newest_shared_revision() {
        let t = MockTransport::new(vec![(
            "server/discover",
            discover_ok(&["2024-11-05", PROTOCOL_VERSION, "2025-11-25"]),
        )]);
        let client = connect_mock(t).await.unwrap();
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION);
    }

    /// A server that advertises discovery but only speaks older revisions
    /// still needs the handshake for those revisions.
    #[tokio::test]
    async fn discover_of_a_legacy_only_server_still_handshakes() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&["2025-11-25"])),
            ("initialize", init_ok("2025-11-25")),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        assert_eq!(client.protocol_version(), "2025-11-25");
        assert_eq!(t.methods_sent(), vec!["server/discover", "initialize"]);
        assert_eq!(t.notified(), vec!["notifications/initialized"]);
        assert_eq!(
            t.request_for("initialize")["params"]["protocolVersion"],
            "2025-11-25"
        );
    }

    #[tokio::test]
    async fn disjoint_version_sets_fail_with_a_clear_error() {
        let t = MockTransport::new(vec![(
            "server/discover",
            discover_ok(&["2030-01-01", "1999-01-01"]),
        )]);
        let err = match connect_mock(t).await {
            Ok(_) => panic!("disjoint version sets must not connect"),
            Err(e) => format!("{e:#}"),
        };

        assert!(err.contains("no common MCP protocol version"), "{err}");
        assert!(err.contains("new-backend"), "{err}");
        assert!(err.contains("2030-01-01"), "{err}");
        assert!(err.contains(PROTOCOL_VERSION), "{err}");
    }

    // --- request shape: legacy stays byte-identical ---

    /// The backwards-compat contract in its strictest form: on a legacy peer
    /// the request we put on the wire is exactly what we sent before
    /// 2026-07-28 existed. No `_meta`, no invented `params`.
    #[tokio::test]
    async fn legacy_requests_carry_no_meta_at_all() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ("tools/list", Reply::Result(json!({"tools": []}))),
            (
                "tools/call",
                Reply::Result(json!({"content": [{"type": "text", "text": "hi"}]})),
            ),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        client.list_tools().await.unwrap();
        client
            .call_tool("search", json!({"q": "rust"}))
            .await
            .unwrap();

        let list = t.request_for("tools/list");
        assert_eq!(
            list,
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            "a legacy tools/list must have no params key at all"
        );

        let call = t.request_for("tools/call");
        assert_eq!(
            call["params"],
            json!({"name": "search", "arguments": {"q": "rust"}}),
            "a legacy tools/call must carry only name and arguments"
        );
    }

    /// Even with telemetry-shaped `_meta` keys in play, a legacy peer sees
    /// none of them.
    #[tokio::test]
    async fn legacy_read_and_prompt_requests_carry_no_meta() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "resources/read",
                Reply::Result(json!({"contents": [{"uri": "file:///x"}]})),
            ),
            ("prompts/get", Reply::Result(json!({"messages": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        client
            .read_resource_raw(json!({"uri": "file:///x"}))
            .await
            .unwrap();
        client.get_prompt_raw(json!({"name": "p"})).await.unwrap();

        assert_eq!(
            t.request_for("resources/read")["params"],
            json!({"uri": "file:///x"})
        );
        assert_eq!(t.request_for("prompts/get")["params"], json!({"name": "p"}));
    }

    // --- request shape: stateless carries _meta ---

    #[tokio::test]
    async fn stateless_requests_carry_version_capabilities_and_client_info() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("tools/list", Reply::Result(json!({"tools": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();

        let meta = &t.request_for("tools/list")["params"]["_meta"];
        assert_eq!(meta[meta_keys::PROTOCOL_VERSION], PROTOCOL_VERSION);
        assert_eq!(meta[meta_keys::CLIENT_INFO]["name"], "mcp");
        assert!(
            meta.get(meta_keys::CLIENT_CAPABILITIES).is_some(),
            "clientCapabilities is required even when empty"
        );
    }

    /// `_meta` must be merged into whatever the caller already had, not
    /// substituted for it — the proxy relays caller-supplied `_meta`.
    #[tokio::test]
    async fn stateless_meta_merges_with_caller_supplied_meta() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client
            .request_raw(
                "tools/call",
                Some(json!({"name": "x", "_meta": {"progressToken": 7}})),
            )
            .await
            .unwrap();

        let params = t.request_for("tools/call")["params"].clone();
        assert_eq!(params["name"], "x");
        assert_eq!(params["_meta"]["progressToken"], 7);
        assert_eq!(
            params["_meta"][meta_keys::PROTOCOL_VERSION],
            PROTOCOL_VERSION
        );
    }

    /// Non-object `params` cannot hold `_meta`. Reshaping it into an object
    /// would break the call outright, so we leave it alone.
    #[tokio::test]
    async fn stateless_meta_leaves_non_object_params_untouched() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("weird/method", Reply::Result(json!({"ok": true}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client
            .request_raw("weird/method", Some(json!([1, 2, 3])))
            .await
            .unwrap();

        assert_eq!(t.request_for("weird/method")["params"], json!([1, 2, 3]));
    }

    // --- MRTR interim results ---

    fn input_required() -> Value {
        json!({
            "resultType": RESULT_TYPE_INPUT_REQUIRED,
            "inputRequests": [{"id": "1", "schema": {}}],
        })
    }

    /// Every typed accessor must name the real problem instead of letting
    /// serde complain about a field it never saw.
    #[tokio::test]
    async fn typed_accessors_reject_input_required_with_a_clear_error() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ("tools/list", Reply::Result(input_required())),
            ("resources/list", Reply::Result(input_required())),
            ("resources/read", Reply::Result(input_required())),
            ("prompts/list", Reply::Result(input_required())),
            ("prompts/get", Reply::Result(input_required())),
            ("tools/call", Reply::Result(input_required())),
        ]);
        let client = connect_mock(t).await.unwrap();

        // Only the typed accessors belong here. `read_resource_raw` and
        // `get_prompt_raw` deliberately PRESERVE an interim result so the
        // proxy can relay it — that is their whole reason to exist, and
        // `raw_accessors_preserve_input_required_on_every_supported_method`
        // pins it.
        let errors = vec![
            format!("{:#}", client.list_tools().await.unwrap_err()),
            format!("{:#}", client.list_resources().await.unwrap_err()),
            format!("{:#}", client.list_prompts().await.unwrap_err()),
            format!("{:#}", client.call_tool("t", json!({})).await.unwrap_err()),
        ];

        for err in errors {
            assert!(
                err.contains("MRTR"),
                "error must explain the MRTR interim result, got: {err}"
            );
            assert!(
                !err.contains("missing field"),
                "error must not be a raw serde failure, got: {err}"
            );
        }
    }

    /// The relaying paths must keep the interim result intact — rejecting it
    /// there would break MRTR for the proxy.
    #[tokio::test]
    async fn raw_accessors_preserve_input_required() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ("tools/call", Reply::Result(input_required())),
        ]);
        let client = connect_mock(t).await.unwrap();

        let raw = client
            .call_tool_raw(json!({"name": "t", "arguments": {}}))
            .await
            .unwrap();
        assert!(is_input_required(&raw));

        let raw = client
            .request_raw("tools/call", Some(json!({"name": "t"})))
            .await
            .unwrap();
        assert!(is_input_required(&raw));
    }

    /// A `complete` result — and a legacy result with no `resultType` at all —
    /// must sail through untouched.
    #[tokio::test]
    async fn results_without_result_type_are_accepted() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "tools/list",
                Reply::Result(json!({"tools": [{"name": "a"}]})),
            ),
            (
                "tools/call",
                Reply::Result(json!({
                    "resultType": RESULT_TYPE_COMPLETE,
                    "content": [{"type": "text", "text": "ok"}],
                })),
            ),
        ]);
        let client = connect_mock(t).await.unwrap();

        assert_eq!(client.list_tools().await.unwrap().len(), 1);
        let call = client.call_tool("t", json!({})).await.unwrap();
        assert_eq!(call.content.len(), 1);
    }

    /// A JSON-RPC error on a normal call must still read as that error, not
    /// get swallowed by the MRTR guard.
    #[tokio::test]
    async fn jsonrpc_errors_still_surface() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ("tools/list", Reply::Error(-32603, "backend exploded")),
        ]);
        let client = connect_mock(t).await.unwrap();

        let err = format!("{:#}", client.list_tools().await.unwrap_err());
        assert!(err.contains("backend exploded"), "{err}");
        assert!(err.contains("-32603"), "{err}");
    }

    // --- W3C trace context in _meta ---

    #[test]
    fn trace_context_moves_only_the_documented_keys() {
        let carrier: HashMap<String, String> = [
            (meta_keys::TRACEPARENT, "00-abc-def-01"),
            (meta_keys::TRACESTATE, "vendor=1"),
            (meta_keys::BAGGAGE, "k=v"),
            ("x-vendor-token", "secret"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let mut meta = serde_json::Map::new();
        merge_trace_context(&mut meta, &carrier);

        assert_eq!(meta[meta_keys::TRACEPARENT], "00-abc-def-01");
        assert_eq!(meta[meta_keys::TRACESTATE], "vendor=1");
        assert_eq!(meta[meta_keys::BAGGAGE], "k=v");
        assert!(
            !meta.contains_key("x-vendor-token"),
            "_meta must not carry keys the backend never asked for"
        );
    }

    /// A propagator that produced nothing (sampled-out span, no context) must
    /// not leave empty trace keys behind.
    #[test]
    fn trace_context_absent_leaves_meta_alone() {
        let mut meta = serde_json::Map::new();
        merge_trace_context(&mut meta, &HashMap::new());
        assert!(meta.is_empty());
    }

    /// Telemetry is off in tests, so this also pins the "no telemetry, no
    /// trace keys" behavior on the live request path.
    #[tokio::test]
    async fn stateless_meta_has_no_trace_keys_when_telemetry_is_off() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("tools/list", Reply::Result(json!({"tools": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();

        let meta = &t.request_for("tools/list")["params"]["_meta"];
        assert!(meta.get(meta_keys::TRACEPARENT).is_none());
    }

    // --- the discovery result shape, pinned to the spec ---

    /// The literal example from the spec's `server/discover` page, driven all
    /// the way through negotiation.
    ///
    /// We previously spoke a shape of our own invention — `protocolVersions`
    /// at the top level, `serverInfo` beside it — and every test agreed with
    /// us, because every fixture was written from the same wrong memory. A
    /// 694-test suite went green on a handshake that could not talk to a real
    /// server. This test exists so the next drift fails loudly.
    #[tokio::test]
    async fn discover_result_matches_the_spec_example() {
        let spec_example = json!({
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}, "resources": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "ExampleServer",
                    "version": "1.0.0"
                }
            },
            "instructions": "This server provides weather and resource utilities.",
            "ttlMs": 3_600_000,
            "cacheScope": "public"
        });

        let t = MockTransport::new(vec![("server/discover", Reply::Result(spec_example))]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        assert_eq!(client.protocol_version(), "2026-07-28");
        assert_eq!(t.methods_sent(), vec!["server/discover"]);
        assert!(t.notified().is_empty());
    }

    /// The shape we shipped by mistake must not be accepted as if it were the
    /// real one — it has to fall back, not silently "work".
    #[tokio::test]
    async fn the_pre_release_discover_shape_is_not_accepted() {
        let t = MockTransport::new(vec![
            (
                "server/discover",
                Reply::Result(json!({
                    "protocolVersions": [PROTOCOL_VERSION],
                    "capabilities": {},
                    "serverInfo": {"name": "x", "version": "1"},
                })),
            ),
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
        ]);
        let client = connect_mock(t).await.unwrap();
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION_LEGACY);
    }

    /// `serverInfo` is optional and the spec says never to make behavior
    /// depend on it, so a terse server must still negotiate.
    #[tokio::test]
    async fn discover_without_server_info_still_negotiates() {
        let t = MockTransport::new(vec![(
            "server/discover",
            Reply::Result(json!({
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {},
            })),
        )]);
        let client = connect_mock(t).await.unwrap();
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION);
    }

    // --- the probe request itself ---

    /// The spec's documented probe carries the standard `_meta`; a strict
    /// modern server MUST reject one that does not.
    #[tokio::test]
    async fn the_probe_carries_the_standard_meta() {
        let t = MockTransport::new(vec![("server/discover", discover_ok(&[PROTOCOL_VERSION]))]);
        connect_mock(Arc::clone(&t)).await.unwrap();

        let meta = &t.request_for("server/discover")["params"]["_meta"];
        // The newest revision we speak, not the negotiated one — negotiating
        // is what this request is for.
        assert_eq!(meta[meta_keys::PROTOCOL_VERSION], PROTOCOL_VERSION);
        assert_eq!(meta[meta_keys::CLIENT_INFO]["name"], "mcp");
        assert!(meta.get(meta_keys::CLIENT_CAPABILITIES).is_some());
    }

    /// Sending `_meta` on the probe must not leak onto the legacy path that
    /// follows it.
    #[tokio::test]
    async fn the_probe_meta_does_not_leak_into_the_handshake() {
        let t = MockTransport::new(vec![("initialize", init_ok(PROTOCOL_VERSION_LEGACY))]);
        connect_mock(Arc::clone(&t)).await.unwrap();

        assert!(t.request_for("server/discover")["params"]
            .get("_meta")
            .is_some());
        assert!(t.request_for("initialize")["params"].get("_meta").is_none());
    }

    // --- the probe is bounded, and survivable ---

    /// A peer that simply never answers the unknown method must cost the short
    /// probe budget, not the full request timeout.
    ///
    /// This one really does wait out [`DISCOVER_PROBE_TIMEOUT`] — that is the
    /// point of it — so it is the slowest test here by design.
    #[tokio::test]
    async fn a_silent_probe_falls_back_without_waiting_for_the_request_timeout() {
        /// Answers `server/discover` by hanging forever, like a backend that
        /// ignores a method it never heard of.
        struct SilentProbe(Arc<MockTransport>);

        #[async_trait::async_trait]
        impl Transport for SilentProbe {
            async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
                if msg.method == "server/discover" {
                    std::future::pending::<()>().await;
                }
                self.0.request(msg).await
            }
            async fn notify(&self, msg: &JsonRpcNotification) -> Result<()> {
                self.0.notify(msg).await
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }

        let inner = MockTransport::new(vec![("initialize", init_ok(PROTOCOL_VERSION_LEGACY))]);
        let transport: Arc<dyn Transport> = Arc::new(SilentProbe(Arc::clone(&inner)));
        let mut client = McpClient::new(Arc::clone(&transport), "silent".to_string());

        let started = std::time::Instant::now();
        client
            .negotiate(&|| Ok(Arc::clone(&transport)))
            .await
            .unwrap();

        assert_eq!(client.protocol_version(), PROTOCOL_VERSION_LEGACY);
        assert!(
            started.elapsed() < DISCOVER_PROBE_TIMEOUT * 3,
            "the probe budget must bound this, not the 60s request timeout; took {:?}",
            started.elapsed()
        );
        assert_eq!(inner.notified(), vec!["notifications/initialized"]);
    }

    /// A backend that dies on the unknown method must not take the connection
    /// with it: the fallback handshake runs on a transport we re-opened.
    #[tokio::test]
    async fn a_fatal_probe_reopens_the_transport_before_the_handshake() {
        let dying = MockTransport::new(vec![("server/discover", Reply::Dead)]);
        let fresh = MockTransport::new(vec![("initialize", init_ok(PROTOCOL_VERSION_LEGACY))]);

        let replacement = Arc::clone(&fresh);
        let mut client = McpClient::new(Arc::clone(&dying) as Arc<dyn Transport>, "npx".into());
        client
            .negotiate(&|| Ok(Arc::clone(&replacement) as Arc<dyn Transport>))
            .await
            .unwrap();

        assert_eq!(client.protocol_version(), PROTOCOL_VERSION_LEGACY);
        assert_eq!(
            dying.methods_sent(),
            vec!["server/discover"],
            "the dead transport must not be reused"
        );
        assert_eq!(fresh.methods_sent(), vec!["initialize"]);
        assert_eq!(fresh.notified(), vec!["notifications/initialized"]);
    }

    /// When we cannot re-open either, the error must name the backend and the
    /// probe — a bare "transport closed" gives the operator nothing to act on.
    #[tokio::test]
    async fn an_unrecoverable_fatal_probe_produces_an_actionable_error() {
        let t = MockTransport::new(vec![
            ("server/discover", Reply::Dead),
            ("initialize", Reply::Dead),
        ]);
        let err = match connect_mock_without_reopen(t).await {
            Ok(_) => panic!("a dead transport must not connect"),
            Err(e) => format!("{e:#}"),
        };

        assert!(err.contains("flaky-backend"), "{err}");
        assert!(err.contains("server/discover"), "{err}");
        assert!(err.contains("unknown JSON-RPC method"), "{err}");
    }

    /// A fresh connection failing exactly like the probe did means the probe
    /// killed nothing. Reported from the field: an expired VPN session made
    /// every request redirect to an SSO login, and the error blamed our
    /// compatibility probe instead of the gateway.
    #[test]
    fn an_identical_failure_on_a_fresh_connection_blames_the_backend_not_the_probe() {
        let same = || anyhow!("HTTP 302 Found: the endpoint redirected to sso.example");

        let reopened = fatal_probe_hint("buser", &same(), &same(), true);
        assert!(reopened.contains("unreachable"), "{reopened}");
        assert!(!reopened.contains("unknown JSON-RPC method"), "{reopened}");

        // Without a re-open the handshake ran on the connection the probe
        // killed, so an identical error proves nothing and the probe stays a
        // suspect.
        let not_reopened = fatal_probe_hint("buser", &same(), &same(), false);
        assert!(
            not_reopened.contains("unknown JSON-RPC method"),
            "{not_reopened}"
        );
    }

    /// Different errors keep pointing at the probe, which is the case the hint
    /// was written for.
    #[test]
    fn a_different_failure_after_re_open_still_blames_the_probe() {
        let hint = fatal_probe_hint(
            "flaky",
            &anyhow!("transport closed"),
            &anyhow!("initialize failed: unsupported version"),
            true,
        );
        assert!(hint.contains("server/discover"), "{hint}");
        assert!(hint.contains("unknown JSON-RPC method"), "{hint}");
    }

    // --- MRTR on the other two supported methods ---

    /// The spec's Supported Requests table lists `prompts/get` and
    /// `resources/read` alongside `tools/call`, so all three need a relaying
    /// path that keeps the interim result intact.
    #[tokio::test]
    async fn raw_accessors_preserve_input_required_on_every_supported_method() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ("resources/read", Reply::Result(input_required())),
            ("prompts/get", Reply::Result(input_required())),
        ]);
        let client = connect_mock(t).await.unwrap();

        assert!(is_input_required(
            &client
                .read_resource_raw(json!({"uri": "file:///x"}))
                .await
                .unwrap()
        ));
        assert!(is_input_required(
            &client.get_prompt_raw(json!({"name": "p"})).await.unwrap()
        ));
    }

    /// Paginated `*/list` methods must follow `nextCursor` to the end.
    ///
    /// This used to be covered only by deserializing a `ToolsListResult`
    /// fixture in protocol.rs, which tested serde rather than the cursor
    /// loop. The loop is what actually breaks.
    #[tokio::test]
    async fn list_methods_follow_the_cursor_to_the_last_page() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "tools/list",
                Reply::Pages(vec![
                    json!({"tools": [{"name": "a"}], "nextCursor": "p2"}),
                    json!({"tools": [{"name": "b"}], "nextCursor": "p3"}),
                    json!({"tools": [{"name": "c"}]}),
                ]),
            ),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        let names: Vec<String> = client
            .list_tools()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["a", "b", "c"]);

        // And each page after the first asked for the cursor it was given —
        // the assertion the old fixture test could not make.
        let cursors: Vec<Option<String>> = t
            .sent()
            .iter()
            .filter(|m| m["method"] == "tools/list")
            .map(|m| m["params"]["cursor"].as_str().map(str::to_string))
            .collect();
        assert_eq!(
            cursors,
            vec![None, Some("p2".to_string()), Some("p3".to_string())]
        );
    }

    /// A `nextCursor` that is not a string is a malformed page, not a
    /// silently-ignored one.
    #[tokio::test]
    async fn a_non_string_next_cursor_is_an_error() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "prompts/list",
                Reply::Result(json!({"prompts": [], "nextCursor": 42})),
            ),
        ]);
        let client = connect_mock(t).await.unwrap();
        let err = format!("{:#}", client.list_prompts().await.unwrap_err());
        assert!(err.contains("nextCursor"), "{err}");
    }

    /// The raw paths must not have changed what goes on the wire.
    #[tokio::test]
    async fn raw_accessors_send_the_same_params_as_the_typed_ones() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            ("resources/read", Reply::Result(json!({"contents": []}))),
            ("prompts/get", Reply::Result(json!({"messages": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        client
            .read_resource_raw(json!({"uri": "file:///x"}))
            .await
            .unwrap();
        client
            .get_prompt_raw(json!({"name": "p", "arguments": {"a": 1}}))
            .await
            .unwrap();

        assert_eq!(
            t.request_for("resources/read")["params"],
            json!({"uri": "file:///x"})
        );
        assert_eq!(
            t.request_for("prompts/get")["params"],
            json!({"name": "p", "arguments": {"a": 1}})
        );
    }

    // --- x-mcp-header: rejecting invalid tool definitions ---

    fn tool_with_schema(name: &str, schema: Value) -> Value {
        json!({"name": name, "inputSchema": schema})
    }

    /// List tools against a stateless peer and return the names that survived.
    async fn listed_tool_names(tools: Value) -> Vec<String> {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("tools/list", Reply::Result(json!({"tools": tools}))),
        ]);
        let client = connect_mock(t).await.unwrap();
        client
            .list_tools()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect()
    }

    /// The spec's own example annotation, and the plain tool beside it.
    #[tokio::test]
    async fn valid_x_mcp_header_annotations_are_accepted() {
        let names = listed_tool_names(json!([
            tool_with_schema(
                "execute_sql",
                json!({
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "x-mcp-header": "Region"},
                        "query": {"type": "string"},
                    },
                }),
            ),
            json!({"name": "plain"}),
        ]))
        .await;

        assert_eq!(names, ["execute_sql", "plain"]);
    }

    /// Every constraint the spec puts on an annotation, one bad tool each. The
    /// header name is chosen by the *server*, so an unchecked one is a
    /// header-smuggling primitive — these are the deny cases that matter.
    #[tokio::test]
    async fn invalid_x_mcp_header_annotations_exclude_the_tool() {
        let object = |property: Value| json!({"type": "object", "properties": {"p": property}});

        let cases: Vec<(&str, Value)> = vec![
            (
                "empty",
                object(json!({"type": "string", "x-mcp-header": ""})),
            ),
            (
                "not-a-string",
                object(json!({"type": "string", "x-mcp-header": 7})),
            ),
            // Header injection, straight up.
            (
                "crlf",
                object(json!({"type": "string", "x-mcp-header": "A\r\nX-Injected: 1"})),
            ),
            (
                "bare-lf",
                object(json!({"type": "string", "x-mcp-header": "A\nB"})),
            ),
            (
                "control-char",
                object(json!({"type": "string", "x-mcp-header": "A\u{0}B"})),
            ),
            // Not RFC 9110 token syntax.
            (
                "colon",
                object(json!({"type": "string", "x-mcp-header": "A:B"})),
            ),
            (
                "space",
                object(json!({"type": "string", "x-mcp-header": "A B"})),
            ),
            (
                "non-ascii",
                object(json!({"type": "string", "x-mcp-header": "Região"})),
            ),
            // `number` is explicitly excluded; so is anything non-primitive.
            (
                "number",
                object(json!({"type": "number", "x-mcp-header": "N"})),
            ),
            (
                "array",
                object(json!({"type": "array", "x-mcp-header": "N"})),
            ),
            (
                "object",
                object(json!({"type": "object", "x-mcp-header": "N"})),
            ),
            // A type we cannot see is a type we cannot confirm is primitive.
            ("untyped", object(json!({"x-mcp-header": "N"}))),
            (
                "union-type",
                object(json!({"type": ["string", "null"], "x-mcp-header": "N"})),
            ),
            // Case-insensitively unique.
            (
                "duplicate",
                json!({
                    "type": "object",
                    "properties": {
                        "a": {"type": "string", "x-mcp-header": "Region"},
                        "b": {"type": "string", "x-mcp-header": "REGION"},
                    },
                }),
            ),
            // Not statically reachable through `properties` alone.
            (
                "behind-items",
                object(json!({
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"q": {"type": "string", "x-mcp-header": "Q"}},
                    },
                })),
            ),
            (
                "behind-oneof",
                json!({
                    "type": "object",
                    "oneOf": [{
                        "properties": {"q": {"type": "string", "x-mcp-header": "Q"}},
                    }],
                }),
            ),
            (
                "behind-anyof",
                json!({
                    "anyOf": [{
                        "properties": {"q": {"type": "string", "x-mcp-header": "Q"}},
                    }],
                }),
            ),
            (
                "behind-allof",
                json!({
                    "allOf": [{
                        "properties": {"q": {"type": "string", "x-mcp-header": "Q"}},
                    }],
                }),
            ),
            (
                "behind-not",
                json!({
                    "not": {"properties": {"q": {"type": "string", "x-mcp-header": "Q"}}},
                }),
            ),
            (
                "behind-if-then-else",
                json!({
                    "type": "object",
                    "if": {"properties": {"a": {"type": "string", "x-mcp-header": "A"}}},
                    "then": {"properties": {"b": {"type": "string", "x-mcp-header": "B"}}},
                    "else": {"properties": {"c": {"type": "string", "x-mcp-header": "C"}}},
                }),
            ),
            (
                "behind-a-ref-target",
                json!({
                    "type": "object",
                    "properties": {"p": {"$ref": "#/$defs/annotated"}},
                    "$defs": {
                        "annotated": {"type": "string", "x-mcp-header": "Sneaky"},
                    },
                }),
            ),
            // On the root schema, which is not a property at all.
            (
                "on-the-root",
                json!({"type": "object", "x-mcp-header": "Root", "properties": {}}),
            ),
        ];

        for (label, schema) in cases {
            let names = listed_tool_names(json!([
                tool_with_schema("bad", schema),
                json!({"name": "good"}),
            ]))
            .await;
            assert_eq!(
                names,
                ["good"],
                "{label} must exclude the tool, and only that tool"
            );
        }
    }

    /// A property literally *named* `x-mcp-header` is a property name, not an
    /// annotation — rejecting that tool would be a false positive.
    #[tokio::test]
    async fn a_property_named_like_the_keyword_is_not_an_annotation() {
        let names = listed_tool_names(json!([tool_with_schema(
            "odd",
            json!({
                "type": "object",
                "properties": {"x-mcp-header": {"type": "string"}},
            }),
        )]))
        .await;
        assert_eq!(names, ["odd"]);
    }

    /// The overwhelmingly common case — no annotations anywhere — must be
    /// untouched, on every revision. This is the backwards-compat guarantee
    /// for the rejection rule.
    #[tokio::test]
    async fn tools_without_annotations_are_never_rejected() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "tools/list",
                Reply::Result(json!({"tools": [
                    {"name": "a"},
                    tool_with_schema("b", json!({"type": "object", "properties": {
                        "q": {"type": "string"},
                        "n": {"type": "number"},
                        "nested": {"type": "object", "properties": {"deep": {"type": "string"}}},
                    }})),
                    tool_with_schema("c", json!({"type": "object", "items": {"type": "string"}})),
                ]})),
            ),
        ]);
        let client = connect_mock(t).await.unwrap();

        let names: Vec<String> = client
            .list_tools()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    // --- x-mcp-header: mirroring values into headers ---

    /// End to end: list a tool with the spec's example annotation, call it,
    /// and the header follows.
    #[tokio::test]
    async fn annotated_values_are_mirrored_into_mcp_param_headers() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "execute_sql",
                    json!({
                        "type": "object",
                        "properties": {
                            "region": {"type": "string", "x-mcp-header": "Region"},
                            "rows": {"type": "integer", "x-mcp-header": "Rows"},
                            "dry": {"type": "boolean", "x-mcp-header": "Dry"},
                            "query": {"type": "string"},
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();
        client
            .call_tool(
                "execute_sql",
                json!({"region": "us-west1", "rows": 42, "dry": false, "query": "SELECT 1"}),
            )
            .await
            .unwrap();

        assert_eq!(
            t.headers_for("tools/call"),
            vec![
                ("Mcp-Param-Dry".to_string(), "false".to_string()),
                ("Mcp-Param-Region".to_string(), "us-west1".to_string()),
                ("Mcp-Param-Rows".to_string(), "42".to_string()),
            ]
        );
        // Un-annotated arguments stay in the body only.
        assert!(!t
            .headers_for("tools/call")
            .iter()
            .any(|(name, _)| name.contains("Query")));
    }

    /// Privilege escalation, not cosmetics: a backend that declares a tool
    /// argument annotated with the SAME header the proxy uses to forward the
    /// caller's identity would let the caller pick their own subject. The
    /// forwarded identity has to win, and the argument-derived one has to be
    /// dropped — not appended after it, because a duplicate header is resolved
    /// by the receiver and we do not get to decide how.
    #[tokio::test]
    async fn forwarded_identity_cannot_be_shadowed_by_x_mcp_header() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "publish",
                    json!({
                        "type": "object",
                        "properties": {
                            // O backend tenta reivindicar o header de identidade.
                            "whoami": {"type": "string", "x-mcp-header": "X-MCP-Subject"},
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();

        client
            .call_tool_raw_with(
                json!({"name": "publish", "arguments": {"whoami": "admin"}}),
                &[("X-MCP-Subject".to_string(), "ana".to_string())],
            )
            .await
            .unwrap();

        let headers = t.headers_for("tools/call");
        let subjects: Vec<&String> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-mcp-subject"))
            .map(|(_, value)| value)
            .collect();

        assert_eq!(
            subjects,
            vec!["ana"],
            "a identidade encaminhada tem que ser a ÚNICA, e não a do argumento"
        );
    }

    /// Sem identidade encaminhada, o comportamento do `x-mcp-header` não muda —
    /// a feature é aditiva.
    #[tokio::test]
    async fn call_tool_raw_with_no_extras_behaves_like_call_tool_raw() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "publish",
                    json!({
                        "type": "object",
                        "properties": {
                            "region": {"type": "string", "x-mcp-header": "Region"},
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();

        client
            .call_tool_raw_with(
                json!({"name": "publish", "arguments": {"region": "sa-east1"}}),
                &[],
            )
            .await
            .unwrap();

        assert_eq!(
            t.headers_for("tools/call"),
            vec![("Mcp-Param-Region".to_string(), "sa-east1".to_string())]
        );
    }

    /// A value outside the header-safe set travels as the spec's Base64
    /// sentinel, never raw.
    #[tokio::test]
    async fn mirrored_values_use_the_base64_sentinel_when_needed() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "greet",
                    json!({
                        "type": "object",
                        "properties": {
                            "greeting": {"type": "string", "x-mcp-header": "Greeting"},
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();
        client
            .call_tool("greet", json!({"greeting": "Hello, 世界"}))
            .await
            .unwrap();

        assert_eq!(
            t.headers_for("tools/call"),
            vec![(
                "Mcp-Param-Greeting".to_string(),
                "=?base64?SGVsbG8sIOS4lueVjA==?=".to_string()
            )]
        );
    }

    /// Absent, null and unrepresentable values produce no header at all — a
    /// header that disagrees with the body is a `-32020` rejection.
    #[tokio::test]
    async fn missing_and_unrepresentable_values_send_no_header() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "t",
                    json!({
                        "type": "object",
                        "properties": {
                            "absent": {"type": "string", "x-mcp-header": "Absent"},
                            "nulled": {"type": "string", "x-mcp-header": "Nulled"},
                            "wrong": {"type": "integer", "x-mcp-header": "Wrong"},
                            "huge": {"type": "integer", "x-mcp-header": "Huge"},
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();
        client
            .call_tool(
                "t",
                // `huge` is outside the IEEE754 safe range the spec requires.
                json!({"nulled": null, "wrong": {"not": "a scalar"}, "huge": 9_007_199_254_740_993_i64}),
            )
            .await
            .unwrap();

        assert!(t.headers_for("tools/call").is_empty());
    }

    /// Nested object properties are reachable, so the value is read at the
    /// exact property path rather than by name anywhere in the arguments.
    #[tokio::test]
    async fn nested_properties_are_read_at_their_exact_path() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "t",
                    json!({
                        "type": "object",
                        "properties": {
                            "outer": {
                                "type": "object",
                                "properties": {
                                    "region": {"type": "string", "x-mcp-header": "Region"},
                                },
                            },
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();

        // A same-named argument at the wrong depth must not be picked up.
        client
            .call_tool("t", json!({"region": "decoy", "outer": {"region": "real"}}))
            .await
            .unwrap();

        assert_eq!(
            t.headers_for("tools/call"),
            vec![("Mcp-Param-Region".to_string(), "real".to_string())]
        );
    }

    /// A tool we never listed has no schema, so there is nothing to mirror —
    /// guessing would only earn a header mismatch.
    #[tokio::test]
    async fn an_unlisted_tool_mirrors_nothing() {
        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client
            .call_tool("never_listed", json!({"region": "us-west1"}))
            .await
            .unwrap();

        assert!(t.headers_for("tools/call").is_empty());
    }

    /// Backwards compatibility: `x-mcp-header` arrived with 2026-07-28, so a
    /// legacy peer receives no `Mcp-Param-*` header even if it somehow
    /// annotated a tool. Its tools still list normally.
    #[tokio::test]
    async fn a_legacy_peer_receives_no_param_headers() {
        let t = MockTransport::new(vec![
            ("initialize", init_ok(PROTOCOL_VERSION_LEGACY)),
            (
                "tools/list",
                Reply::Result(json!({"tools": [tool_with_schema(
                    "execute_sql",
                    json!({
                        "type": "object",
                        "properties": {
                            "region": {"type": "string", "x-mcp-header": "Region"},
                        },
                    }),
                )]})),
            ),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();

        assert_eq!(client.list_tools().await.unwrap().len(), 1);
        client
            .call_tool("execute_sql", json!({"region": "us-west1"}))
            .await
            .unwrap();

        assert!(t.headers_for("tools/call").is_empty());
        // And the body is exactly what it always was.
        assert_eq!(
            t.request_for("tools/call")["params"],
            json!({"name": "execute_sql", "arguments": {"region": "us-west1"}})
        );
    }

    /// Annotations are re-learned on every `tools/list`, so one the server has
    /// dropped stops producing a header.
    #[tokio::test]
    async fn dropped_annotations_stop_producing_headers() {
        let annotated = tool_with_schema(
            "t",
            json!({
                "type": "object",
                "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
            }),
        );

        let t = MockTransport::new(vec![
            ("server/discover", discover_ok(&[PROTOCOL_VERSION])),
            ("tools/list", Reply::Result(json!({"tools": [annotated]}))),
            ("tools/call", Reply::Result(json!({"content": []}))),
        ]);
        let client = connect_mock(Arc::clone(&t)).await.unwrap();
        client.list_tools().await.unwrap();
        assert!(!client
            .param_headers("t", &json!({"region": "a"}))
            .is_empty());

        // Same client, a list that no longer annotates anything.
        client.accept_tools(vec![Tool {
            name: "t".to_string(),
            input_schema: Some(json!({"type": "object", "properties": {}})),
            ..Tool::default()
        }]);
        assert!(client
            .param_headers("t", &json!({"region": "a"}))
            .is_empty());
    }

    // --- x-mcp-header: the validator in isolation ---

    #[test]
    fn params_of_reports_paths_and_names() {
        let params = x_mcp_header::params_of(Some(&json!({
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
                },
                "flag": {"type": "boolean", "x-mcp-header": "Flag"},
            },
        })))
        .expect("valid");

        let mut described: Vec<(Vec<String>, String)> =
            params.into_iter().map(|p| (p.path, p.name)).collect();
        described.sort();

        assert_eq!(
            described,
            vec![
                (vec!["flag".to_string()], "Flag".to_string()),
                (
                    vec!["outer".to_string(), "region".to_string()],
                    "Region".to_string()
                ),
            ]
        );
    }

    #[test]
    fn params_of_tolerates_a_missing_or_odd_schema() {
        assert!(x_mcp_header::params_of(None).unwrap().is_empty());
        for schema in [json!({}), json!(null), json!("nonsense"), json!([1, 2])] {
            assert!(
                x_mcp_header::params_of(Some(&schema)).unwrap().is_empty(),
                "{schema} must be tolerated, not rejected"
            );
        }
    }

    /// Every allowed token character, so the validator is not accidentally
    /// stricter than RFC 9110.
    #[test]
    fn every_rfc_9110_token_character_is_accepted() {
        let name = "!#$%&'*+-.^_`|~0123456789AZaz";
        let params = x_mcp_header::params_of(Some(&json!({
            "type": "object",
            "properties": {"p": {"type": "string", "x-mcp-header": name}},
        })))
        .expect("a full token must be accepted");
        assert_eq!(params[0].name, name);
    }

    // --- handshake version resolution ---

    #[test]
    fn agreed_handshake_version_rules() {
        let echo = |v: &str| json!({"protocolVersion": v});

        assert_eq!(
            agreed_handshake_version(Some(&echo("2024-11-05")), PROTOCOL_VERSION_LEGACY),
            "2024-11-05"
        );
        // Unknown, stateless, malformed and absent all fall back to what we
        // asked for — we already ran a handshake, so we are stateful.
        assert_eq!(
            agreed_handshake_version(Some(&echo("2030-01-01")), PROTOCOL_VERSION_LEGACY),
            PROTOCOL_VERSION_LEGACY
        );
        assert_eq!(
            agreed_handshake_version(Some(&echo(PROTOCOL_VERSION)), PROTOCOL_VERSION_LEGACY),
            PROTOCOL_VERSION_LEGACY
        );
        assert_eq!(
            agreed_handshake_version(Some(&json!({"protocolVersion": 5})), "2025-06-18"),
            "2025-06-18"
        );
        assert_eq!(
            agreed_handshake_version(None, PROTOCOL_VERSION_LEGACY),
            PROTOCOL_VERSION_LEGACY
        );
    }
}
