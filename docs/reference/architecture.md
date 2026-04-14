# Architecture

How `mcp` works internally. Read this if you want to contribute, debug an issue, or just understand what happens when you run a command.

## The big picture

When you run `mcp sentry search_issues '{"query": "is:unresolved"}'`, this is what happens:

```
1. Parse CLI args → server="sentry", tool="search_issues", args={...}
2. Load config → find "sentry" in servers.json → it's an HTTP server
3. Create transport → HttpTransport with the server URL
4. Load saved auth token (if any)
5. MCP handshake:
   → Send "initialize" request with protocol version
   ← Receive server capabilities
   → Send "notifications/initialized"
6. Send "tools/call" request with tool name and arguments
   ← If 401: start OAuth flow → retry with new token
   ← Receive tool result
7. Print JSON result to stdout
8. Close transport
```

The whole thing is a single async pipeline. No daemon, no background process, no state between runs (except saved tokens).

## Transport: the core abstraction

The most important design decision is the `Transport` trait:

```rust
trait Transport: Send + Sync {
    async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn notify(&self, msg: &JsonRpcNotification) -> Result<()>;
    async fn close(&self) -> Result<()>;
}
```

Note the `&self` (not `&mut self`) and the `Sync` bound. This is what makes the proxy non-blocking under load: a single transport instance can be shared across many concurrent tasks via `Arc<dyn Transport>`, and each implementation uses interior mutability (channels, atomics, mutexes) for the small amount of state it needs to mutate. There is no global lock around the client.

Three implementations:

**StdioTransport** — Spawns a child process and runs it as a multiplexed pipe. A dedicated **writer task** owns the child's stdin and serializes outbound writes. A dedicated **reader task** consumes the child's stdout line-by-line and dispatches each response to its caller via a `oneshot` channel keyed by JSON-RPC `id`. The result: **multiple in-flight requests can run concurrently on the same backend process** — callers only block waiting for their own response. The child is spawned with `kill_on_drop(true)` so it is reaped on any cleanup path (graceful shutdown, panic, task abort, error). On `close()` the child gets a brief grace period and is then force-killed.

**HttpTransport** — Sends HTTP POST requests with JSON-RPC bodies. Handles SSE (Server-Sent Events) responses by extracting the last `data:` line. Manages session IDs via `Mcp-Session-Id` headers. On 401 responses, triggers the authentication flow and retries once. Mutable state (`session_id`, `bearer_token`, `headers` after a 401) lives behind small `Mutex`es; `reqwest::Client` is already `Send + Sync`, so concurrent requests fan out at the HTTP layer.

**CliTransport** — Wraps any command-line tool as an MCP server (see [CLI as MCP](../guides/cli-as-mcp.md)). Discovery state lives behind an `RwLock` with double-checked locking, and each tool invocation spawns a fresh `Command` with `kill_on_drop(true)` so cancellation reaps the child instead of leaking it.

`McpClient` wraps the transport in `Arc<dyn Transport>` and uses an `AtomicU64` for request id generation, so a single `Arc<McpClient>` is safe to share across any number of tasks. Adding a new transport (WebSocket, for example) means implementing the three trait methods — nothing else changes.

## Authentication: layered fallbacks

Auth only applies to HTTP servers. The strategy is a cascade:

1. **Config headers** — If `servers.json` has an `Authorization` header with a non-empty token, use it
2. **Saved token** — On connect, load token from `auth.json` (if valid and not expired)
3. **OAuth 2.0** — On 401 response:
   - Discover the authorization server (RFC 9728 Protected Resource Metadata → `.well-known/oauth-authorization-server`)
   - Register as a client (Dynamic Client Registration)
   - Run Authorization Code flow with PKCE (S256)
   - Open browser, listen for callback on localhost:8085-8099
   - Exchange code for tokens, save them
4. **Manual prompt** — If OAuth registration fails, ask the user for a token interactively. Show service-specific hints for known services (Sentry, GitHub, Slack, etc.)

Tokens are stored per server URL (normalized, trailing slash stripped). Refresh tokens are used automatically when access tokens expire.

## Protocol: JSON-RPC 2.0 over MCP

`mcp` implements a subset of the [Model Context Protocol](https://spec.modelcontextprotocol.io/):

**Handshake:**
- `initialize` → Server responds with capabilities
- `notifications/initialized` → Client confirms it's ready

**Tool operations:**
- `tools/list` → Returns available tools (with pagination via cursor)
- `tools/call` → Execute a tool with arguments, get results

**Resource operations:**
- `resources/list` → Returns available resources, aggregated across upstreams
- `resources/read` → Read a specific resource by URI

**Prompt operations:**
- `prompts/list` → Returns available prompts, aggregated across upstreams
- `prompts/get` → Get a specific prompt by name (with optional arguments)

All three categories use the same `{server}__{name}` aliasing to keep items from different upstreams distinguishable. Sampling and other MCP features are not implemented.

Responses follow the MCP content model: an array of content items, each with a type (`text`, `image`) and corresponding data. The `isError` flag indicates tool-level errors (distinct from protocol errors).

## Config: untagged enum deserialization

Server configs use serde's untagged enum:

```rust
enum ServerConfig {
    Stdio { command, args, env, idle_timeout, min_idle_timeout, max_idle_timeout },
    Http { url, headers, idle_timeout, min_idle_timeout, max_idle_timeout },
}
```

Serde tries each variant in order. If the JSON has `command`, it's Stdio. If it has `url`, it's HTTP. This means the config file doesn't need a `type` field — the structure itself determines the type.

Environment variable substitution (`${VAR}`) happens at config load time via regex replacement, before JSON parsing. Missing vars become empty strings.

## Registry: search and scaffold

The registry integration is straightforward:
- Search the [official MCP registry API](https://registry.modelcontextprotocol.io/v0.1/servers) by query
- Find a server by exact name
- Generate a config entry from registry metadata (command, args, env var placeholders)

When adding from registry, packages (stdio) take priority over remotes (HTTP). Environment variables get `${VAR}` placeholders so the user sets them in their shell.

## Output: dual format (Text + JSON)

Output adapts to the context automatically via `OutputFormat::detect()`:

- **Interactive terminal** — colored tables with `comfy-table`, styled text with `console` crate
- **Piped or redirected** — JSON for composability with `jq`
- **`--json` flag** — forces JSON output regardless of context

All output functions return `Result` and write to stdout. Errors and status messages go to stderr. This separation is critical for scripting — `stdout` is always valid structured data, `stderr` is for humans.

For tool call results, text content prints directly in interactive mode. Images show a `[image: mime/type]` placeholder. Validation errors from MCP servers (e.g. Sentry-style structured errors) are parsed and reformatted into readable per-field messages with colored highlighting. JSON mode wraps everything in the MCP protocol format (`content` array + `isError` flag).

## Proxy mode: `mcp serve`

The proxy inverts the CLI's role — instead of being a **client** that talks to one server, it becomes a **server** that talks to many.

```
MCP Client  ←stdin/stdout→  mcp serve  ←→  backend 1 (stdio)
                                        ←→  backend 2 (http)
                                        ←→  backend N
```

Backends are managed lazily with a persistent tool cache. On startup, the proxy loads previously discovered tools from a local [ChronDB](https://chrondb.avelino.run/) database and serves them immediately — no backend connections needed. A background task then connects to all backends to refresh the cache. On first run (no cache), `tools/list` blocks on full discovery as a fallback. On `tools/call`, the proxy infers the target backend from the namespaced name (`server__tool`) and discovers **only that backend** if it hasn't been seen yet — other backends are not touched. This means a call to `gh__issue` only waits for the `gh` backend, not for every other server to finish discovery. If the backend cannot be inferred (e.g. a non-namespaced tool name), the proxy falls back to discovering all pending backends.

Cache invalidation is per-backend via SHA-256 hash of the raw config JSON. If a backend's config changes in `servers.json`, its cached tools are discarded and re-discovered. The cache and audit log share a single [ChronDB](https://chrondb.avelino.run/) database (`~/.config/mcp/db/`), separated by key prefix (`cache:tools:*` vs `audit:*`).

Each backend tracks usage statistics: request count, first/last use timestamps, and an exponential moving average (EMA) of inter-request intervals. A background reaper task runs every 30 seconds and shuts down backends that exceed their idle timeout. The timeout is adaptive by default — frequently used backends (>20 req/h) get 5 minutes, moderately used (5-20 req/h) get 3 minutes, and rarely used (<5 req/h) get 1 minute. Users can override this per backend with fixed timeouts or `"never"`.

A **warm-up grace period** protects freshly-connected backends: a backend with `request_count == 0` is never reaped before its `max_idle_timeout` elapses, so the proxy doesn't kill a backend you haven't gotten around to using yet. Without this, the proxy would reap idle backends ~60 seconds after start and the very first real `tools/call` would always pay a full reconnect.

When the reaper does fire, it shuts down all eligible backends **in parallel** via a `tokio::task::JoinSet`. If a backend's graceful `shutdown()` doesn't finish within 5 seconds, the reaper drops the `Arc<McpClient>` and `kill_on_drop(true)` force-reaps the child — orphaned backend processes are not possible by construction.

When a backend is shut down, its tools remain in the tool list (cached in memory and on disk). On the next `tools/call` targeting that backend, the proxy transparently reconnects, refreshes the tool cache, and forwards the request. Usage stats are preserved across reconnections for adaptive timeout continuity.

The proxy reuses the same `McpClient` and `Transport` abstractions — no new protocol code was needed. It just listens on stdin instead of connecting to a server's stdin.

Error handling is partial-availability: if one backend fails to connect, the others still work. If a backend dies mid-session, the proxy returns an MCP-level error for that tool call without crashing.

### Concurrency model

The proxy is the orchestrator for **N concurrent clients sharing the same set of backends**. The whole pipeline is built so that no single client, request, or backend can wedge any of the others.

Backends are pooled by name in a `HashMap<String, BackendState>` inside `ProxyServer`, and each connected backend is held as `Arc<McpClient>`. A request flows through `dispatch_request` in three carefully scoped phases:

1. **Resolve (under a brief proxy lock)** — look up the namespaced tool in `tool_map`, run the ACL check, and clone the `Arc<McpClient>` out of `BackendState::Connected`. The lock is released before any I/O.
2. **Connect (without the proxy lock)** — if no client exists yet, `connect_backend()` spawns the child, runs the MCP handshake and `tools/list`, and only then briefly re-acquires the lock to install the new client (deduplicating against any concurrent connector).
3. **Invoke (without the proxy lock)** — `client.call_tool().await` runs entirely outside the proxy lock. Because `McpClient` and `Transport` are `&self`, the same `Arc<McpClient>` is invoked in parallel by every concurrent caller; the stdio multiplexer described above handles fan-in/fan-out by id.

Discovery — the act of connecting to a previously-unseen backend and listing its tools — used to run **under** the proxy lock, which meant a single slow backend (e.g. a 30-second OAuth handshake) could wedge every other client until it returned. That is fixed by a separate `discovery_lock: Arc<Mutex<()>>` on `ProxyServer`. Discovery batches now snapshot the pending set under a brief lock, drop the proxy lock, run all the connect attempts in parallel **without** holding the proxy mutex, and only re-acquire the lock briefly to commit each result. Two callers that both want to discover are serialized on the discovery lock (so they don't double-spawn), but request handlers targeting already-discovered backends fly through with zero contention while a discovery batch is in progress.

For single-item requests (`tools/call`, `resources/read`, `prompts/get`), the proxy uses **per-server lazy discovery**: it infers the target backend from the namespaced name and calls `discover_single_backend` instead of `discover_pending_backends`. This means the request discovers only the needed server rather than proactively discovering kubectl, grafana, or every other pending backend. However, `discover_single_backend` still runs under the same shared `discovery_lock`, so it can wait behind another discovery already in progress. Full batch discovery is reserved for listing operations (`tools/list`, `resources/list`, `prompts/list`) where the client expects the complete catalog.

The HTTP+SSE legacy transport has its own backpressure trap: each client session is fed by a bounded `mpsc` channel, and a slow consumer can fill the buffer. The POST handler bounds its `tx.send(...)` with a 5s timeout — on failure or timeout, the session is **evicted** from the session map and the client is expected to reconnect. The SSE keepalive ping background task uses `try_send` instead of `send().await` so a momentarily-full buffer never blocks it; after ~1 minute of consecutive full-buffer pings the session is also evicted as wedged.

Practical consequences:

- Calls to **different** backends are fully parallel.
- Calls to the **same** backend are also parallel — they fan out through one shared process via the stdio multiplexer (or through `reqwest`'s native concurrency for HTTP backends). One backend = one OS process, regardless of how many clients are connected.
- A slow or hung backend only delays the requests targeting it. Other clients keep moving.
- A slow discovery (e.g. an unreachable backend hitting its 30s timeout) blocks only other callers that also need discovery for the same backend. A `tools/call` for a different backend discovers only its target — it is not delayed by the slow one. Already-discovered backends keep serving requests normally.
- A dead client only loses its own request. The HTTP listener is bound with TCP keepalive (30s idle / 10s interval) so half-open sockets from crashed clients are detected within ~60s, and `MCP_PROXY_REQUEST_TIMEOUT` (default 120s) is a final hard bound at the proxy boundary.
- A client request that is cancelled mid-flight cleans up after itself: the future is dropped, any spawned child process is reaped via `kill_on_drop`, and the backend's pending-request map is cleared by the reader task on EOF.

### Server-side authentication

The proxy supports an optional authentication layer for HTTP mode, designed to be transport-independent:

```
HTTP headers → extract_credentials() → Credentials (HashMap)
                                            ↓
                                    AuthProvider.authenticate()
                                            ↓
                                    AuthIdentity { subject, roles }
                                            ↓
                                    ACL.is_tool_allowed()
```

The `AuthProvider` trait and `AuthIdentity` type are transport-agnostic — only `extract_credentials()` knows about HTTP headers. This means the same auth logic works across any transport. Stdio mode always uses `AuthIdentity::anonymous()`.

Three providers are available: `NoAuth` (default), `BearerTokenAuth` (static token mapping), and `ForwardedUserAuth` (reverse proxy header trust). The ACL system filters `tools/list` responses and blocks unauthorized `tools/call` requests before they reach backends.

## Design principles

- **No daemon** — Each invocation is independent. Start, connect, do the thing, exit. Tokens are persisted to disk, everything else is ephemeral.
- **Lazy by default** — In proxy mode, backends are only connected when needed and shut down when idle. No process runs longer than it has to. Tool lists are cached to disk so restarts don't pay the discovery cost again.
- **Protocol over implementation** — The Transport trait means the client code is completely decoupled from transport details. Adding WebSocket support is adding a file, not refactoring the client.
- **Fail loud** — Errors propagate up with context (`anyhow` chains). No silent failures, no swallowed errors, no default fallbacks that hide problems.
- **JSON in, JSON out** — The CLI is a pipe-friendly citizen. Structured input, structured output, errors on stderr.
