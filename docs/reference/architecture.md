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
trait Transport: Send {
    async fn request(&mut self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn notify(&mut self, msg: &JsonRpcNotification) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}
```

Everything in the client uses this interface. It doesn't know if it's talking to a subprocess or a remote server. Two implementations:

**StdioTransport** — Spawns a child process, sends JSON-RPC messages to its stdin, reads responses from stdout. Handles line-by-line parsing, skips server notifications (messages without `id`), and applies a configurable timeout.

**HttpTransport** — Sends HTTP POST requests with JSON-RPC bodies. Handles SSE (Server-Sent Events) responses by extracting the last `data:` line. Manages session IDs via `Mcp-Session-Id` headers. On 401 responses, triggers the authentication flow and retries once.

The client wraps the transport in a `Box<dyn Transport>`, so adding a new transport (WebSocket, for example) means implementing three methods — nothing else changes.

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

That's all the CLI needs. It doesn't implement resources, prompts, sampling, or other MCP features — just tools.

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

## Output: JSON everywhere

All output functions return `Result` and write to stdout. Errors and status messages go to stderr. This separation is critical for scripting — `stdout` is always valid JSON, `stderr` is for humans.

The output module doesn't do any filtering or transformation. It formats the raw protocol data as pretty-printed JSON. Users can pipe to `jq` for whatever processing they need.

## Proxy mode: `mcp serve`

The proxy inverts the CLI's role — instead of being a **client** that talks to one server, it becomes a **server** that talks to many.

```
MCP Client  ←stdin/stdout→  mcp serve  ←→  backend 1 (stdio)
                                        ←→  backend 2 (http)
                                        ←→  backend N
```

Backends are managed lazily with a persistent tool cache. On startup, the proxy loads previously discovered tools from a local [ChronDB](https://chrondb.avelino.run/) database and serves them immediately — no backend connections needed. A background task then connects to all backends to refresh the cache. On first run (no cache), `tools/list` blocks on discovery as a fallback. On `tools/call`, the proxy splits the namespaced name (`server__tool`), ensures the target backend is connected (reconnecting on demand if it was shut down), and forwards the request.

Cache invalidation is per-backend via SHA-256 hash of the raw config JSON. If a backend's config changes in `servers.json`, its cached tools are discarded and re-discovered. The cache and audit log share a single [ChronDB](https://chrondb.avelino.run/) database (`~/.config/mcp/db/`), separated by key prefix (`cache:tools:*` vs `audit:*`).

Each backend tracks usage statistics: request count, first/last use timestamps, and an exponential moving average (EMA) of inter-request intervals. A background reaper task runs every 30 seconds and shuts down backends that exceed their idle timeout. The timeout is adaptive by default — frequently used backends (>20 req/h) get 5 minutes, moderately used (5-20 req/h) get 3 minutes, and rarely used (<5 req/h) get 1 minute. Users can override this per backend with fixed timeouts or `"never"`.

When a backend is shut down, its tools remain in the tool list (cached in memory and on disk). On the next `tools/call` targeting that backend, the proxy transparently reconnects, refreshes the tool cache, and forwards the request. Usage stats are preserved across reconnections for adaptive timeout continuity.

The proxy reuses the same `McpClient` and `Transport` abstractions — no new protocol code was needed. It just listens on stdin instead of connecting to a server's stdin.

Error handling is partial-availability: if one backend fails to connect, the others still work. If a backend dies mid-session, the proxy returns an MCP-level error for that tool call without crashing.

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
