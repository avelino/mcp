# CLI reference

Complete reference for all `mcp` commands.

## Output format

By default, `mcp` detects the output context:

- **Interactive terminal** — human-readable tables with colors
- **Piped or redirected** — JSON (for scripting with `jq`, etc.)

Use `--json` anywhere to force JSON output regardless of context:

```bash
mcp --list --json          # JSON even in terminal
mcp sentry --list --json   # JSON tool list
```

## Global commands

### `mcp --help`, `mcp -h`

Show usage information.

### `mcp --list`

List all configured servers.

```bash
mcp --list
```

Interactive output:

```
Server     Type   Endpoint
sentry     http   https://mcp.sentry.dev/sse
slack      stdio  npx -y slack-mcp-server@latest
grafana    stdio  uvx mcp-grafana

3 server(s) configured
```

JSON output (`--json` or piped):

```json
[
  { "name": "sentry", "type": "http", "url": "https://mcp.sentry.dev/sse" },
  { "name": "slack", "type": "stdio", "command": "npx", "args": ["-y", "slack-mcp-server@latest"] }
]
```

## Global flags

### `--json`

Force JSON output. Can be placed anywhere in the command:

```bash
mcp --json --list
mcp sentry --list --json
mcp sentry search_issues '{"query": "..."}' --json
```

## Server commands

### `mcp <server> --list`

Connect to the server and list available tools.

```bash
mcp sentry --list
```

Interactive output:

```
Tool                  Description
search_issues         Search for issues in Sentry
get_issue_details     Get details of a specific issue
search_events         Search events in a project

3 tool(s) available
```

If the server name alone is provided (no flags, no tool), this is the default behavior:

```bash
mcp sentry          # same as mcp sentry --list
```

### `mcp <server> --info`

Like `--list`, but includes parameter details for each tool.

```bash
mcp sentry --info
```

Interactive output:

```
search_issues
  Search for issues in Sentry
  Parameters:
    query string — The search query (required)
    project string — Project slug
    sort string — Sort order

get_issue_details
  Get details of a specific issue
  Parameters:
    issue_id string — The issue ID (required)

2 tool(s) available
```

JSON output includes full JSON Schema for each tool's input parameters.

### `mcp <server> <tool> [json]`

Call a tool on the server. The optional `json` argument is a JSON object with the tool's parameters.

```bash
mcp sentry search_issues '{"query": "is:unresolved"}'
```

If `json` is omitted:
- **Interactive terminal** — Uses `{}` (empty object)
- **Piped input** — Reads JSON from stdin

Interactive output prints text content directly:

```
Found 23 issues matching query "is:unresolved level:error"
```

Errors are prefixed with `error:` on stderr.

JSON output wraps content in the MCP protocol format:

```json
{
  "content": [
    { "type": "text", "text": "Found 23 issues..." }
  ],
  "isError": false
}
```

Content items have a `type` field:
- `"text"` — Text content in the `text` field
- `"image"` — Base64-encoded image in `data` field, with `mimeType`
- `"resource"` — Embedded resource content

## Proxy commands

### `mcp serve`

Start a proxy server that aggregates all configured backends into a single MCP endpoint.

```bash
mcp serve               # stdio mode (default)
mcp serve --http        # HTTP mode on 127.0.0.1:8080
mcp serve --http :9090  # HTTP mode on custom port
mcp serve --http 0.0.0.0:8080 --insecure  # HTTP on all interfaces
```

The proxy connects to every server in `servers.json`, merges their tool lists with namespaced names (`server__tool`), and routes `tools/call` requests to the correct backend.

#### Stdio mode (default)

Designed to be used as a stdio transport in any MCP client:

```json
{
  "mcpServers": {
    "all": {
      "command": "mcp",
      "args": ["serve"]
    }
  }
}
```

Diagnostics are logged to stderr. Protocol messages use stdin/stdout.

#### HTTP mode (`--http`)

Exposes the proxy over HTTP with the following endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | JSON-RPC 2.0 request/response endpoint |
| `GET` | `/mcp/sse` | SSE endpoint for streaming (per MCP spec) |
| `GET` | `/health` | Health check (returns JSON status, see below) |

Default bind address is `127.0.0.1:8080` (localhost only). To bind to a different address:

```bash
mcp serve --http 127.0.0.1:9090
mcp serve --http :3000              # shorthand for 0.0.0.0:3000 — requires --insecure
```

#### `--insecure`

Allow binding to non-loopback addresses without TLS. Required when using addresses like `0.0.0.0`, `192.168.x.x`, etc. Without this flag, the server refuses to start on non-loopback interfaces to prevent accidental plaintext exposure.

#### Health check (`GET /health`)

Returns the proxy status as JSON:

```json
{
  "status": "ok",
  "backends_configured": 9,
  "backends_connected": 3,
  "active_clients": 5,
  "tools": 213,
  "version": "0.4.3"
}
```

| Field | Description |
|-------|-------------|
| `status` | Always `"ok"` |
| `backends_configured` | Total servers in `servers.json` |
| `backends_connected` | Backends currently running (others are idle-shutdown or not yet connected) |
| `active_clients` | Number of SSE sessions currently registered |
| `tools` | Total tools across all backends (including idle ones — tools are cached) |
| `version` | `mcp` binary version |

`backends_connected` should **not** grow with `active_clients` — that's the proxy doing its job (N clients sharing M backends). If they grow together, clients may be bypassing the proxy.

#### Graceful shutdown

The HTTP server handles `SIGTERM` and `SIGINT` (Ctrl+C) gracefully: stops accepting new connections, finishes in-flight requests, and disconnects all backends.

See **[Proxy mode guide](../guides/proxy-mode.md)** for full details, client configuration examples, and team setup.

## Registry commands

### `mcp search <query>`

Search the MCP server registry.

```bash
mcp search filesystem
mcp search "database sql"
```

Interactive output shows a table of matching servers. JSON output returns full server metadata including repository URL and install instructions.

### `mcp add <name>`

Add a server from the registry. Looks up the server by name, generates a config entry, and writes it to `servers.json`.

```bash
mcp add filesystem
```

Fails if:
- Server not found in registry
- Server already exists in config
- Name is reserved (`search`, `add`, `remove`, `list`, `help`, `version`)

### `mcp add --url <url> <name>`

Add an HTTP server manually.

```bash
mcp add --url https://api.example.com/mcp my-server
```

### `mcp remove <name>`

Remove a server from the config file.

```bash
mcp remove filesystem
```

Fails if the server is not in the config.

### `mcp update <name>`

Refresh a server's config entry from the registry, preserving your customizations.

```bash
mcp update github
```

Use this when the registry metadata for a server changed (new package version, new env vars, updated args) and you want to pull the changes without losing what you customized locally.

**What gets refreshed (from the registry):**
- `command` and `args`
- `url` (HTTP servers)
- `env` schema — new vars are added as `${VAR_NAME}` placeholders, vars removed from the registry are dropped

**What is preserved (your customizations):**
- Filled-in `env` values (anything that isn't a `${VAR_NAME}` placeholder)
- `idle_timeout`, `min_idle_timeout`, `max_idle_timeout`
- `headers` (HTTP servers)
- `cli`, `cli_help`, `cli_depth`, `cli_only`, `tools`

If the entry already matches the registry, the file is not rewritten and `mcp` reports `already up to date`. New env vars introduced by the update are listed at the end so you know what to fill in.

Fails if:
- Server is not in the local config (use `mcp add <name>` first)
- Server is not in the registry

> If the server changed type in the registry (stdio ↔ http), `mcp update` warns and drops type-specific fields that no longer apply.

## ACL commands

### `mcp acl classify`

Classify every tool of every configured backend as `read`, `write`, or
`ambiguous`, using the automatic classifier combined with manual
`tool_acl` overrides from `servers.json`. This is metadata only — no
enforcement path changes yet.

```bash
mcp acl classify                      # all servers, table output
mcp acl classify --server grafana     # one server
mcp acl classify --format json        # machine-readable
```

**Flags:**
- `--server <alias>` — restrict to one backend
- `--format table|json` — override the auto-detected output format

**Table columns:**

| Column | Meaning |
|---|---|
| `SERVER` | Backend alias |
| `TOOL` | Upstream tool name (not namespaced) |
| `KIND` | `read`, `write`, or `ambiguous` |
| `CONF` | Classifier confidence (0.00–1.00) |
| `SOURCE` | `override`, `annotation`, `classifier`, or `fallback` |
| `reasons` | Which signals fired (name tokens, description patterns, schema hints) |

Rows prefixed with `[!]` are **ambiguous** — the classifier could not
decide. They are treated as `write` at runtime (fail-safe). Add a
`tool_acl` entry in `servers.json` to pin them explicitly.

**Example (JSON):**

```bash
mcp acl classify --server databricks --format json | jq '.[] | {tool, kind}'
```

The JSON form is an array of `{server, tool, kind, confidence, source, reasons}` objects, suitable for scripting or diffing across config changes.

See [Tool ACL overrides](./config-file.md#tool-acl-overrides) for how to pin tools manually, and [`docs/acl-redesign-plan.md`](../acl-redesign-plan.md) for the full redesign context.

### `mcp acl check`

Test an ACL decision without starting the proxy. Useful for validating
policy changes before rolling them out.

```bash
mcp acl check --subject alice --server grafana --tool query_prometheus
mcp acl check --subject bob --server databricks --tool execute_sql --access write
mcp acl check --role dev --server github --all-tools
mcp acl check --subject alice --server github --all-tools --format json
```

**Flags:**
- `--subject <name>` — subject to check (looks up roles from `subjects` map in ACL config)
- `--server <alias>` — backend server alias (required)
- `--tool <name>` — single tool to check (required unless `--all-tools`)
- `--access read|write` — override the tool classification (if omitted, the CLI connects to the backend to classify the tool automatically)
- `--role <name>` — check a hypothetical role (creates a synthetic identity)
- `--all-tools` — connect to the backend, list all tools, and check each one
- `--format table|json` — override the auto-detected output format

**Single-tool output:**

```
ALLOW  via dev[0]  access=read  classification=classifier:read (confidence 0.72)
```

**Multi-tool output (`--all-tools`):**

```
TOOL                                     DECISION RULE                      ACCESS KIND       SOURCE      CONF
query_prometheus                         ALLOW  dev[0]                    read   read       classifier  0.72
update_dashboard                         DENY   default                   -      write      classifier  0.81
```

**Exit code:** `0` for allow, `1` for deny (single-tool mode only).
`--all-tools` always exits `0` since mixed results are expected.

**Examples:**

```bash
# CI pre-deploy check: ensure dev role can read grafana
mcp acl check --role dev --server grafana --tool query_prometheus || echo "BLOCKED"

# Audit what a role can reach on a server
mcp acl check --role dev --server github --all-tools --format json | jq '.[] | select(.decision=="DENY")'
```
