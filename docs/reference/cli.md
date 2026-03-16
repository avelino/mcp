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
sentry     http   https://mcp.sentry.dev/mcp
slack      stdio  npx -y slack-mcp-server@latest
grafana    stdio  uvx mcp-grafana

3 server(s) configured
```

JSON output (`--json` or piped):

```json
[
  { "name": "sentry", "type": "http", "url": "https://mcp.sentry.dev/mcp" },
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
