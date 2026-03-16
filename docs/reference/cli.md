# CLI reference

Complete reference for all `mcp` commands.

## Global commands

### `mcp --help`, `mcp -h`

Show usage information.

### `mcp --list`

List all configured servers. Output is a JSON array.

```bash
mcp --list
```

```json
[
  { "name": "sentry", "type": "http", "url": "https://mcp.sentry.dev/sse" },
  { "name": "slack", "type": "stdio", "command": "npx", "args": ["-y", "slack-mcp-server@latest"] }
]
```

## Server commands

### `mcp <server> --list`

Connect to the server and list available tools. Output is a JSON array of tool names and descriptions.

```bash
mcp sentry --list
```

If the server name alone is provided (no flags, no tool), this is the default behavior:

```bash
mcp sentry          # same as mcp sentry --list
```

### `mcp <server> --info`

Like `--list`, but includes the full JSON Schema for each tool's input parameters.

```bash
mcp sentry --info
```

```json
[
  {
    "name": "search_issues",
    "description": "Search for issues",
    "inputSchema": {
      "type": "object",
      "properties": {
        "query": { "type": "string" }
      },
      "required": ["query"]
    }
  }
]
```

### `mcp <server> <tool> [json]`

Call a tool on the server. The optional `json` argument is a JSON object with the tool's parameters.

```bash
mcp sentry search_issues '{"query": "is:unresolved"}'
```

If `json` is omitted:
- **Interactive terminal** — Uses `{}` (empty object)
- **Piped input** — Reads JSON from stdin

Output is a JSON object with `content` array and optional `isError` flag:

```json
{
  "content": [
    { "type": "text", "text": "..." }
  ],
  "isError": false
}
```

Content items have a `type` field:
- `"text"` — Text content in the `text` field
- `"image"` — Base64-encoded image in `data` field, with `mimeType`

## Registry commands

### `mcp search <query>`

Search the MCP server registry.

```bash
mcp search filesystem
mcp search "database sql"
```

Returns a JSON array of matching servers with name, description, repository URL, and install instructions.

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
