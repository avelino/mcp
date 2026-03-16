# mcp

CLI that turns [MCP servers](https://modelcontextprotocol.io/) into terminal commands.

```
mcp sentry search_issues '{"query": "is:unresolved level:error"}'
```

No SDKs. No wrapper code. One binary, any MCP server.

## What it does

MCP (Model Context Protocol) servers expose tools — search issues, query logs, send messages, read files. This CLI lets you call those tools directly from your terminal. You configure a server once, then use it like any other command.

```
$ mcp slack list_channels
$ mcp grafana search_dashboards '{"query": "api-latency"}'
$ mcp sentry get_issue_details '{"issue_id": "12345"}'
```

Output is always JSON. Pipe it, `jq` it, script it.

## Quick start

**Install:**

```bash
# Homebrew (macOS and Linux)
brew install avelino/mcp/mcp

# Docker
docker pull ghcr.io/avelino/mcp
alias mcp='docker run --rm -v ~/.config/mcp:/root/.config/mcp ghcr.io/avelino/mcp'

# Pre-built binary from GitHub Releases
# Download the latest from https://github.com/avelino/mcp/releases

# From source (requires Rust)
cargo install --path .
```

**Add a server from the registry:**

```bash
mcp add filesystem
```

**Or add an HTTP server manually:**

```bash
mcp add --url https://mcp.sentry.dev/sse sentry
```

**See what tools are available:**

```bash
mcp sentry --list
```

**Call a tool:**

```bash
mcp sentry search_issues '{"query": "is:unresolved"}'
```

That's it. You're using MCP.

## How it works

```
You  -->  mcp CLI  -->  MCP Server  -->  Service API
              |
         servers.json
```

The CLI reads your config (`~/.config/mcp/servers.json`), connects to the server using stdio or HTTP, and speaks [JSON-RPC 2.0](https://www.jsonrpc.org/specification) to call tools. Authentication (OAuth 2.0, API tokens) is handled automatically.

## Configuration

Servers live in `~/.config/mcp/servers.json`:

```json
{
  "mcpServers": {
    "slack": {
      "command": "npx",
      "args": ["-y", "slack-mcp-server@latest", "--transport", "stdio"],
      "env": {
        "SLACK_MCP_XOXP_TOKEN": "${SLACK_TOKEN}",
        "SLACK_MCP_TEAM_ID": "${SLACK_TEAM_ID}"
      }
    },
    "sentry": {
      "url": "https://mcp.sentry.dev/sse"
    }
  }
}
```

Two types of servers:
- **Stdio** — the CLI spawns a local process (`command` + `args`)
- **HTTP** — the CLI connects to a remote URL (`url` + optional `headers`)

Environment variables use `${VAR_NAME}` syntax and are resolved at runtime.

## Authentication

For HTTP servers that require auth, `mcp` handles it automatically:

1. **OAuth 2.0** — If the server supports it, `mcp` opens your browser, completes the flow, and saves the token
2. **Manual token** — If OAuth isn't available, it guides you to get a token with service-specific instructions
3. **Config headers** — You can set `Authorization` headers directly in config

Tokens are saved in `~/.config/mcp/auth.json` and refreshed automatically.

## Commands

| Command | Description |
|---|---|
| `mcp --list` | List configured servers |
| `mcp <server> --list` | List available tools |
| `mcp <server> --info` | List tools with input schemas |
| `mcp <server> <tool> [json]` | Call a tool |
| `mcp search <query>` | Search the MCP server registry |
| `mcp add <name>` | Add a server from registry |
| `mcp add --url <url> <name>` | Add an HTTP server |
| `mcp remove <name>` | Remove a server |
| `mcp serve` | Start proxy — all servers as one MCP endpoint |
| `mcp logs` | Show audit log entries |
| `mcp logs --errors` | Show only failures |
| `mcp logs -f` | Follow mode — stream new entries live |

## Piping JSON from stdin

If you don't pass JSON arguments on the command line, `mcp` reads from stdin:

```bash
echo '{"query": "is:unresolved"}' | mcp sentry search_issues
```

## Docker

The CLI is available as a multi-arch Docker image (amd64/arm64):

```bash
# Run directly
docker run --rm -v ~/.config/mcp:/root/.config/mcp ghcr.io/avelino/mcp --list

# Call a tool
docker run --rm -v ~/.config/mcp:/root/.config/mcp ghcr.io/avelino/mcp sentry search_issues '{"query": "is:unresolved"}'

# Pass environment variables for servers that need them
docker run --rm \
  -v ~/.config/mcp:/root/.config/mcp \
  -e GITHUB_TOKEN \
  ghcr.io/avelino/mcp github search_repositories '{"query": "mcp"}'

# Use an alias for convenience
alias mcp='docker run --rm -v ~/.config/mcp:/root/.config/mcp ghcr.io/avelino/mcp'
mcp sentry --list
```

Available tags:

| Tag | Description |
|---|---|
| `latest` | Latest stable release |
| `x.y.z` | Pinned version |
| `beta` | Latest build from main branch |

## Proxy mode

Use `mcp serve` to expose all your configured servers as a single MCP endpoint. Configure it once, use it from any LLM tool:

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

This works with Claude Code, Cursor, Windsurf, or any MCP-compatible client. Tools are namespaced as `server__tool` (e.g. `sentry__search_issues`). See the [proxy mode guide](docs/guides/proxy-mode.md) for details.

## Audit logging

Every operation is logged — tool calls, searches, config changes, proxy requests. Query the log with filters or stream it in real-time:

```bash
mcp logs                          # recent entries
mcp logs --server sentry --errors # sentry failures only
mcp logs --since 1h               # last hour
mcp logs -f                       # follow mode (tail -f)
mcp logs --json | jq '...'        # pipe to jq
```

Logs are stored locally in an embedded database. No external services, no network calls. See the [audit logging guide](docs/guides/audit-logging.md) for configuration and details.

## Environment variables

| Variable | Description |
|---|---|
| `MCP_CONFIG_PATH` | Override config file location |
| `MCP_TIMEOUT` | Timeout in seconds for stdio servers (default: 60) |

## Documentation

Full documentation: [docs/](docs/README.md)

## Development

```bash
cargo build
cargo test
```

## Contributing

1. Fork the repo
2. Create your branch (`git checkout -b my-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Submit a pull request

## License

MIT
