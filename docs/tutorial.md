# Tutorial

This tutorial walks you through the most common things you'll do with `mcp`. By the end, you'll know how to configure servers, authenticate, explore tools, call them, and use `mcp` in scripts.

> **Prerequisites:** You've completed the [Getting started](getting-started.md) guide and have `mcp` installed.

## Part 1: Understanding servers

MCP servers come in two flavors:

### Stdio servers

These run as a local process. The CLI spawns them, sends JSON-RPC messages to their stdin, and reads responses from their stdout. Most community servers work this way.

```json
{
  "mcpServers": {
    "slack": {
      "command": "npx",
      "args": ["-y", "slack-mcp-server@latest", "--transport", "stdio"],
      "env": {
        "SLACK_MCP_XOXP_TOKEN": "${SLACK_TOKEN}"
      }
    }
  }
}
```

### HTTP servers

These are remote services. The CLI sends HTTP POST requests with JSON-RPC payloads. Some services like Sentry and Honeycomb offer hosted MCP servers.

```json
{
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse"
    }
  }
}
```

## Part 2: Configuring servers manually

The config file lives at `~/.config/mcp/servers.json`. You can edit it directly.

Let's add Sentry manually:

```bash
mkdir -p ~/.config/mcp
```

Edit `~/.config/mcp/servers.json`:

```json
{
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse"
    }
  }
}
```

Verify it's configured:

```bash
mcp --list
```

```json
[
  {
    "name": "sentry",
    "type": "http",
    "url": "https://mcp.sentry.dev/sse"
  }
]
```

## Part 3: Authentication

When you first connect to an HTTP server that requires authentication, `mcp` handles it automatically.

```bash
mcp sentry --list
```

If the server supports OAuth 2.0, your browser opens to authorize the app. After you approve, the token is saved to `~/.config/mcp/auth.json` and reused automatically.

If OAuth isn't supported, `mcp` recognizes popular services and shows you where to get a token:

```
This server requires a Sentry Auth Token.

  How: Create a token with org:read, project:read scopes
  URL: https://sentry.io/settings/account/api/auth-tokens/

Enter access token for https://mcp.sentry.dev:
>
```

You paste the token, it's saved, and you're in.

### Using environment variables for tokens

For servers that need a token in headers, use env vars instead of hardcoding secrets:

```json
{
  "mcpServers": {
    "my-api": {
      "url": "https://api.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${MY_API_TOKEN}"
      }
    }
  }
}
```

Then set the env var in your shell:

```bash
export MY_API_TOKEN="your-token-here"
mcp my-api --list
```

## Part 4: Exploring tools

Every server exposes different tools. Use `--list` to see what's available:

```bash
mcp sentry --list
```

```json
[
  { "name": "search_issues", "description": "Search for issues" },
  { "name": "get_issue_details", "description": "Get details of an issue" },
  { "name": "search_events", "description": "Search events in a project" }
]
```

To see the full input schema (what arguments each tool accepts):

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
        "query": { "type": "string", "description": "Sentry search query" },
        "sort": { "type": "string", "enum": ["date", "priority", "freq"] }
      },
      "required": ["query"]
    }
  }
]
```

This tells you exactly what JSON to pass.

## Part 5: Calling tools

Pass the tool name and a JSON object:

```bash
mcp sentry search_issues '{"query": "is:unresolved level:error"}'
```

The response is always a JSON object with a `content` array:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Found 23 issues matching query..."
    }
  ]
}
```

### Reading arguments from stdin

Instead of passing JSON on the command line, you can pipe it:

```bash
echo '{"query": "is:unresolved"}' | mcp sentry search_issues
```

This is useful when arguments are complex or come from another command:

```bash
cat query.json | mcp sentry search_issues
```

### Parsing output with jq

Since output is JSON, pipe to `jq` for filtering:

```bash
# Get just the tool names
mcp sentry --list | jq '.[].name'

# Extract the text content from a tool call
mcp sentry search_issues '{"query": "is:unresolved"}' | jq '.content[0].text'
```

## Part 6: Managing servers

### Search the registry

Find servers from the official MCP registry:

```bash
mcp search database
```

```json
[
  {
    "name": "sqlite",
    "description": "MCP server for SQLite databases",
    "install": ["npx @anthropic/sqlite-mcp-server"]
  }
]
```

### Add from registry

```bash
mcp add sqlite
```

The CLI fetches the server metadata, writes the config entry, and tells you which env vars to set.

### Add HTTP server manually

```bash
mcp add --url https://mcp.honeycomb.io/mcp honeycomb
```

### Remove a server

```bash
mcp remove sqlite
```

## Part 7: Real-world example

Let's put it together. You want to find unresolved Sentry errors, check Grafana dashboards for related metrics, and post a summary to Slack.

```bash
# Find errors
mcp sentry search_issues '{"query": "is:unresolved level:error"}' \
  | jq '.content[0].text' > /tmp/errors.txt

# Search for related dashboards
mcp grafana search_dashboards '{"query": "api-errors"}' \
  | jq '.[0]'

# Post to Slack
mcp slack send_message "{
  \"channel\": \"#incidents\",
  \"text\": \"Found errors — check Sentry and Grafana\"
}"
```

Each service is just another command. No SDKs, no client libraries, no boilerplate.

## What's next?

- **[Configuration guide](guides/configuration.md)** — Full config file specification.
- **[Authentication guide](guides/authentication.md)** — OAuth 2.0 details, token management.
- **[Scripting guide](guides/scripting.md)** — Patterns for shell scripts and automation.
- **[Supported services](howto/services.md)** — Step-by-step setup for specific services.
