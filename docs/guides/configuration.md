# Configuration

This guide covers everything about configuring `mcp` servers.

## Config file location

By default, `mcp` reads from:

```
~/.config/mcp/servers.json
```

Override with the `MCP_CONFIG_PATH` environment variable:

```bash
MCP_CONFIG_PATH=./my-servers.json mcp --list
```

If the file doesn't exist, `mcp` starts with zero servers. No error, no default file created — you build it as you go with `mcp add` or by editing the file directly.

## File format

The config file is JSON with a single top-level key:

```json
{
  "mcpServers": {
    "server-name": { ... },
    "another-server": { ... }
  }
}
```

Each server entry is identified by its name (the key). This name is what you use on the command line: `mcp server-name --list`.

## Server types

### Stdio servers

Stdio servers run as local processes. The CLI spawns them, communicates via stdin/stdout using JSON-RPC 2.0.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic/fs-mcp-server", "/home/me/documents"],
      "env": {}
    }
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `command` | string | yes | The executable to run |
| `args` | string[] | no | Command-line arguments |
| `env` | object | no | Environment variables for the process |

The `command` is the only required field. `args` defaults to `[]` and `env` defaults to `{}`.

### HTTP servers

HTTP servers are remote endpoints. The CLI sends POST requests with JSON-RPC payloads.

```json
{
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse",
      "headers": {
        "Authorization": "Bearer ${SENTRY_TOKEN}"
      }
    }
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | yes | The server endpoint URL |
| `headers` | object | no | HTTP headers to include in every request |

`mcp` handles both standard JSON responses and [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) responses automatically. It also maintains session IDs when the server returns `Mcp-Session-Id` headers.

## Environment variable substitution

Any value in the config can use `${VAR_NAME}` to reference environment variables. They're resolved when the config is loaded.

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@anthropic/github-mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_PERSONAL_TOKEN}"
      }
    }
  }
}
```

If an env var is not set, it resolves to an empty string. This is intentional — it lets you have optional variables without breaking the config.

Works in any string value: `env`, `headers`, `args`, `url`, etc.

## Server names

Server names are used as the first argument on the command line (`mcp <name> ...`). A few names are reserved and cannot be used:

- `search`
- `add`
- `remove`
- `list`
- `help`
- `version`

If you accidentally name a server with a reserved name, `mcp` will warn you at startup:

```
warning: server "search" conflicts with a reserved command name
  → rename it in /home/you/.config/mcp/servers.json to avoid unexpected behavior
```

## Adding servers

### From the registry

```bash
mcp add filesystem
```

This looks up the server in the [MCP registry](https://registry.modelcontextprotocol.io), generates the config entry automatically, and tells you which env vars to set.

### Manually (HTTP)

```bash
mcp add --url https://api.example.com/mcp my-server
```

### Manually (edit file)

Just open `~/.config/mcp/servers.json` in your editor and add the entry.

## Removing servers

```bash
mcp remove filesystem
```

This removes the entry from the config file.

## Multiple configs

You can maintain different config files for different contexts:

```bash
# Work servers
MCP_CONFIG_PATH=~/.config/mcp/work.json mcp --list

# Personal servers
MCP_CONFIG_PATH=~/.config/mcp/personal.json mcp --list
```

Or use shell aliases:

```bash
alias mcp-work='MCP_CONFIG_PATH=~/.config/mcp/work.json mcp'
alias mcp-personal='MCP_CONFIG_PATH=~/.config/mcp/personal.json mcp'
```

## Complete example

A real-world config with multiple server types:

```json
{
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse"
    },
    "honeycomb": {
      "url": "https://mcp.honeycomb.io/mcp"
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "slack-mcp-server@latest", "--transport", "stdio"],
      "env": {
        "SLACK_MCP_XOXP_TOKEN": "${SLACK_TOKEN}",
        "SLACK_MCP_TEAM_ID": "${SLACK_TEAM_ID}"
      }
    },
    "roam": {
      "command": "npx",
      "args": ["-y", "roam-tui@latest", "--mcp"],
      "env": {
        "ROAM_GRAPH_API_TOKEN": "${ROAM_TOKEN}"
      }
    },
    "grafana": {
      "url": "https://grafana.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${GRAFANA_TOKEN}"
      }
    }
  }
}
```
