# Environment variables

## CLI variables

These variables configure `mcp` behavior:

| Variable | Default | Description |
|---|---|---|
| `MCP_CONFIG_PATH` | `~/.config/mcp/servers.json` | Path to the config file |
| `MCP_TIMEOUT` | `60` | Timeout in seconds for stdio server responses |

### `MCP_CONFIG_PATH`

Override the default config file location. Useful for maintaining multiple configs or testing.

```bash
MCP_CONFIG_PATH=./test-servers.json mcp --list
```

### `MCP_TIMEOUT`

How long to wait for a stdio server to respond, in seconds. Increase this for servers that take a long time to initialize (like some npm packages on first run).

```bash
MCP_TIMEOUT=120 mcp slack --list
```

Does not affect HTTP servers (they use reqwest's default timeouts).

## Config variables

Environment variables referenced in `servers.json` with `${VAR_NAME}` syntax. These are user-defined and depend on which servers you've configured.

Common examples:

| Variable | Service | Description |
|---|---|---|
| `GITHUB_TOKEN` | GitHub | Personal access token |
| `SLACK_TOKEN` | Slack | Bot or user OAuth token (`xoxb-` or `xoxp-`) |
| `SENTRY_TOKEN` | Sentry | Auth token |
| `GRAFANA_TOKEN` | Grafana | Service account token |
| `ROAM_TOKEN` | Roam Research | Graph API token |

Set them in your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export GITHUB_TOKEN="ghp_..."
export SLACK_TOKEN="xoxb-..."
```

Or pass them inline:

```bash
GITHUB_TOKEN="ghp_..." mcp github --list
```
