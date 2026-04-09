# Environment variables

## CLI variables

These variables configure `mcp` behavior:

| Variable | Default | Description |
|---|---|---|
| `MCP_CONFIG_PATH` | `~/.config/mcp/servers.json` | Path to the config file |
| `MCP_TIMEOUT` | `60` | Timeout in seconds for stdio server responses |
| `MCP_PROXY_REQUEST_TIMEOUT` | `120` | (proxy mode) Hard upper bound, in seconds, that any single client request can spend inside `mcp serve` before the proxy returns a JSON-RPC error. Acts as a belt-and-suspenders boundary on top of the per-transport `MCP_TIMEOUT`. |

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

### `MCP_PROXY_REQUEST_TIMEOUT`

Only applies to `mcp serve`. Bounds how long the proxy will wait for any single client JSON-RPC request to complete end-to-end (auth + routing + backend I/O). If the bound is hit, the client receives a JSON-RPC error with code `-32000` and the in-flight request is dropped — other concurrent clients are unaffected. Set lower for tighter SLAs, higher for backends that legitimately take a long time.

```bash
MCP_PROXY_REQUEST_TIMEOUT=60 mcp serve --http :7332
```

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
