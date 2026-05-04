# Environment variables

## CLI variables

These variables configure `mcp` behavior:

| Variable | Default | Description |
|---|---|---|
| `MCP_SERVERS_CONFIG` | — | Inline JSON config (entire `servers.json` content). Highest priority — skips file read entirely. |
| `MCP_CONFIG_PATH` | `~/.config/mcp/servers.json` | Path to the config file |
| `MCP_CONFIG_DIR` | `~/.config/mcp` | Config directory. Falls back to `/tmp/mcp` when `HOME` is not set. |
| `MCP_TIMEOUT` | `60` | Timeout in seconds for server responses (stdio, CLI, and HTTP transports) |
| `MCP_MAX_OUTPUT` | `1048576` | Maximum output bytes from CLI server commands |
| `MCP_PROXY_REQUEST_TIMEOUT` | `120` | (proxy mode) Hard upper bound, in seconds, that any single client request can spend inside `mcp serve` before the proxy returns a JSON-RPC error. Acts as a belt-and-suspenders boundary on top of the per-transport `MCP_TIMEOUT`. |
| `MCP_CLASSIFIER_CACHE` | `~/.config/mcp/tool-classification.json` | Path to the persistent tool read/write classification cache (see [`mcp acl classify`](./cli.md#mcp-acl-classify)). Override this in CI/containers that cannot write to `$HOME`. |
| `MCP_DISCOVERY_CONCURRENCY` | `10` | Max parallel `--help` calls during CLI subcommand discovery (see [CLI as MCP](../guides/cli-as-mcp.md)) |
| `MCP_AUDIT_OUTPUT` | `file` | Audit output destination: `file` (ChronDB, queryable via `mcp logs`), `stdout`, `stderr` (JSON lines for container log drivers), or `none` (disable). |
| `MCP_AUDIT_ENABLED` | `true` | Set to `false` or `0` to disable audit logging and database initialization. Overrides `audit.enabled` in the config file. |
| `MCP_AUDIT_PATH` | `~/.config/mcp/db/data` | Override the ChronDB data directory. Overrides `audit.path` in the config file. |
| `MCP_AUDIT_INDEX_PATH` | `~/.config/mcp/db/index` | Override the ChronDB index directory. Overrides `audit.index_path` in the config file. |
| `MCP_LOG_LEVEL` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error`. Uses `tracing` `EnvFilter` syntax — you can also set per-module levels like `mcp=debug,hyper=warn`. |
| `MCP_LOG_FORMAT` | `text` | Log output format: `text` (human-readable) or `json` (structured, for container log drivers). |
| `MCP_OAUTH_CALLBACK_PORT` | `8085-8099` | Port or range for the OAuth callback listener. Single port (`9000`), range (`9000-9010`), or `0` for OS-assigned. |
| `MCP_AUTH_CONFIG` | — | Inline JSON content of `auth.json` (read-only). Highest priority for auth — skips file read. Writes are no-ops with a single `warn` log. Intended for k8s/Docker Secrets. |
| `MCP_AUTH_PATH` | `~/.config/mcp/auth.json` | Override the OAuth token storage location (file path) |

### Config loading priority

`mcp` resolves its configuration in this order:

1. **`MCP_SERVERS_CONFIG`** — inline JSON string, parsed directly (no file read)
2. **`MCP_CONFIG_PATH`** — path to a config file
3. **`MCP_CONFIG_DIR`/servers.json** — config directory override
4. **`~/.config/mcp/servers.json`** — default file location
5. **`/tmp/mcp/servers.json`** — last-resort fallback when `HOME` is not set

Environment variable substitution (`${VAR_NAME}`) works in all cases, including inline config.

### `MCP_SERVERS_CONFIG`

Provide the entire config as a JSON string. This is the recommended approach for containers — no file mounts required:

```bash
export MCP_SERVERS_CONFIG='{
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse",
      "headers": {"Authorization": "Bearer ${SENTRY_TOKEN}"}
    }
  }
}'
mcp serve --http 0.0.0.0:8080
```

Load from an existing file with `$(cat ...)`:

```bash
MCP_SERVERS_CONFIG="$(cat servers.json)" mcp serve --http 0.0.0.0:8080
```

`MCP_SERVERS_CONFIG` takes priority over `MCP_CONFIG_PATH`. If both are set, the inline config wins.

### `MCP_CONFIG_PATH`

Override the default config file location. Useful for maintaining multiple configs or testing.

```bash
MCP_CONFIG_PATH=./test-servers.json mcp --list
```

### `MCP_CONFIG_DIR`

Override the base config directory (default `~/.config/mcp`). All default paths (`servers.json`, `auth.json`, `db/`, `tool-classification.json`) resolve relative to this directory.

```bash
MCP_CONFIG_DIR=/data/mcp mcp serve --http 0.0.0.0:8080
```

When `HOME` is not set (common in `scratch` and `distroless` containers), `mcp` falls back to `/tmp/mcp` with a warning.

### `MCP_TIMEOUT`

How long to wait for a server to respond, in seconds. Applies to all transports: stdio, CLI, and HTTP. Increase this for servers that take a long time to initialize (like some npm packages on first run) or slow HTTP backends.

```bash
MCP_TIMEOUT=120 mcp slack --list
```

### `MCP_MAX_OUTPUT`

Maximum number of bytes to capture from a CLI server's stdout. Commands that exceed this limit have their output truncated. Default is 1 MB.

```bash
MCP_MAX_OUTPUT=5242880 mcp my-cli some-tool '{"query": "large dataset"}'
```

### `MCP_PROXY_REQUEST_TIMEOUT`

Only applies to `mcp serve`. Bounds how long the proxy will wait for any single client JSON-RPC request to complete end-to-end (auth + routing + backend I/O). If the bound is hit, the client receives a JSON-RPC error with code `-32000` and the in-flight request is dropped — other concurrent clients are unaffected. Set lower for tighter SLAs, higher for backends that legitimately take a long time.

```bash
MCP_PROXY_REQUEST_TIMEOUT=60 mcp serve --http :7332
```

### `MCP_CLASSIFIER_CACHE`

Override the path of the tool read/write classification cache. The cache is
a JSON file populated lazily by `mcp serve` and `mcp acl classify`, keyed
by `(server, tool, hash(description))`. If the description changes, that
tool's entry is transparently invalidated.

Useful when `$HOME` is read-only (CI workers, containers) — point the
cache at an ephemeral path:

```bash
MCP_CLASSIFIER_CACHE=/tmp/classify.json mcp acl classify
```

Corrupt or unreadable cache files are non-fatal: a warning is logged and
the process proceeds with fresh in-memory classifications.

### `MCP_DISCOVERY_CONCURRENCY`

Only applies to CLI servers (`cli: true`). Limits how many `--help` calls run in parallel during subcommand discovery. Lower this if your machine struggles with many concurrent child processes, or raise it to speed up discovery for deeply nested CLIs.

```bash
MCP_DISCOVERY_CONCURRENCY=5 mcp kubectl --list
```

### `MCP_AUDIT_ENABLED`

Disable audit logging entirely. When set to `false` or `0`, the database is not initialized and no filesystem writes occur. This overrides `"enabled": true` in the config file's `audit` section.

The default Docker image sets `MCP_AUDIT_ENABLED=false` because `scratch` images have no writable filesystem. Override it when you mount a volume:

```bash
docker run --rm \
  -e MCP_AUDIT_ENABLED=true \
  -e MCP_AUDIT_PATH=/data/audit/data \
  -e MCP_AUDIT_INDEX_PATH=/data/audit/index \
  -v audit-data:/data/audit \
  ghcr.io/avelino/mcp serve --http 0.0.0.0:8080
```

### `MCP_AUDIT_PATH` / `MCP_AUDIT_INDEX_PATH`

Override the ChronDB data and index directories. These take priority over the `audit.path` and `audit.index_path` fields in the config file.

```bash
MCP_AUDIT_PATH=/var/lib/mcp/data MCP_AUDIT_INDEX_PATH=/var/lib/mcp/index mcp serve --http 0.0.0.0:8080
```

### `MCP_AUTH_CONFIG`

Inline JSON content of `auth.json`, equivalent to [`MCP_SERVERS_CONFIG`](#mcp_servers_config) but for OAuth tokens and dynamic-client registrations. Highest priority — when set, the file at `MCP_AUTH_PATH` (or the default location) is **not** read.

```bash
export MCP_AUTH_CONFIG='{
  "clients": {
    "https://mcp.sentry.dev": {"client_id": "abc123"}
  },
  "tokens": {
    "https://mcp.sentry.dev": {
      "access_token": "${SENTRY_ACCESS_TOKEN}",
      "refresh_token": "${SENTRY_REFRESH_TOKEN}"
    }
  }
}'
mcp serve --http 0.0.0.0:8080
```

`${VAR}` placeholders are expanded the same way as in [`MCP_SERVERS_CONFIG`](#mcp_servers_config), so you can split tokens across multiple Secret keys.

**Read-only on disk; mutable in memory.** When `MCP_AUTH_CONFIG` is set, the env var seeds an in-memory auth store on first load. Subsequent OAuth flows — token refresh, dynamic-client registration — update the cache so refreshed tokens are visible to later calls within the same process. Nothing is ever written back to disk (the source of truth is the Secret), and a single `warn` log is emitted on the first save attempt. On pod restart, the Secret is read again — any in-memory mutations are discarded.

**Use cases:**

- Kubernetes deployments where the pod has a read-only filesystem and OAuth tokens come from a Secret (see [Deploying on Kubernetes](../howto/kubernetes.md))
- Docker containers where mounting a writable `auth.json` is undesirable
- CI environments that need pre-provisioned tokens for ephemeral runs

**Not recommended for:**

- Local development on a workstation — use the default `auth.json` and let `mcp add` handle the OAuth flow.
- Any environment where you expect `mcp add <server>` to register a new client and persist the result. That flow requires a writable file.

`MCP_AUTH_CONFIG` takes priority over `MCP_AUTH_PATH`. If both are set, the inline content wins. An empty or whitespace-only value falls through to the file path.

### `MCP_AUTH_PATH`

Override the OAuth token storage location (file path). Default is `~/.config/mcp/auth.json`. Useful in containers where `$HOME` doesn't exist, or to share an auth store across multiple `mcp` invocations.

```bash
MCP_AUTH_PATH=/data/auth.json mcp add sentry --remote https://mcp.sentry.dev
```

For container deployments where the filesystem is read-only or you want tokens injected from a secret manager, use [`MCP_AUTH_CONFIG`](#mcp_auth_config) instead.

### Auth loading priority

`mcp` resolves the auth store in this order:

1. **`MCP_AUTH_CONFIG`** — inline JSON (read-only, no file I/O)
2. **`MCP_AUTH_PATH`** — file path override
3. **`MCP_CONFIG_DIR`/auth.json** — config directory override
4. **`~/.config/mcp/auth.json`** — default file location

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
