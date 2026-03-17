# Config file reference

## Location

Default: `~/.config/mcp/servers.json`

Override: `MCP_CONFIG_PATH` environment variable.

## Schema

```json
{
  "mcpServers": {
    "<name>": <ServerConfig>,
    ...
  }
}
```

## ServerConfig

Two variants, distinguished by their fields:

### Stdio server

```json
{
  "command": "npx",
  "args": ["-y", "package-name"],
  "env": {
    "KEY": "value"
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `command` | string | *required* | Executable to spawn |
| `args` | string[] | `[]` | Arguments passed to the command |
| `env` | object | `{}` | Environment variables for the process |
| `idle_timeout` | string | `"adaptive"` | Idle shutdown policy (see [Idle timeout](#idle-timeout)) |
| `min_idle_timeout` | string | `"1m"` | Minimum idle timeout for adaptive mode |
| `max_idle_timeout` | string | `"5m"` | Maximum idle timeout for adaptive mode |

### HTTP server

```json
{
  "url": "https://example.com/mcp",
  "headers": {
    "Authorization": "Bearer token"
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | *required* | Server endpoint URL |
| `headers` | object | `{}` | HTTP headers for every request |
| `idle_timeout` | string | `"adaptive"` | Idle shutdown policy (see [Idle timeout](#idle-timeout)) |
| `min_idle_timeout` | string | `"1m"` | Minimum idle timeout for adaptive mode |
| `max_idle_timeout` | string | `"5m"` | Maximum idle timeout for adaptive mode |

## Idle timeout

Controls when the proxy shuts down idle backend connections to reclaim resources. Applies to both stdio and HTTP backends in proxy mode (`mcp serve`).

### Policy values

| Value | Behavior |
|-------|----------|
| `"adaptive"` (default) | Timeout adjusts based on usage frequency — frequently used backends stay alive longer |
| `"never"` | Never shut down — backend stays connected for the entire proxy lifetime |
| `"<duration>"` | Fixed timeout (e.g. `"3m"`, `"30s"`, `"1h"`) |

Duration format: number followed by `s` (seconds), `m` (minutes), or `h` (hours). Plain numbers are treated as seconds.

### Adaptive mode

When `idle_timeout` is `"adaptive"` (the default), the proxy tracks how often each backend is used and assigns a timeout tier:

| Usage tier | Requests/hour | Idle timeout |
|-----------|--------------|-------------|
| Hot | > 20 | 5 min |
| Warm | 5–20 | 3 min |
| Cold | < 5 | 1 min |

The tier is computed from the backend's total request count divided by its uptime. The result is clamped between `min_idle_timeout` (default `1m`) and `max_idle_timeout` (default `5m`).

When a backend is shut down due to inactivity, its tools remain visible in `tools/list`. On the next `tools/call`, the proxy reconnects automatically (lazy initialization). Usage history is preserved across reconnections so the adaptive algorithm has continuity.

### Examples

```json
{
  "mcpServers": {
    "slack": {
      "command": "npx",
      "args": ["@anthropic/mcp-slack"],
      "idle_timeout": "adaptive",
      "min_idle_timeout": "30s",
      "max_idle_timeout": "5m"
    },
    "sentry": {
      "url": "https://mcp.sentry.io",
      "idle_timeout": "never"
    },
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github"],
      "idle_timeout": "2m"
    }
  }
}
```

## Type detection

The config uses serde's untagged enum deserialization. The type is inferred from the fields:

- Has `command` → Stdio
- Has `url` → HTTP

If both are present, Stdio takes priority (it's checked first).

## Environment variable substitution

Any `${VAR_NAME}` in a string value is replaced with the env var's value at load time.

```json
{
  "env": { "TOKEN": "${MY_SECRET}" },
  "headers": { "Authorization": "Bearer ${API_KEY}" },
  "url": "https://${HOST}/mcp"
}
```

Missing env vars resolve to empty string `""`.

## Reserved names

These names cannot be used as server names:

- `search`
- `add`
- `remove`
- `list`
- `help`
- `version`

Using a reserved name won't break the config, but you'll get a warning and the server may be shadowed by built-in commands.

## Server authentication (`serverAuth`)

Optional. Configures authentication for `mcp serve --http`. Ignored for direct CLI usage.

```json
{
  "mcpServers": { ... },
  "serverAuth": {
    "provider": "<provider>",
    "bearer": { ... },
    "forwarded": { ... },
    "acl": { ... }
  }
}
```

### Provider

| Value | Description |
|-------|-------------|
| `"none"` (default) | No authentication — all requests are anonymous |
| `"bearer"` | Static bearer token validation |
| `"forwarded"` | Trust reverse proxy header |

### Bearer config

Required when `provider` is `"bearer"`.

```json
{
  "bearer": {
    "tokens": {
      "<token>": "<subject>",
      "secret-abc": "alice"
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tokens` | object | Map of token → subject identity |

### Forwarded config

Optional when `provider` is `"forwarded"`. Defaults to `x-forwarded-user`.

```json
{
  "forwarded": {
    "header": "x-forwarded-user"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `header` | string | `"x-forwarded-user"` | Header name to read the authenticated user from |

### ACL config

Optional. Controls which users can access which tools.

```json
{
  "acl": {
    "default": "allow",
    "rules": [
      {
        "subjects": ["bob"],
        "roles": ["viewer"],
        "tools": ["sentry__*"],
        "policy": "deny"
      }
    ]
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default` | `"allow"` \| `"deny"` | `"allow"` | Default policy when no rule matches |
| `rules` | array | `[]` | Ordered list of ACL rules (first match wins) |

#### ACL rule

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subjects` | string[] | `[]` (match all) | User subjects to match (`*` = any) |
| `roles` | string[] | `[]` (match all) | Roles to match (`*` = any) |
| `tools` | string[] | *required* | Tool name patterns (supports `*` prefix/suffix globs) |
| `policy` | `"allow"` \| `"deny"` | *required* | Action when rule matches |

Both `subjects` and `roles` must match for a rule to apply. Empty means "match all".

## Auth store

Tokens and OAuth client registrations are stored separately in:

```
~/.config/mcp/auth.json
```

```json
{
  "clients": {
    "https://server-url": {
      "client_id": "registered-client-id",
      "client_secret": "optional-secret"
    }
  },
  "tokens": {
    "https://server-url": {
      "access_token": "the-token",
      "refresh_token": "optional-refresh-token",
      "expires_at": 1710000000
    }
  }
}
```

Keys are normalized server URLs (trailing slash removed).
