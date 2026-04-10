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

Three variants, distinguished by their fields:

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
| `tool_acl` | object | `null` | Manual read/write classification overrides (see [Tool ACL overrides](#tool-acl-overrides)) |
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
| `tool_acl` | object | `null` | Manual read/write classification overrides (see [Tool ACL overrides](#tool-acl-overrides)) |
| `idle_timeout` | string | `"adaptive"` | Idle shutdown policy (see [Idle timeout](#idle-timeout)) |
| `min_idle_timeout` | string | `"1m"` | Minimum idle timeout for adaptive mode |
| `max_idle_timeout` | string | `"5m"` | Maximum idle timeout for adaptive mode |

### CLI server

```json
{
  "command": "kubectl",
  "cli": true,
  "cli_help": "--help",
  "cli_depth": 2,
  "cli_only": ["get", "describe", "logs"]
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `command` | string | *required* | CLI executable to wrap |
| `cli` | bool | *required* | Must be `true` — marks this as a CLI server |
| `cli_help` | string | `"--help"` | Flag used to discover subcommands and options |
| `cli_depth` | number | `2` | How deep to recurse into subcommands for flag discovery |
| `cli_only` | string[] | `[]` (all) | Whitelist of subcommands to expose |
| `args` | string[] | `[]` | Base arguments prepended to every invocation |
| `env` | object | `{}` | Environment variables for the CLI process |
| `tools` | array | `[]` | Preset tool definitions (skips auto-discovery when set) |
| `tool_acl` | object | `null` | Manual read/write classification overrides (see [Tool ACL overrides](#tool-acl-overrides)) |
| `idle_timeout` | string | `"adaptive"` | Idle shutdown policy (see [Idle timeout](#idle-timeout)) |
| `min_idle_timeout` | string | `"1m"` | Minimum idle timeout for adaptive mode |
| `max_idle_timeout` | string | `"5m"` | Maximum idle timeout for adaptive mode |

See the [CLI as MCP guide](../guides/cli-as-mcp.md) for discovery details and examples.

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

## Tool ACL overrides

The proxy ships with an automatic classifier that labels every tool of every
upstream MCP as `read`, `write`, or `ambiguous` (treated as write, fail-safe).
The classifier is auditable — run `mcp acl classify` to see the verdict,
confidence, source, and reasons for each tool.

When the classifier is wrong (or when you just want to be explicit),
add `tool_acl` to any server and pin individual tools to `read` or `write`
using the same glob syntax as the ACL rules (`*`, prefix, suffix, contains).

```json
{
  "mcpServers": {
    "grafana": {
      "command": "mcp-grafana",
      "tool_acl": {
        "read":  ["get_*", "list_*", "search_*", "find_*", "query_*", "generate_deeplink"],
        "write": ["update_dashboard", "create_*", "alerting_manage_*"]
      }
    },
    "databricks": {
      "command": "databricks-mcp",
      "tool_acl": {
        "read":  ["execute_sql_read_only", "poll_sql_result"],
        "write": ["execute_sql"]
      }
    }
  }
}
```

Semantics:

- Both `read` and `write` are optional — omit either or both.
- Overrides run **before** the classifier. A tool that matches an override
  is never scored.
- The same pattern string may not appear in both `read` and `write` for the
  same server — that fails loudly at load time.
- If two different globs on the same server both match a single tool name
  (e.g. `get_*` in `read` and `*_thing` in `write` both match `get_thing`),
  the proxy fails safe to `write` at classification time. Narrow your
  globs to avoid this.
- Overrides are **never cached** — they are re-read from the config on
  every startup.

For the full redesign plan and the token/description dictionaries the
classifier uses, see [`docs/acl-redesign-plan.md`](../acl-redesign-plan.md).

## Type detection

The config uses serde's untagged enum deserialization. The type is inferred from the fields:

- Has `command` + `cli: true` → CLI
- Has `command` (without `cli`) → Stdio
- Has `url` → HTTP

CLI is checked first, then Stdio, then HTTP.

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

Required when `provider` is `"bearer"`. Each entry in `tokens` accepts two shapes:

- **Legacy (string):** `"<token>": "<subject>"` — subject only, no roles.
- **Extended (object):** `"<token>": { "subject": "<subject>", "roles": ["<role>", ...] }` — subject plus roles used by ACL evaluation.

Both forms can coexist in the same file.

```json
{
  "bearer": {
    "tokens": {
      "secret-abc": "alice",
      "secret-def": { "subject": "bob", "roles": ["dev", "oncall"] }
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tokens` | object | Map of token → subject string **or** `{subject, roles}` object |

Each extended entry:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subject` | string | *required* | User identity for this token |
| `roles` | string[] | `[]` | Roles assigned to this identity (used by ACL rules) |

### Forwarded config

Optional when `provider` is `"forwarded"`. Reads the authenticated user from a header set by a trusted reverse proxy, and optionally reads a groups header to populate roles.

```json
{
  "forwarded": {
    "header": "x-forwarded-user",
    "groups_header": "x-forwarded-groups"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `header` | string | `"x-forwarded-user"` | Header name to read the authenticated user from |
| `groups_header` | string | `"x-forwarded-groups"` | Header name to read roles from (comma-separated, oauth2-proxy convention) |

Groups header value is parsed as a comma-separated list: each entry is trimmed and empty entries are dropped. Missing header yields empty roles (not an error). Role matching is case-sensitive.

> Only use `forwarded` behind a trusted reverse proxy. The proxy **must** strip these headers from incoming client requests — otherwise a client could forge identity and roles.

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
| `tools` | string[] | *required* | Tool name patterns (supports `*` wildcards — prefix, suffix, middle, multiple) |
| `policy` | `"allow"` \| `"deny"` | *required* | Action when rule matches |

Both `subjects` and `roles` must match for a rule to apply. Empty means "match all".

#### Tool pattern glob syntax

The `tools` field supports glob patterns with `*` wildcards:

| Pattern | Matches | Example |
|---------|---------|---------|
| `sentry__*` | Anything starting with `sentry__` | `sentry__search_issues` |
| `*_issues` | Anything ending with `_issues` | `search_issues`, `sentry__list_issues` |
| `*admin*` | Anything containing `admin` | `admin_panel`, `user_admin_tools` |
| `sentry__*_admin__*` | Multiple wildcards | `sentry__team_admin__delete` |
| `my_tool` | Exact match (no wildcards) | `my_tool` |
| `*` | Everything | any tool |

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
