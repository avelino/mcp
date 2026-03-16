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
