# Audit logging

Every operation that passes through `mcp` is logged — CLI commands, proxy requests, tool calls, registry searches. The audit log gives you full visibility into what happened, when, how long it took, and whether it succeeded.

## How it works

`mcp` writes audit entries to an embedded [ChronDB](https://chrondb.avelino.run/) database stored locally. Logging happens in a background thread via an async channel, so it never blocks your commands.

```
mcp <any command>  -->  AuditLogger (mpsc channel)  -->  ChronDB (background writer)
                                                             |
                                                    ~/.config/mcp/audit/
```

Every entry records:

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 timestamp |
| `source` | Where it came from: `cli`, `serve:http`, `serve:stdio` |
| `method` | What was called: `tools/call`, `tools/list`, `registry/search`, etc. |
| `tool_name` | Tool name (for `tools/call`) |
| `server_name` | Backend server name |
| `identity` | Who called it: `local` for CLI, user subject for proxy |
| `duration_ms` | How long it took |
| `success` | Whether it worked |
| `error_message` | Error details when it failed |
| `acl_decision` | `allow` or `deny` when ACL evaluation is performed |
| `acl_matched_rule` | Which rule decided: `dev[1]`, `alice.extra[0]`, `default`, `legacy[3]`, `legacy:default`, `no-acl` |
| `acl_access_kind` | Effective access evaluated: `read`, `write`, or `*` |
| `classification_kind` | Tool classification: `read`, `write`, or `ambiguous` |
| `classification_source` | How it was classified: `override`, `annotation`, `classifier`, or `fallback` |
| `classification_confidence` | Classifier confidence (0.00–1.00) |

ACL/classification fields are present on entries that perform ACL checks:
proxy `tools/call`, `tools/list:filtered`, and CLI `acl/check`. Other entries
omit them (the fields are absent, not null).

## What gets logged

Everything:

| Command | Method |
|---|---|
| `mcp --list` | `servers/list` |
| `mcp search <query>` | `registry/search` |
| `mcp add <name>` | `config/add` |
| `mcp remove <name>` | `config/remove` |
| `mcp update <name>` | `config/update` |
| `mcp <server> --list` | `tools/list` |
| `mcp <server> --info` | `tools/info` |
| `mcp <server> <tool>` | `tools/call` |
| Proxy: any JSON-RPC request | `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get` |

The only command that doesn't log itself is `mcp logs` (that would be recursive).

## Querying logs

```bash
# Recent entries (default: last 50)
mcp logs

# Last 100 entries
mcp logs --limit 100

# Filter by backend server
mcp logs --server sentry

# Filter by tool name prefix
mcp logs --tool sentry__search

# Filter by JSON-RPC method
mcp logs --method tools/call

# Filter by caller identity (proxy mode)
mcp logs --identity alice

# Only failures
mcp logs --errors

# Time-based filter
mcp logs --since 5m       # last 5 minutes
mcp logs --since 1h       # last hour
mcp logs --since 24h      # last 24 hours
mcp logs --since 7d       # last 7 days

# Combine filters
mcp logs --server sentry --errors --since 24h
```

### Output formats

**Terminal** (interactive) — colored table:

```
Timestamp                         Source       Method           Tool                     Server   Identity  Duration  Status  Detail
2026-03-16T18:30:00+00:00         serve:http   tools/call       sentry__search_issues    sentry   alice     142ms     ok      -
2026-03-16T18:30:02+00:00         cli          registry/search  -                        -        local     630ms     ok      query=filesystem
2026-03-16T18:30:05+00:00         cli          tools/call       search_issues            sentry   local     27ms      error   MCP error -32602: Invalid arguments for tool search_issues:

3 entry(ies)
```

**JSON** (piped or `--json`) — composable with `jq`:

```bash
# Slow calls (>500ms)
mcp logs --json | jq '.[] | select(.duration_ms > 500)'

# Error messages only
mcp logs --errors --json | jq '.[].error_message'

# Count calls per server
mcp logs --json | jq 'group_by(.server_name) | map({server: .[0].server_name, count: length})'

# Denied write requests
mcp logs --json | jq '.[] | select(.acl_decision=="deny" and .acl_access_kind=="write")'

# Low-confidence classifications that were allowed
mcp logs --json | jq '.[] | select(.classification_confidence < 0.5 and .acl_decision=="allow")'

# Which rules are denying requests
mcp logs --json | jq '[.[] | select(.acl_decision=="deny")] | group_by(.acl_matched_rule) | map({rule: .[0].acl_matched_rule, count: length})'
```

## Follow mode

Stream new entries in real-time, like `tail -f`:

```bash
# Follow all entries
mcp logs -f

# Follow only errors
mcp logs -f --errors

# Follow filtered by server
mcp logs -f --server sentry
```

Follow mode uses polling (1s interval) on the ChronDB database, so it works even when `mcp serve` runs in a separate process.

## Configuration

Add an `audit` section to `~/.config/mcp/servers.json`:

```json
{
  "mcpServers": { ... },
  "audit": {
    "enabled": true,
    "log_arguments": false
  }
}
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable/disable audit logging |
| `log_arguments` | `false` | Log tool call arguments (may contain PII) |
| `path` | `~/.config/mcp/audit/data` | ChronDB data directory |
| `index_path` | `~/.config/mcp/audit/index` | ChronDB index directory |

### Logging arguments

By default, tool call arguments are **not** logged to avoid capturing sensitive data (API keys, personal info, query contents). Enable `log_arguments` only if you need it:

```json
{
  "audit": {
    "log_arguments": true
  }
}
```

With this enabled, `mcp logs --json` will include the full arguments:

```json
{
  "method": "tools/call",
  "tool_name": "search_issues",
  "arguments": {"query": "is:unresolved", "organizationSlug": "my-org"},
  ...
}
```

## Storage

Audit data lives in `~/.config/mcp/audit/` by default:

```
~/.config/mcp/audit/
  data/     # ChronDB git-based document store
  index/    # Lucene search index
```

Each entry is stored as a JSON document with key `audit:{timestamp_millis}-{uuid}`, which gives natural chronological ordering via prefix listing.

## Disabling audit logging

Via config file:

```json
{
  "audit": {
    "enabled": false
  }
}
```

Via environment variable (takes priority over config file):

```bash
MCP_AUDIT_ENABLED=false mcp serve --http 0.0.0.0:8080
```

When disabled, the logger is a no-op and the database is not initialized — zero overhead, no files created, no filesystem writes. This is the default in the Docker image.

## Environment variable overrides

All audit settings can be overridden via environment variables, which take priority over the config file. This is useful for container deployments where editing the config JSON is impractical.

| Variable | Overrides | Description |
|---|---|---|
| `MCP_AUDIT_ENABLED` | `audit.enabled` | Set to `false` or `0` to disable |
| `MCP_AUDIT_PATH` | `audit.path` | ChronDB data directory |
| `MCP_AUDIT_INDEX_PATH` | `audit.index_path` | ChronDB index directory |

Example: redirect audit to a mounted volume in Docker:

```bash
docker run -d \
  -e MCP_AUDIT_ENABLED=true \
  -e MCP_AUDIT_PATH=/data/audit/data \
  -e MCP_AUDIT_INDEX_PATH=/data/audit/index \
  -v audit-vol:/data/audit \
  ghcr.io/avelino/mcp serve --http 0.0.0.0:8080
```

See the full list of variables in the [environment variables reference](../reference/environment-variables.md).
