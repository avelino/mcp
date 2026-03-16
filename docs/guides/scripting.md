# Scripting

`mcp` automatically switches to JSON output when piped or redirected, making it easy to use in shell scripts, CI/CD pipelines, and automation. You can also force JSON with `--json`.

## Basics

### Output format detection

When piped (non-interactive), `mcp` outputs JSON by default. In interactive terminals, it shows human-readable tables. Use `--json` to force JSON in any context:

```bash
# These all produce JSON:
mcp sentry search_issues '{"query": "..."}' | jq '.'   # piped → JSON
mcp sentry --list > tools.json                           # redirected → JSON
mcp sentry --list --json                                 # explicit → JSON
```

### Output goes to stdout

All tool results are JSON on stdout:

```bash
result=$(mcp sentry search_issues '{"query": "is:unresolved"}')
echo "$result" | jq '.content[0].text'
```

### Errors go to stderr

Errors and status messages go to stderr, so they don't pollute your data:

```bash
# This captures only the JSON, not auth messages or warnings
mcp sentry search_issues '{"query": "is:unresolved"}' > results.json
```

### Exit codes

- `0` — Success
- `1` — Error (connection failed, tool error, bad config, etc.)

```bash
if mcp sentry --list > /dev/null 2>&1; then
    echo "Sentry is configured and reachable"
else
    echo "Sentry is not available"
fi
```

## Piping input

When no JSON argument is provided on the command line, `mcp` reads from stdin (if it's not a terminal):

```bash
# From a file
cat query.json | mcp sentry search_issues

# From another command
jq -n '{"query": "is:unresolved"}' | mcp sentry search_issues

# Here document
mcp sentry search_issues <<'EOF'
{"query": "is:unresolved", "sort": "date"}
EOF
```

If stdin is a terminal (interactive), `mcp` uses `{}` as the default argument. This is why `mcp sentry --list` works without any input.

## Parsing with jq

### Get tool names

```bash
mcp sentry --list | jq -r '.[].name'
```

### Extract text content

```bash
mcp sentry search_issues '{"query": "is:unresolved"}' \
  | jq -r '.content[] | select(.type == "text") | .text'
```

### Check for errors

```bash
result=$(mcp sentry search_issues '{"query": "bad query"}')
is_error=$(echo "$result" | jq -r '.isError // false')
if [ "$is_error" = "true" ]; then
    echo "Tool returned an error"
fi
```

## Common patterns

### Loop over results

```bash
# Get all tool names and call each one with empty args
mcp sentry --list | jq -r '.[].name' | while read tool; do
    echo "=== $tool ==="
    mcp sentry "$tool" 2>/dev/null || echo "(failed)"
done
```

### Build arguments dynamically

```bash
project="my-project"
query="is:unresolved level:error"
args=$(jq -n --arg q "$query" --arg p "$project" \
    '{"query": $q, "project": $p}')
mcp sentry search_issues "$args"
```

### Chain multiple servers

```bash
# Get Sentry errors, format them, post to Slack
errors=$(mcp sentry search_issues '{"query": "is:unresolved level:error"}' \
    | jq -r '.content[0].text')

message="Unresolved errors from Sentry:\n${errors}"
mcp slack send_message "$(jq -n --arg text "$message" \
    '{"channel": "#alerts", "text": $text}')"
```

### Cron job

```bash
#!/bin/bash
# /etc/cron.d/check-errors — run every hour

export SENTRY_TOKEN="your-token"
export MCP_CONFIG_PATH="/opt/mcp/servers.json"

count=$(mcp sentry search_issues '{"query": "is:unresolved level:error"}' \
    | jq '.content[0].text | length')

if [ "$count" -gt 0 ]; then
    echo "Found $count unresolved errors" | mail -s "Sentry Alert" team@example.com
fi
```

## CI/CD

### GitHub Actions

```yaml
- name: Check for critical Sentry issues
  env:
    MCP_CONFIG_PATH: ./ci/mcp-servers.json
    SENTRY_TOKEN: ${{ secrets.SENTRY_TOKEN }}
  run: |
    result=$(mcp sentry search_issues '{"query": "is:unresolved level:fatal"}')
    count=$(echo "$result" | jq '.content | length')
    if [ "$count" -gt 0 ]; then
      echo "::warning::Found unresolved fatal issues in Sentry"
    fi
```

## Tips

- **Always quote JSON arguments** — Shell metacharacters in JSON can cause issues
- **Use `jq -n`** — When building JSON arguments with variables, `jq -n` is safer than string interpolation
- **Redirect stderr** — Use `2>/dev/null` to suppress auth messages in scripts
- **Set `MCP_TIMEOUT`** — Increase for slow servers: `MCP_TIMEOUT=120 mcp slack --list`
- **Non-interactive stdin** — When piping or in cron, stdin is not a terminal, so `mcp` reads from it. Pass `{}` explicitly if the tool needs no arguments: `echo '{}' | mcp server tool`
