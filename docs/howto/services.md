# Supported services

Step-by-step setup guides for popular services. Each section gets you from zero to working.

## Sentry

Track errors, search issues, and inspect events.

**Add the server:**

```bash
mcp add --url https://mcp.sentry.dev/sse sentry
```

**Authenticate:**

```bash
mcp sentry --list
```

Sentry supports OAuth 2.0. Your browser will open to authorize the app. After approval, the token is saved automatically.

**Example usage:**

```bash
# Search for unresolved errors
mcp sentry search_issues '{"query": "is:unresolved level:error"}'

# Get issue details
mcp sentry get_issue_details '{"issue_id": "12345"}'

# Search events in a project
mcp sentry search_events '{"project": "my-project", "query": "transaction:/api/users"}'
```

## Slack

Send messages, list channels, search conversations.

**Add the server:**

```bash
mcp add slack
```

**Set environment variables:**

You need a Slack app with a bot token. Go to [api.slack.com/apps](https://api.slack.com/apps), create an app, and get the OAuth token.

```bash
export SLACK_MCP_XOXP_TOKEN="xoxp-your-token"
export SLACK_MCP_TEAM_ID="T12345678"
```

**Test:**

```bash
mcp slack --list
```

> **Note:** Slack's MCP server can take 30+ seconds to initialize on first run (npm install). If you get a timeout, increase it: `MCP_TIMEOUT=120 mcp slack --list`

**Example usage:**

```bash
# List channels
mcp slack list_channels

# Send a message
mcp slack send_message '{"channel": "#general", "text": "Hello from mcp!"}'
```

## Grafana

Search dashboards, query Prometheus, check alerts.

**Add the server (self-hosted Grafana):**

```json
{
  "mcpServers": {
    "grafana": {
      "url": "https://grafana.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${GRAFANA_TOKEN}"
      }
    }
  }
}
```

Create a Service Account Token in Grafana: Administration → Service Accounts → Add token.

```bash
export GRAFANA_TOKEN="glsa_..."
```

**Example usage:**

```bash
# Search dashboards
mcp grafana search_dashboards '{"query": "api-latency"}'

# Query Prometheus
mcp grafana query_prometheus '{"query": "rate(http_requests_total[5m])"}'

# List alert rules
mcp grafana list_alert_groups
```

## GitHub

Search repositories, manage issues, read files.

**Add the server:**

```bash
mcp add github
```

**Set environment variable:**

Create a [Personal Access Token](https://github.com/settings/tokens) with the scopes you need.

```bash
export GITHUB_TOKEN="ghp_..."
```

**Example usage:**

```bash
# Search repositories
mcp github search_repositories '{"query": "mcp language:rust"}'

# Get file contents
mcp github get_file_contents '{"owner": "anthropics", "repo": "mcp", "path": "README.md"}'
```

## Honeycomb

Query datasets, explore traces, manage columns.

**Add the server:**

```bash
mcp add --url https://mcp.honeycomb.io/mcp honeycomb
```

**Authenticate:**

On first connect, `mcp` will prompt for your API key:

```
This server requires a Honeycomb API Key.

  How: Go to Account → API Keys → Create API Key
  URL: https://ui.honeycomb.io/account

Enter access token for https://mcp.honeycomb.io:
>
```

Or use OAuth if your Honeycomb setup supports it.

**Example usage:**

```bash
mcp honeycomb --list
```

## Roam Research

Read and write to your Roam graph.

**Add the server:**

```bash
mcp add roam
```

**Set environment variable:**

Get a Graph API Token from your Roam settings.

```bash
export ROAM_GRAPH_API_TOKEN="roam-graph-token-..."
```

**Example usage:**

```bash
# Search pages
mcp roam search '{"query": "project ideas"}'

# Get a page
mcp roam get_page '{"title": "Daily Notes"}'

# Create a block
mcp roam create_block '{"page": "Inbox", "content": "New idea from CLI"}'
```

## Adding any server

The pattern is always the same:

1. **Find it** — `mcp search <name>` or check the server's documentation
2. **Add it** — `mcp add <name>` or `mcp add --url <url> <name>` or edit `servers.json`
3. **Set credentials** — Environment variables or let OAuth handle it
4. **Explore** — `mcp <name> --list` to see available tools
5. **Use it** — `mcp <name> <tool> '{"arg": "value"}'`

Any MCP-compatible server works. If it speaks JSON-RPC 2.0 over stdio or HTTP, `mcp` can talk to it.
