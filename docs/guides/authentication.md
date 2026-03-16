# Authentication

`mcp` supports multiple authentication methods. For most services, authentication is automatic — you just connect and `mcp` handles the rest.

## How it works

When you call a tool on an HTTP server, `mcp` follows this sequence:

1. **Check for saved token** — Look in `~/.config/mcp/auth.json` for a valid, non-expired token
2. **Check config headers** — Use `Authorization` header from config if present
3. **On 401 response** — Start the authentication flow:
   - Try OAuth 2.0 (discovery + PKCE flow)
   - Fall back to manual token prompt

Tokens are stored per server URL and refreshed automatically when they expire.

## OAuth 2.0 (automatic)

Services like Sentry support OAuth 2.0 with the MCP protocol. When you first connect:

```bash
mcp sentry --list
```

```
Authenticating with https://mcp.sentry.dev...
Opening browser for authorization...
```

Your browser opens, you authorize the app, and the token is saved. Next time, it just works.

### What happens under the hood

1. `mcp` checks the server for [OAuth Protected Resource Metadata](https://datatracker.ietf.org/doc/rfc9728/) to find the authorization server
2. Fetches the OAuth Authorization Server Metadata (`.well-known/oauth-authorization-server`)
3. Registers as a client using [Dynamic Client Registration](https://datatracker.ietf.org/doc/rfc7591/) if supported
4. Generates a PKCE challenge (S256) for security
5. Opens your browser to the authorization URL
6. Listens on a local port (`localhost:8085-8099`) for the callback
7. Exchanges the authorization code for tokens
8. Saves tokens to `~/.config/mcp/auth.json`

### Token refresh

When a token expires, `mcp` automatically tries to refresh it using the refresh token. If that fails, it starts the OAuth flow again.

## Manual token (interactive)

If a server doesn't support OAuth, `mcp` falls back to asking for a token. It recognizes popular services and shows helpful instructions:

```
This server requires a Honeycomb API Key.

  How: Go to Account → API Keys → Create API Key
  URL: https://ui.honeycomb.io/account

Enter access token for https://mcp.honeycomb.io:
>
```

Paste your token, press Enter. It's saved and used for future requests.

### Recognized services

`mcp` has built-in hints for these services:

| Service | Token type | Where to get it |
|---|---|---|
| Honeycomb | API Key | Account → API Keys |
| GitHub | Personal Access Token | Settings → Developer settings → Personal access tokens |
| Sentry | Auth Token | Settings → Account → API → Auth Tokens |
| Linear | API Key | Settings → API → Personal API Keys |
| Notion | Integration Token | My Integrations → Create integration |
| Slack | Bot/User Token | Your app → OAuth & Permissions |
| Grafana | Service Account Token | Administration → Service Accounts |
| GitLab | Personal Access Token | User Settings → Access Tokens |
| Jira | API Token | Manage profile → Security → API tokens |
| Cloudflare | API Token | Profile → API Tokens |
| Datadog | API Key | Organization Settings → API Keys |
| PagerDuty | API Key | User Settings → Create API User Token |

For unrecognized services, you get a generic prompt.

## Config-based authentication

You can set auth headers directly in the config file:

```json
{
  "mcpServers": {
    "my-api": {
      "url": "https://api.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${MY_TOKEN}"
      }
    }
  }
}
```

Use `${ENV_VAR}` to avoid hardcoding secrets. Set the env var in your shell profile:

```bash
export MY_TOKEN="your-token-here"
```

### Empty tokens are skipped

If an env var is not set, the `Authorization` header resolves to `Bearer ` (empty token). `mcp` detects this and skips the header, falling back to OAuth or manual auth instead.

## Token storage

Tokens are saved in `~/.config/mcp/auth.json`:

```json
{
  "clients": {
    "https://mcp.sentry.dev": {
      "client_id": "abc123"
    }
  },
  "tokens": {
    "https://mcp.sentry.dev": {
      "access_token": "sntrys_...",
      "refresh_token": "sntryr_...",
      "expires_at": 1710000000
    }
  }
}
```

- **`clients`** — OAuth client registrations (client ID per server)
- **`tokens`** — Access tokens, refresh tokens, and expiry timestamps

### Clearing tokens

To re-authenticate, delete the entry from `auth.json` or delete the whole file:

```bash
rm ~/.config/mcp/auth.json
```

Next connection will trigger a fresh authentication flow.

## Authentication priority

When multiple auth sources exist, the priority is:

1. **Config headers** — `Authorization` header from `servers.json` (if non-empty)
2. **Saved token** — Token from `auth.json` (loaded on connect)
3. **OAuth flow** — Triggered on 401 response
4. **Manual prompt** — If OAuth registration fails

## Server-side authentication (proxy mode)

The sections above cover **client-side** authentication — how `mcp` authenticates when calling remote MCP servers. When running `mcp serve --http`, the proxy itself can also **authenticate incoming requests** from clients.

This is configured via the `serverAuth` key in `servers.json`. See the [proxy mode guide](proxy-mode.md#authentication) for full details.

### Quick example

```json
{
  "mcpServers": { ... },
  "serverAuth": {
    "provider": "bearer",
    "bearer": {
      "tokens": {
        "tok-alice": "alice",
        "tok-bob": "bob"
      }
    },
    "acl": {
      "default": "allow",
      "rules": [
        { "subjects": ["bob"], "tools": ["sentry__*"], "policy": "deny" }
      ]
    }
  }
}
```

### Available providers

| Provider | Use case |
|----------|----------|
| `none` (default) | No auth — all requests are anonymous |
| `bearer` | Static token-to-user mapping |
| `forwarded` | Trust reverse proxy `X-Forwarded-User` header |

### Access control (ACL)

Rules control which authenticated users can access which tools. Rules are evaluated in order — first match wins. See [proxy mode ACL docs](proxy-mode.md#access-control-acl) for the full rule syntax.
