# OAuth Authorization Server — connect Claude.ai, ChatGPT, Cursor

`mcp serve` ships an OAuth 2.0 Authorization Server with Dynamic
Client Registration ([RFC 7591][rfc7591]). It lets you plug a self-hosted
proxy directly into Claude.ai, ChatGPT, Cursor and other AI clients
that consume the [MCP authorization spec][mcp-auth] — no static
bearer token to share, no extra OAuth infra in the middle.

## Why this exists

Before `oauth_as`:

- `BearerTokenAuth` (static `subject → token` map) is fine for local
  dev and CI but Claude.ai-style clients refuse to connect to it.
- `ForwardedUserAuth` works only when a separate IdP-aware reverse
  proxy is in front. That's a heavy lift just to expose a fleet of
  MCP servers to your AI tools.

`oauth_as` makes `mcp serve` itself the Authorization Server — but
delegates *user* authentication to a trusted reverse proxy
(oauth2-proxy, Cloudflare Access, Pomerium, anything that sets
`X-Forwarded-User`). MCP never handles passwords. The OAuth flow
just wraps the SSO session that already exists.

## Architecture

```
+----------+    +----------------+    +-------------------+
| Claude   |--->|  oauth2-proxy  |--->|    mcp serve      |
|  / etc.  |    |  (your IdP)    |    | OAuth AS + /mcp   |
+----------+    +----------------+    +-------------------+
   ^  user          ^ SSO session         ^
   | OAuth          | sets headers        | validates JWT
   | flow           | X-Forwarded-User    | on every request
                    | X-Forwarded-Groups
```

The reverse proxy authenticates the human. `mcp serve` reads the
trusted headers at `/authorize` and emits a short-lived authorization
code, then a JWT access token that subsequent `/mcp` requests carry
in `Authorization: Bearer …`.

## Two providers, one endpoint

The most common deployment runs **`oauth_as` and `bearer` in
parallel** on the same instance:

- Local dev / CI uses a static bearer token.
- Claude.ai web uses the OAuth flow.

Both kinds of `Authorization: Bearer …` hit the same `/mcp`. The
[`ProviderChain`][src-chain] tries each provider in order and the
first one that accepts wins. ACL discriminates per role (see below),
so static-bearer and OAuth identities can have completely different
permissions on the same set of backends.

## Configure `serverAuth`

Drop this into `servers.json` (the working `mcp serve` config file):

```json
{
  "serverAuth": {
    "providers": ["bearer", "oauth_as"],

    "bearer": {
      "tokens": {
        "tok-local-dev": { "subject": "avelino", "roles": ["admin"] }
      }
    },

    "oauthAs": {
      "issuerUrl": "https://mcp.example.com",
      "jwtSecret": "${MCP_OAUTH_AS_JWT_SECRET}",
      "trustedUserHeader": "x-forwarded-user",
      "trustedGroupsHeader": "x-forwarded-groups",
      "trustedSourceCidrs": ["127.0.0.1/32", "10.0.0.0/8"],
      "accessTokenTtlSeconds": 3600,
      "refreshTokenTtlSeconds": 2592000,
      "authorizationCodeTtlSeconds": 60,
      "scopesSupported": ["mcp"],
      "redirectUriAllowlist": [
        "https://claude.ai/api/mcp/auth_callback",
        "https://chat.openai.com/aip/*/oauth/callback"
      ],
      "injectedRoles": ["oauth-user"]
    },

    "acl": {
      "default": "deny",
      "rules": [
        { "roles": ["admin"],      "tools": ["*"],         "policy": "allow" },
        { "roles": ["oauth-user"], "tools": ["sentry__*"], "policy": "allow" }
      ]
    }
  }
}
```

Field-by-field for `oauthAs`:

| Field | Required | Default | Notes |
|---|---|---|---|
| `issuerUrl` | yes | — | Public HTTPS URL the AS advertises. Must match what clients reach. |
| `jwtSecret` | yes | — | HMAC-SHA256 signing key. **≥ 32 bytes.** Boot fails otherwise. |
| `trustedUserHeader` | no | `x-forwarded-user` | The header your reverse proxy sets. |
| `trustedGroupsHeader` | no | `x-forwarded-groups` | Comma-separated → JWT `groups` claim. |
| `trustedSourceCidrs` | yes | — | CIDRs allowed to reach `/authorize`. **Empty list rejected at boot** — without it any client could spoof `X-Forwarded-User`. |
| `accessTokenTtlSeconds` | no | `3600` | JWT lifetime. |
| `refreshTokenTtlSeconds` | no | `2592000` (30d) | Refresh token lifetime. |
| `authorizationCodeTtlSeconds` | no | `60` | Code lifetime. |
| `scopesSupported` | no | `[]` | Advertised in metadata. |
| `redirectUriAllowlist` | yes | — | Patterns clients may register. Trailing `*` for ChatGPT-style URIs. |
| `injectedRoles` | no | `[]` | Roles always added to issued JWTs. Marker for ACL discrimination. |

## How `injectedRoles` filters which mcpServers an AI client can use

Tools are routed to backends by prefix: `sentry__list_issues` lives
in the `sentry` backend, `github__create_issue` in `github`, and so
on. `injectedRoles: ["oauth-user"]` stamps every OAuth-issued JWT
with the `oauth-user` role. Combine that with an ACL rule like
`{"roles": ["oauth-user"], "tools": ["sentry__*"], "policy": "allow"}`
and Claude.ai web sees only `sentry` tools, while your local-dev
admin token still sees everything.

There's no special "OAuth user" path in the dispatcher. The same
`is_tool_allowed` evaluator that gates static-bearer requests gates
JWT requests too.

## Run it

1. **Generate the JWT secret** (32+ random bytes, kept out of the
   config file):

   ```bash
   export MCP_OAUTH_AS_JWT_SECRET=$(openssl rand -hex 32)
   ```

2. **Front it with oauth2-proxy** (or Cloudflare Access, Pomerium,
   etc.) so all traffic to `mcp serve` already has
   `X-Forwarded-User` set. The [oauth2-proxy quickstart][oauth2-proxy]
   walks through pointing it at Google / GitHub / Okta.

3. **Boot the proxy**:

   ```bash
   mcp serve --bind 127.0.0.1:8080
   ```

   Bind to loopback so only the reverse proxy can reach it. Anything
   else needs `--insecure`.

4. **Validate the discovery endpoints** before pointing a client at
   it:

   ```bash
   curl https://mcp.example.com/.well-known/oauth-protected-resource
   curl https://mcp.example.com/.well-known/oauth-authorization-server
   ```

   Both must return JSON. Empty bodies or HTML pages mean the
   provider isn't enabled or the proxy isn't routing the path.

5. **Connect from Claude.ai**:
   - Settings → Connectors → "Add custom connector"
   - URL: `https://mcp.example.com/mcp`
   - Authenticate with whatever IdP your reverse proxy uses
   - Tools should appear once the OAuth flow completes

The same URL works in ChatGPT (admin → connectors) and Cursor
(settings → MCP).

## State persistence

`oauth_as` persists registered clients and refresh tokens to
`auth_server.json` in the config dir. Inflight authorization codes
are *not* persisted — restart drops them, which is the safer default
than letting captured codes resume post-restart.

Override the location with `MCP_AUTH_SERVER_PATH=/path/to/file`, or
inline the whole content with `MCP_AUTH_SERVER_CONFIG='{"clients":{}, "refresh_tokens":{}}'`.
The inline mode is for read-only Secret mounts in Kubernetes — same
contract as `MCP_AUTH_CONFIG` for the client store.

### Losing this file logs everyone out immediately

This is not "you lose some history". Point `MCP_AUTH_SERVER_PATH` at ephemeral storage and **every restart forces every user to reconnect the MCP by hand.**

Two things break at once:

1. **Access tokens die instantly, even unexpired ones.** Before verifying a signature, the provider checks that the token's `aud` refers to a registered client, so a token whose DCR registration is gone is rejected no matter how much TTL is left. Revoking a client *should* kill its tokens — that same check turns a wiped state file into a fleet-wide revocation.
2. **Refresh tokens are gone too**, so there is no silent recovery. The client cannot refresh; it has to re-register via DCR and send the user back through the browser.

The signing secret is not enough on its own. Tokens are stateless JWTs, but the registered-client check makes verification depend on this file, so a stable `jwtSecret` with a wiped state file still rejects everything.

Durable storage is the requirement. On Kubernetes that means a PersistentVolumeClaim, not an `emptyDir` — see [Kubernetes: OAuth AS state](kubernetes.md#oauth-as-state-needs-a-persistent-volume).

Even with durable storage, users still re-authenticate when the `jwtSecret` rotates, or when they go idle past the refresh token TTL (`refreshTokenTtlSeconds`, 30d by default).

## Security notes

- **`trustedSourceCidrs` is mandatory.** With an empty list, any
  client could send a request directly to `mcp serve` carrying a
  forged `X-Forwarded-User` and walk away with an authorization
  code. The boot path refuses to start without at least one CIDR.

- **HTTPS issuer.** Setting `issuerUrl` to plain `http://` works
  technically but means tokens flow in cleartext. Document this for
  your auditors if you intentionally chose plain HTTP for an
  internal-only deployment.

- **JWT secret rotation invalidates all existing tokens.** v1 has no
  in-place rotation. Plan for a forced re-login when you change the
  secret.

- **PKCE S256 only.** The metadata advertises only `S256`. Clients
  attempting `plain` are rejected at `/authorize`. This is the
  OAuth 2.1 / MCP authorization spec baseline.

- **Refresh tokens rotate** on every successful refresh. A captured
  refresh token is valid for one use at most.

- **Authorization responses carry `iss`** ([RFC 9207][rfc9207]). The
  redirect back to the client appends `iss=<issuerUrl>` next to `code`
  and `state`, normalized the same way the metadata endpoint
  normalizes it (trailing slash trimmed), so the client's string
  comparison matches. This closes the AS mix-up attack: a client
  running flows against several authorization servers can prove the
  code came from the one it started with.

  The `mcp` client validates `iss` **when it is present** and fails
  the flow on a mismatch. An authorization server that sends no `iss`
  keeps working unchanged.

- **Discovery documents are validated against where they came from**
  ([RFC 8414][rfc8414] §3.3). The `issuer` inside
  `/.well-known/oauth-authorization-server` must be identical to the
  origin the document was fetched from, or the client aborts. Without
  that check, a hostile server could declare any issuer it liked — and
  the issuer is exactly what the `iss` comparison above and the client
  registration key below are built on. A document that omits `issuer`
  altogether is still accepted: hand-rolled metadata routinely does,
  and there is no identity to reject on.

## Client registrations are bound to the issuer

On the client side, `mcp` stores the `client_id` it obtained from
Dynamic Client Registration keyed by the **authorization server's
`issuer`**, not by the MCP server URL. One AS's `client_id` is never
replayed against another, even for the same MCP server. Access and
refresh tokens stay keyed by MCP server URL — they are scoped to the
resource server, not the issuer.

Stores written by older builds keyed registrations by MCP server URL.
They are migrated in place on first read: `auth.json` gains a
`version` field and the old entries move to `legacy_clients`, where
they keep working. Each one is re-keyed under an issuer only once a
token exchange with that issuer has actually succeeded — a server
merely *claiming* an issuer never gets to adopt a credential, which
would let it overwrite that issuer's registration. **Nothing has to be
re-registered and nobody has to re-login.**

Registration requests now also send `application_type: "native"`
(SEP-837), which is what stops OIDC-flavored authorization servers
from rejecting localhost redirect URIs. `mcp serve`'s own AS accepts
the field, echoes it back per RFC 7591 §3.2.1 when sent, and imposes
no redirect constraints from it — clients that omit it are equally
fine.

## DCR is deprecated (but still supported)

MCP 2026-07-28 deprecates Dynamic Client Registration in favour of
Client ID Metadata Documents (CIMD), with a 12-month window before
removal. `mcp serve` **keeps its `/register` endpoint working** and
the client keeps using it — nothing in this guide changes today. CIMD
is not implemented yet.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `403 /authorize must originate from a trusted reverse proxy` | Peer IP is not in `trustedSourceCidrs`. |
| `400 redirect_uri rejected: …` | URI not in `redirectUriAllowlist` *or* not registered by the client. |
| `400 invalid_grant` on `/token` | Code expired (60s default), already used, or PKCE verifier doesn't match. |
| Claude.ai: "couldn't connect" with no error | The discovery endpoints returned non-JSON or 5xx. Curl them. |
| `issuer mismatch in OAuth callback` | The AS returned an `iss` that doesn't match its advertised `issuer`. Check `issuerUrl` against what `/.well-known/oauth-authorization-server` publishes. |
| `authorization server metadata declares issuer … but was fetched from …` | RFC 8414 §3.3 violation: `issuerUrl` doesn't match the origin serving the metadata. Usually a reverse proxy rewriting the host. |
| Boot fails: `oauthAs.jwtSecret must be at least 32 bytes` | The env var is empty or shorter. |
| Boot fails: `oauthAs.trustedSourceCidrs must list at least one CIDR` | The anti-spoof list was left empty. |

## References

- MCP authorization spec: <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- RFC 7591 — Dynamic Client Registration: <https://www.rfc-editor.org/rfc/rfc7591>
- RFC 8414 — Authorization Server Metadata: <https://www.rfc-editor.org/rfc/rfc8414>
- RFC 9728 — Protected Resource Metadata: <https://www.rfc-editor.org/rfc/rfc9728>
- RFC 9207 — Authorization Server Issuer Identification: <https://www.rfc-editor.org/rfc/rfc9207>
- RFC 7636 — PKCE: <https://www.rfc-editor.org/rfc/rfc7636>
- Claude.ai Custom Connectors: <https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>

[rfc7591]: https://www.rfc-editor.org/rfc/rfc7591
[rfc9207]: https://www.rfc-editor.org/rfc/rfc9207
[rfc8414]: https://www.rfc-editor.org/rfc/rfc8414
[mcp-auth]: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
[oauth2-proxy]: https://oauth2-proxy.github.io/oauth2-proxy/
[src-chain]: https://github.com/avelino/mcp/blob/main/src/server_auth/providers.rs
