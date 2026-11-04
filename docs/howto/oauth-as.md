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
| `trustedIssuers` | no | `[]` | Identity providers whose signed assertions are exchanged for a token with no consent screen. Empty leaves the `jwt-bearer` grant off. See [Enterprise Managed Authorization](#enterprise-managed-authorization-id-jag). |
| `staticClients` | no | `[]` | Clients that exist without Dynamic Client Registration. Required for managed authorization: the `client_id` an identity provider stamps into an assertion can never be one DCR minted. |

Each entry of `trustedIssuers`:

| Field | Required | Default | Notes |
|---|---|---|---|
| `issuer` | yes | — | Compared byte for byte against the assertion's `iss`. Must be `https://`. A prefix or host match would admit another customer's users. |
| `tenantId` | no | — | Matched against the assertion's `aud_tenant` to pick between entries that share an `issuer`. Omit it and the entry vouches for every workspace behind that issuer. `""` is rejected at boot, because an env var that expanded to nothing is not the same decision as leaving the key out. |
| `allowedEmailDomains` | yes | — | Domains this issuer may vouch for. **Boot fails on an empty list**, because identity here is the `email` claim and nothing else, so without the list every account the issuer cares to sign for is admitted. |
| `roles` | no | `[]` | Roles granted to users arriving through this issuer. Read from this config, never from the assertion. |

Each entry of `staticClients`:

| Field | Required | Default | Notes |
|---|---|---|---|
| `clientId` | yes | — | The `client_id` the identity provider stamps into every assertion. Must be byte-identical to the value configured on the connector, and you choose it rather than reading it off the Claude console. Listing the same id twice fails boot, and a DCR registration with the same id takes precedence. |

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

## Enterprise Managed Authorization (ID-JAG)

With `trustedIssuers` configured, `mcp serve` accepts a second way in. A
client presents a JWT that an identity provider already signed, and gets an
access token back. No browser, no consent screen, no `/authorize`.

The assertion is an [Identity Assertion JWT Authorization Grant][id-jag]
(ID-JAG), presented on the [RFC 7523][rfc7523] grant type
`urn:ietf:params:oauth:grant-type:jwt-bearer`. MCP specifies the exchange as
the [`enterprise-managed-authorization` extension][mcp-ema] (stable revision
[2026-07-28][mcp-ema-spec]). Anthropic documents its half as
[Enterprise Managed Auth][claude-ema].

There is no consent screen because the consent already happened somewhere
else. The customer's admin decided, inside their own identity provider, that
this connector may act for their users. Nothing is left for the user to
approve, which is exactly why what the assertion claims has to be checked to
the letter.

Two blocks added to the `oauthAs` config above turn it on. Nothing else
changes, and nothing existing is affected:

```json
{
  "oauthAs": {
    "trustedIssuers": [
      {
        "issuer": "https://identity.anthropic.com/issuers/${MCP_CLAUDE_ISSUER_ID}",
        "allowedEmailDomains": ["example.com"],
        "roles": ["business"]
      }
    ],
    "staticClients": [{ "clientId": "${MCP_CLAUDE_CLIENT_ID}" }]
  }
}
```

`${VAR}` placeholders resolve from the environment, and a **missing or empty
variable expands to an empty string** rather than failing. The two unset
variables then fail in different ways, neither of them convenient:

- An empty `clientId` is rejected by the boot validation. On `replicas: 1`
  with `strategy: Recreate` there is no old pod left to serve traffic, so the
  deploy takes the whole proxy down, not just this grant.
- An unset issuer id leaves `issuer` a valid-looking URL with nothing on the
  end. The process boots, and then every exchange is refused with `assertion
  issuer is not trusted`.

Set the environment variables in the deploy that adds this config, not after.

### When Claude uses it

Claude runs the exchange when the MCP server answers a tool call with `401
Unauthorized` **and** the user's organization has managed authorization
configured for that connector. It runs it *instead of* showing the Connect
card, not alongside it ([Claude docs][claude-ema]).

That substitution is the fact to plan a rollout around. Once an admin turns it
on, the interactive OAuth flow stops being the fallback for those users. If
the grant is broken they do not get a Connect card, they get nothing. Have the
grant answering before anyone clicks through the setup.

A server that never answers `401` never reaches the exchange at all. Managed
authorization does not apply to authless servers, and the `401` it keys off is
the same one that drives [lazy authentication][claude-lazy-auth].

### What Claude checks before it sends an assertion

Three conditions, all read off
`/.well-known/oauth-authorization-server`
([authorization server requirements][claude-ema-requirements]):

- `grant_types_supported` lists
  `urn:ietf:params:oauth:grant-type:jwt-bearer`. Anthropic is explicit that
  the grant has to be advertised there even when the token endpoint already
  accepts it.
- `issuer` is identical to the URL the metadata was fetched from, as
  [RFC 8414 §3.3][rfc8414-s3.3] requires.
- `token_endpoint` is on the same registrable domain as `issuer`.

```bash
curl -s https://mcp.example.com/.well-known/oauth-authorization-server \
  | jq '{issuer, token_endpoint, grant_types_supported}'
```

A reverse proxy rewriting the host breaks the second condition and the first
two are the usual cause of "configured, but Claude never tries the exchange".
Claude also does not follow redirects on the token request, so the
`token_endpoint` has to answer at the URL it publishes.

### Where the issuer URL comes from

The customer's Claude admin sets this up under Settings → Connectors → the
connector → Managed authorization → Set up. The flow needs a Team or
Enterprise plan. The issuer URL it produces is what goes into
`trustedIssuers[].issuer`.

For a Claude-issued setup that URL looks like
`https://identity.anthropic.com/issuers/<id>`, and its discovery document
sits at `<issuer>/.well-known/openid-configuration`. That document carries
`issuer` and `jwks_uri` and nothing else (no `authorization_endpoint`, no
`token_endpoint`) ([Claude docs][claude-ema-issuers]). `mcp serve` reads the
two fields directly instead of handing the document to a full OpenID Connect
client, which would reject it for the fields it does not have.

### The `client_id` is yours to pick, and it has to match in two places

It does **not** come out of the Claude console. You choose the value, and it
goes in two places that must be byte-identical:

1. `serverAuth.oauthAs.staticClients[].clientId`, here
2. the OAuth client ID field in the connector's managed-authorization setup

The identity provider stamps that value into the `client_id` claim of every
assertion it signs, and check 6 below compares it against the `client_id` on
the `/token` form. One character of difference fails every exchange.

### Why `staticClients` exists, and what it is not

Dynamic Client Registration cannot serve this flow. DCR mints an identifier
of its own (`mcp_<hex>` here) that nobody ever told the identity provider, so
it never matches the `client_id` the provider stamps. Anthropic says so
outright ([Claude docs][claude-ema]), and the MCP spec has separately
[deprecated DCR][mcp-client-registration] in favour of Client ID Metadata
Documents.

`staticClients` is the answer, and its job is narrower than it looks. **It
takes no part in validating an assertion.** The `trustedIssuers` entry has no
`clientId` field, and nothing on the assertion path reads this list. It exists
because the JWT provider refuses any access token whose `aud` is not a
registered client (the same check that makes deregistering a client revoke its
tokens), and a token minted for a provider-stamped `client_id` has no DCR
record to point at.

Check 6 does compare the assertion's `client_id` against the request's, but
both values arrive from the caller, so on its own it proves nothing about
registration. The registration check is the one in the provider, and
`staticClients` is what lets it pass.

A client registered through DCR wins over a `staticClients` entry with the
same id.

### Roles come from this config, never from the assertion

`trustedIssuers[].roles`, plus whatever `injectedRoles` adds, is the whole
role set a user arriving through that issuer gets. No claim in the assertion
can add one.

The signer is someone else's identity provider. A group claim it mints is a
privilege decision taken outside your configuration, so honouring it would
make their config an escalation path into yours. Anthropic's own assertions
sidestep the question by carrying no group claims at all. They state the
user's email and say nothing about how the user signed in, not even whether
MFA was involved ([claim reference][claude-ema-claims]). The rule holds for
every issuer you add.

### Identity is the `email` claim, which is why `allowedEmailDomains` is mandatory

This AS has no user database. `sub` resolves against nothing here, so the
subject of the issued token is the `email` claim, lowercased. Boot fails on an
empty `allowedEmailDomains` because that list is the only thing between the
grant and anyone the issuer cares to vouch for.

Anthropic states the risk plainly: an issuer URL is not a secret, whoever runs
an identity provider can put any address in `email`, and someone can register
another customer's issuer URL, or an identity provider of their own, in a
workspace they control ([Claude docs][claude-ema-validate]). The guidance is
to accept `email` only on a domain you have verified. Here, that verified
domain *is* this list.

Three details of the comparison, all deliberate:

- The domain is matched whole, never as a suffix, so `evilexample.com` does
  not pass for `example.com`.
- A non-ASCII address is refused before anything normalizes it. Unicode case
  folding maps U+212A (KELVIN SIGN) onto ASCII `k`, so a domain spelled with
  that character would reach the comparison as `bank.com`.
- An assertion with no `email` is refused rather than falling back to `sub`.

**If you arrived from the MCP extension**, note the divergence. The extension
says to match users on `sub` first and fall back to `email`. Anthropic says
the opposite for Claude-issued assertions: `sub` is opaque, differs under each
issuer, and does not match the subject your product receives through SSO, so
find the user by `email` ([Claude docs][claude-ema-claude-issued]). This
implementation follows Anthropic. It is a choice, not a bug.

### An entry without `tenantId`

`aud_tenant` is the assertion's answer to "which of your customers is this",
for products where one issuer URL serves several workspaces. Leave `tenantId`
out and the entry matches every assertion from its issuer, whatever
`aud_tenant` says. That is the minimal configuration, and the right one when
an issuer serves exactly one workspace.

`aud_tenant` only chooses the entry. The issuer check still runs against that
entry's configured `issuer`, and the roles and allowed domains come from the
entry it selected. That resolution runs twice, the second time against the
signed payload, so an unsigned `aud_tenant` is never what picked the role set.
Claude does not inspect the value either. It is yours to assign.

Two entries sharing an `issuer` need `tenantId` on both. An assertion that
could match two is refused as ambiguous instead of silently taking the first,
and a config whose entries cannot each resolve to themselves fails at boot
rather than at exchange time.

### The nine checks

Every assertion runs the full sequence from
[Validate the identity assertion][claude-ema-validate], in that order. The
order is load-bearing: the issuer is settled before any key is fetched, and
the `jti` is burned last, so an assertion refused for any other reason never
consumes the `jti` of one that would have been accepted.

0. Which `trustedIssuers` entry applies, from `iss` and `aud_tenant`.
1. `iss` equals that entry's `issuer` as an exact string.
2. The key comes from `<iss>/.well-known/openid-configuration` → `jwks_uri`
   ([RFC 7517][rfc7517]). The assertion's own `jwk`, `jku` and `x5u` headers
   are ignored, and no single key is pinned: a token that brings its own key
   is a token that verifies itself.
3. The signature verifies. `alg` is pinned to ES256 or RS256 *before* the key
   fetch. `none` never parses as an algorithm at all, and HS256, which would
   verify against this AS's own `jwtSecret`, is refused at that first check.
   Claude-issued assertions use ES256.
4. `typ` is `oauth-id-jag+jwt`.
5. `aud` is this AS's `issuerUrl`, as a string or a one-element array.
   Trailing slashes are trimmed on both sides, the same way the metadata
   endpoint trims them.
6. The `client_id` claim equals the `client_id` on the request.
7. `sub` is present and non-empty.
8. `exp` has not passed, `iat` is not in the future, and `nbf`, when present,
   has passed. Clock skew allowed: **60 seconds**, on every time claim. An
   `exp` more than an hour out is refused as well. That ceiling exists to
   bound the replay cache, not to second-guess the issuer's lifetime.
9. `jti` is present and has not been redeemed before under this issuer.
   Uniqueness is per issuer ([RFC 7519 §4.1.7][rfc7519-jti]), so the cache is
   keyed by the pair. A `jti` whose status cannot be determined is refused.

Every failure comes back to the client as `invalid_grant`, which is what
[RFC 7523 §3][rfc7523-s3] requires, with a deliberately uninformative
`error_description`. Troubleshooting that string is
[its own table below](#why-an-identity-assertion-was-refused).

### The access token's lifetime is your offboarding window

When a user is removed from the customer's Claude organization, Claude stops
signing assertions for them. Tokens already issued stay valid
([Claude docs][claude-ema-lifetime]). So `accessTokenTtlSeconds` (one hour by
default) is how long a removed user keeps access, and there is no shorter
path. Pick it with that in mind, not just with session comfort in mind.

This grant issues no refresh token, which is what keeps that bound true: a
client holding only an access token has to come back with a fresh assertion,
and after offboarding there is none to be had. It also caps what a replayed
assertion would buy, if the `jti` check had missed one. The interactive
`authorization_code` flow keeps issuing refresh tokens as before.

> **Known divergence.** Access tokens this AS issues carry `aud = client_id`,
> not the `resource` the request named ([RFC 8707][rfc8707]). The `resource`
> parameter is accepted, present or absent, and does not change the token's
> audience. `aud = client_id` is what the provider's registered-client check
> reads, so changing it would invalidate every token in circulation. Recorded
> here rather than quietly adjusted.

### JWKS cache

Verification keys are fetched on demand and cached per `(issuer, kid)`.

- **TTL** comes from the key set's own `Cache-Control: max-age`, clamped to
  **60s–3600s**. With no `max-age` the cache uses **300s**. The floor stops an
  issuer advertising `max-age=0` from turning every exchange into two
  round-trips. The ceiling bounds how long a key the issuer retired stays
  usable here.
- **Key rotation needs no restart.** A `kid` that is not cached earns one
  refetch, and a successful refresh replaces everything cached for that
  issuer, so a dropped key stops working as soon as it leaves the document.
- **An unknown `kid` is cheap to refuse.** For 60 seconds after a successful
  read, a `kid` missing from that key set is refused without touching the
  network, so invented `kid`s cannot be turned into traffic against the
  issuer. A *failed* refresh arms nothing, on purpose: a broken issuer has to
  stay retryable.
- **Both fetches happen inside one `/token` request**, 2s timeout each. The
  budget is Claude's. It gives the token endpoint 10 seconds before reporting a
  connection failure, and a cold-cache exchange spends two fetches, two TLS
  handshakes and a signature verification inside that.
- A key set is refused whole when it is empty, holds more than 50 keys,
  exceeds 256 KiB, or yields no key this AS can verify with. Refusing it whole
  leaves the previously cached keys in place: a CDN error page that parses as
  an empty JSON key set is not an instruction to forget working keys. In the
  log, an empty document is an issuer or CDN problem, while a full one with
  nothing usable is an algorithm mismatch.

### Replay cache, and the one deploy precondition

Redeemed `jti` values live in memory, keyed by `(issuer, jti)`, each
remembered until its assertion's `exp` plus the 60s skew. The cache holds at
most 100,000 live entries. Past that, an exchange is refused rather than let
through unchecked. **It does not survive a restart and it is not shared
between processes.**

That makes the deployment topology part of the security property:

- **`replicas: 1` with `strategy: Recreate`.** The old pod is gone before the
  new one starts, so the only window in which a `jti` could be redeemed twice
  is the restart gap, and during the gap nothing is answering anyway.
- **`RollingUpdate` breaks it.** Two pods go `Ready` at once, each with an
  empty cache, with a Service picking between them. That is overlap, not a
  gap: the same assertion can be redeemed on both. The [Kubernetes
  guide](kubernetes.md#use-recreate-not-rollingupdate) already calls for
  `Recreate` because of the `ReadWriteOnce` volume. Managed authorization
  gives it a second, independent reason.

Claude's assertions expire in under a minute, and every sign-in and every
renewal gets a fresh one with a new `jti`
([Claude docs][claude-ema-claude-issued]), so the window a restart opens is
small. Small is not zero, and whoever switches to `RollingUpdate` for an
unrelated reason should know what it costs.

## What a `401` tells the client

Every `401` from `/mcp` carries a `WWW-Authenticate` header
([RFC 6750 §3][rfc6750-s3]). The value depends on whether this instance
actually serves an authorization server.

With `oauth_as` in `providers` **and** an `oauthAs` block:

```
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

Otherwise, including when `oauthAs` is configured but `oauth_as` is not in
`providers`:

```
WWW-Authenticate: Bearer
```

The pointer is how a client that knows only the MCP URL finds where to sign
in. [RFC 9728][rfc9728-prm] §5.1 defines the parameter, and MCP's
[authorization server discovery][mcp-as-discovery] builds on it. Both
conditions are required on purpose: the metadata route is mounted only when
`oauth_as` is in `providers`, and advertising a route that answers `404` sends
the client chasing nothing.

The URL is `issuerUrl` with trailing slashes trimmed, the same trim the
metadata handler applies, so the challenge names the route it serves. An
`issuerUrl` holding a double quote or a control character is rejected at boot,
because the value is echoed into this header, and a malformed header leaves a
`401` that tells the client nothing. If the challenge cannot be represented at
all, the header is dropped and the `401` still stands. It never becomes a
`500`.

## What a reload applies, and what needs a restart

`POST /reload` (and `SIGHUP`) re-reads `servers.json` and swaps what it can
swap. For `oauthAs` the split is:

| Field | Applied by a reload |
|---|---|
| `staticClients` | **Yes.** The configured clients are replaced wholesale, so dropping an entry rejects the tokens issued under that id on the next request. |
| `acl`, `adminRoles` | Yes. Siblings of `oauthAs`, listed here because they decide what an OAuth identity can do once it is in. |
| `trustedIssuers`, `jwtSecret`, `injectedRoles`, the TTLs, `trustedUserHeader`, `trustedGroupsHeader`, `trustedSourceCidrs`, `redirectUriAllowlist`, `scopesSupported` | **Treat as restart-only.** The token *validator* is rebuilt from the new values, but `/authorize`, `/token`, `/register` and the metadata endpoints still run on the config this process booted with: that sub-router is built once, around the listener. A new trusted issuer does not start working, and the reload does not say so. |
| `issuerUrl` | **No**, and the reload does say so: it comes back in `requires_restart`. |
| `oauth_as` added to or removed from `providers` | **No.** Same reason, plus the on-disk client store is wired before the listener exists. Reported in `requires_restart`, and the rest of the reload still applies. |

A reload that changes `issuerUrl` is worse than a no-op, which is why the
field is reported rather than quietly ignored. The validator picks up the new
value while `/token` keeps minting `iss` under the old one, so every token is
rejected until the process restarts. Change it and restart in the same move.

Anthropic makes the same point from outside: keep the published `issuer`
exactly as it is, trailing slash included, because a Claude-issued setup
records the value and a changed one stops sign-ins for that customer
([Claude docs][claude-ema-requirements]). [RFC 8414 §3.3][rfc8414-s3.3] is the
other half of the constraint. The `issuer` in the metadata has to match the
URL the metadata was fetched from.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `403 /authorize must originate from a trusted reverse proxy` | Peer IP is not in `trustedSourceCidrs`. |
| `400 redirect_uri rejected: …` | URI not in `redirectUriAllowlist` *or* not registered by the client. |
| `400 invalid_grant` on `/token` | On `authorization_code`: code expired (60s default), already used, or PKCE verifier doesn't match. On `jwt-bearer`: see [Why an identity assertion was refused](#why-an-identity-assertion-was-refused). |
| Claude.ai: "couldn't connect" with no error | The discovery endpoints returned non-JSON or 5xx. Curl them. |
| `issuer mismatch in OAuth callback` | The AS returned an `iss` that doesn't match its advertised `issuer`. Check `issuerUrl` against what `/.well-known/oauth-authorization-server` publishes. |
| `authorization server metadata declares issuer … but was fetched from …` | RFC 8414 §3.3 violation: `issuerUrl` doesn't match the origin serving the metadata. Usually a reverse proxy rewriting the host. |
| Boot fails: `oauthAs.jwtSecret must be at least 32 bytes` | The env var is empty or shorter. |
| Boot fails: `oauthAs.trustedSourceCidrs must list at least one CIDR` | The anti-spoof list was left empty. |
| Boot fails: `oauthAs.trustedIssuers[N].allowedEmailDomains must list at least one domain` | An issuer entry with no domain allowlist. See [why it is mandatory](#identity-is-the-email-claim-which-is-why-allowedemaildomains-is-mandatory). |
| Boot fails: `oauthAs.trustedIssuers[N] is not uniquely addressable` | Two entries share an `issuer` and cannot be told apart (the same `issuer` and `tenantId` twice, or a tenant-less twin of a tenanted entry). |
| Boot fails: `oauthAs.staticClients must not list the same clientId twice` | A duplicate would be silently dropped by the map it is stored in, so it fails instead. |

### Why an identity assertion was refused

Every refusal of the `jwt-bearer` grant is an `invalid_grant` with a generic
`error_description` ([RFC 7523 §3][rfc7523-s3]). That is deliberate, so the
wording cannot become an oracle for someone probing the config. It also means
the string is the only thing an operator has to go on. This is the mapping.

| `error_description` | Likely cause | Where to look |
|---|---|---|
| `assertion header is malformed` | The `assertion` form field is not a JWT. | What the client actually posted. |
| `assertion alg must be ES256 or RS256` | The header offers something else: `none`, or an HMAC algorithm such as HS256. Refused before any key is fetched. | The issuer's signing configuration. Claude-issued assertions use ES256. |
| `assertion header carries no kid` | No `kid`, so no key can be selected. | The issuer's key set and how it signs. |
| `assertion payload is malformed` | Three base64 segments, but the middle one is not JSON this AS can read. | The issuer. |
| `assertion issuer is not trusted` | `iss` matches no `trustedIssuers[].issuer`, **or** it matches one whose `tenantId` is set to something other than the assertion's `aud_tenant`. Compared byte for byte, so a trailing slash or an `http`/`https` difference is a mismatch. | `trustedIssuers` against the issuer URL the Claude setup shows. |
| `assertion issuer is ambiguous, tenant required` | Two entries share this `issuer` and the assertion named no `aud_tenant`, or named one both could serve. | Give each entry a distinct `tenantId` and set the tenant id in the connector setup. |
| `assertion iss does not match the trusted issuer` | A redundant repeat of the exact-match rule, run on both the unverified and the signed payload. Unreachable while issuer resolution keeps comparing byte for byte. | — |
| `assertion signing key could not be resolved` | **The real reason is only in the server log.** Candidates: the issuer was unreachable or answered non-2xx, its discovery document named a different issuer, the key set was not a JWKS, it published no keys, more than 50 keys, a body over 256 KiB, or no key usable for this `kid`. | The `tracing::warn!` line `could not resolve the signing key for an identity assertion`, which carries `issuer`, `kid` and the underlying `error`. |
| `assertion alg does not match its signing key` | The header's `alg` differs from the one the matching JWKS entry declares. | The issuer's key set. |
| `assertion signature is invalid` | Right key, wrong signature, or the assertion was altered in transit. | The issuer. |
| `assertion typ must be oauth-id-jag+jwt` | The header's `typ` is something else, usually plain `JWT`. | The issuer is minting an ordinary JWT, not an ID-JAG. |
| `assertion aud is missing or names more than one audience` | No `aud`, or an array with zero or with two or more entries. A one-element array is fine. | The issuer. |
| `assertion aud is not this authorization server` | `aud` is not `issuerUrl`. The usual cause is `issuerUrl` diverging from what the identity provider was given: a different host, a scheme change, or a reverse proxy rewriting the origin. | `curl https://…/.well-known/oauth-authorization-server` and compare its `issuer` against the connector setup. |
| `assertion client_id does not match the request` | The `client_id` the provider stamps is not the one on the `/token` form. | The two places that have to agree: `staticClients[].clientId` and the connector's OAuth client ID field. |
| `assertion carries no sub` | No `sub`, or empty. | The issuer. |
| `assertion carries no exp`, `assertion carries no iat` | A required time claim is missing. | The issuer. |
| `assertion has expired` | `exp` is more than 60s in the past. Assertions are short-lived by design (Claude's last under a minute), so a clock off by more than a minute shows up here first. | This host's clock, then the issuer's. |
| `assertion exp is too far in the future` | `exp` more than an hour out. The ceiling bounds the replay cache. | The issuer's assertion lifetime. |
| `assertion iat is in the future`, `assertion is not valid yet` | `iat` or `nbf` more than 60s ahead. | Clock skew between the issuer and this host. |
| `assertion carries no email` | No `email` claim. There is no fallback to `sub`. | The issuer's claim configuration. |
| `assertion email must be ascii` | A non-ASCII address, refused by design before normalization. | — |
| `assertion email is malformed` | No `@`, or an empty local part or domain. | The issuer. |
| `assertion email domain is not allowed for this issuer` | The domain after the last `@` is not in that entry's `allowedEmailDomains`. Matched whole and case-insensitively, never as a suffix. | `allowedEmailDomains` on the entry that `iss` and `aud_tenant` resolved to. |
| `assertion carries no jti` | No `jti`, or empty. Replay cannot be checked without one, so the exchange is refused. | The issuer. |
| `assertion was refused by replay protection` | Either this `(issuer, jti)` was already redeemed, or the cache is at its 100,000-entry cap. One string for both, so the wording cannot be used to read the cache's state. | The log tells them apart: a replay logs at `debug`, a full cache at `warn`, both with `reason`. A replay right after a deploy, or under two pods, means [the cache is not where you think it is](#replay-cache-and-the-one-deploy-precondition). |

Anthropic's [connector troubleshooting guide][claude-troubleshooting] covers
the other side of the exchange, and its
[cases to check before launch][claude-ema-cases] is worth a pass before an
admin turns managed authorization on.

## References

- MCP authorization spec: <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- RFC 7591 — Dynamic Client Registration: <https://www.rfc-editor.org/rfc/rfc7591>
- RFC 8414 — Authorization Server Metadata: <https://www.rfc-editor.org/rfc/rfc8414>
- RFC 9728 — Protected Resource Metadata: <https://www.rfc-editor.org/rfc/rfc9728>
- RFC 9207 — Authorization Server Issuer Identification: <https://www.rfc-editor.org/rfc/rfc9207>
- RFC 7636 — PKCE: <https://www.rfc-editor.org/rfc/rfc7636>
- Claude.ai Custom Connectors: <https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>

For managed authorization specifically:

- Enterprise Managed Auth (Anthropic): <https://claude.com/docs/connectors/building/enterprise-managed-auth>
- MCP `enterprise-managed-authorization` extension: <https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization>
- ID-JAG — Identity Assertion JWT Authorization Grant: <https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/>
- RFC 7523 — JWT profile for OAuth 2.0 authorization grants: <https://datatracker.ietf.org/doc/html/rfc7523>
- RFC 8707 — Resource Indicators: <https://www.rfc-editor.org/rfc/rfc8707.html>
- SEP-990, the proposal this grew from: <https://modelcontextprotocol.io/seps/990-enable-enterprise-idp-policy-controls-during-mcp-o>

[rfc7591]: https://www.rfc-editor.org/rfc/rfc7591
[rfc9207]: https://www.rfc-editor.org/rfc/rfc9207
[rfc8414]: https://www.rfc-editor.org/rfc/rfc8414
[mcp-auth]: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
[oauth2-proxy]: https://oauth2-proxy.github.io/oauth2-proxy/
[src-chain]: https://github.com/avelino/mcp/blob/main/src/server_auth/providers.rs
[id-jag]: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
[rfc7523]: https://datatracker.ietf.org/doc/html/rfc7523
[rfc7523-s3]: https://datatracker.ietf.org/doc/html/rfc7523#section-3
[rfc7517]: https://datatracker.ietf.org/doc/html/rfc7517
[rfc7519-jti]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
[rfc6750-s3]: https://datatracker.ietf.org/doc/html/rfc6750#section-3
[rfc8414-s3.3]: https://datatracker.ietf.org/doc/html/rfc8414#section-3.3
[rfc8707]: https://www.rfc-editor.org/rfc/rfc8707.html
[rfc9728-prm]: https://datatracker.ietf.org/doc/html/rfc9728
[mcp-ema]: https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
[mcp-ema-spec]: https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx
[mcp-client-registration]: https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
[mcp-as-discovery]: https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery
[claude-ema]: https://claude.com/docs/connectors/building/enterprise-managed-auth
[claude-ema-issuers]: https://claude.com/docs/connectors/building/enterprise-managed-auth#who-issues-the-identity-assertion
[claude-ema-requirements]: https://claude.com/docs/connectors/building/enterprise-managed-auth#authorization-server-requirements
[claude-ema-claims]: https://claude.com/docs/connectors/building/enterprise-managed-auth#identity-assertion-claims
[claude-ema-validate]: https://claude.com/docs/connectors/building/enterprise-managed-auth#validate-the-identity-assertion
[claude-ema-claude-issued]: https://claude.com/docs/connectors/building/enterprise-managed-auth#claude-issued-assertions
[claude-ema-lifetime]: https://claude.com/docs/connectors/building/enterprise-managed-auth#access-token-lifetime
[claude-ema-cases]: https://claude.com/docs/connectors/building/enterprise-managed-auth#cases-to-check-before-launch
[claude-lazy-auth]: https://claude.com/docs/connectors/building/lazy-authentication
[claude-troubleshooting]: https://claude.com/docs/connectors/building/troubleshooting
