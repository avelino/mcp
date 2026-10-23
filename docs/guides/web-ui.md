# Web UI

`mcp ui` serves a local web UI from the same binary. It is a view over the same modules the CLI uses — the config file, the tool cache, the audit log, the ACL evaluator and the instance registry — not a second implementation of them.

No Node, no bundler, no asset directory to deploy: templates and the one vendored JavaScript file are compiled into the binary.

```bash
mcp ui
```

```
mcp ui listening on http://127.0.0.1:7332
open: http://127.0.0.1:7332/?token=…
```

Open the printed URL. The token is exchanged for a cookie and removed from the address bar.

## What it shows

| Screen | Content |
|---|---|
| **Overview** | Backends, cached tool counts, calls and denials in the last 24h, running `mcp serve` instances |
| **Servers** | The configured entries, with add (registry, URL, stdio), remove, and per-server detail |
| **Detail** | Cached catalog with read/write classification, and the config **as written**, with secrets redacted |
| **Playground** | A form generated from the tool's `inputSchema`, the JSON-RPC it will send, and the result |
| **Activity** | Audit entries with the ACL decision and the rule that matched; live refresh every 5s |
| **Access** | Roles, subjects, tokens (counts only) and a simulator that runs the proxy's own ACL evaluator |
| **Settings** | Paths, audit and telemetry state, instances with a per-process reload |

## Editing

Every edit is a **plan**: the UI applies the form to the raw JSON, renders a unified diff, validates the result and shows the impact (instances that will be signalled, cache invalidation, whether a restart is required). Nothing is written until you apply.

On apply:

1. the file's SHA-256 is compared with the one the form was rendered from — if it changed, the write is refused with `409` and you re-open the form;
2. the new document is validated with the same parser `mcp` uses at load time;
3. it is written to a temp file in the same directory, `fsync`ed, and renamed over the target; the previous file is kept as `servers.json.bak.<timestamp>`;
4. the result is `chmod 0600` (the file may contain header tokens);
5. every running `mcp serve` instance receives `SIGHUP`.

The write is **field-level**: only the keys that changed are rewritten. Comments and `${VAR}` placeholders elsewhere in the file — including inside the edited entry — survive. This is why the UI reads the raw bytes instead of the loaded config, which has already expanded every placeholder.

```jsonc
{
  // kept warm: sentry is the busiest backend
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse",
      "headers": { "Authorization": "Bearer ${SENTRY_TOKEN}" },
      "idle_timeout": "adaptive" // stays on this line
    }
  }
}
```

Editing that entry changes one line and nothing else.

## Security model

The UI is reachable by every process running as you, so the token is not a defence against local code — anything that can read `~/.config/mcp` already has your tokens. It is a defence against **the browser**:

- binds to `127.0.0.1` by default;
- a 48-character token, delivered once in the URL, is exchanged for a `HttpOnly; SameSite=Strict` cookie;
- the `Host` header must be loopback (DNS-rebinding guard);
- POSTs must be same-origin (`Origin` and `Sec-Fetch-Site` are checked) and carry the session token in the form;
- no CORS, no CDN, no external request from the page;
- config values are redacted server-side before rendering: a header or env value that is not a `${VAR}` reference is replaced with `•••• (redacted)`.

`--read-only` disables every mutating route, and is also the mode used when the config comes from `MCP_SERVERS_CONFIG` (there is no file to write):

```bash
mcp ui --read-only
```

## Team mode

The same UI can be served by the proxy, so a team gets one control room for the deployment instead of one per laptop:

```bash
mcp serve --http 0.0.0.0:7332 --insecure --management
```

`--management` mounts the UI at `/` of the proxy. It uses the **same** `serverAuth` as `/mcp`: the sign-in form asks for a token, the proxy's provider chain validates it, and the browser keeps it in an HttpOnly, `SameSite=Strict` cookie. The token is re-validated on **every** request, so deleting it from `serverAuth.bearer.tokens` (or letting a JWT expire) signs that browser out on its next click — there is no session table to keep in sync.

What the role decides:

| | Reader (`serverAuth.acl`) | Admin (`serverAuth.adminRoles`) |
|---|---|---|
| Overview, servers, catalog | yes, **filtered by the viewer's ACL** | yes, everything |
| Playground | only tools the ACL allows | yes |
| Activity | only their own entries | everyone's |
| Access (policy, simulator) | no | yes |
| Settings, instances | no | yes |
| Edit / add / remove servers, reload | no (403) | yes |

The catalog is filtered with the proxy's own evaluator, so the UI cannot show a tool the same request would be denied. A hand-crafted `POST /playground/call` is checked again before it reaches a backend.

Writes are the same plan/apply flow as the local UI — diff, validation, atomic write, backup — and then reload **in process**: the proxy re-reads the file it is already serving from. Nothing is signalled through the instance registry, because that would mean taking a file lock this process already holds.

Two things to know before exposing it:

- **Without `serverAuth.providers` the proxy is `NoAuth`.** Everyone is anonymous, so the UI is read-only for everyone and the login form accepts any token. The proxy logs a warning at boot; add `providers: ["bearer"]` (or `forwarded`/`oauth_as`) and `adminRoles`.
- **`forwarded` trusts headers.** It is only safe behind a reverse proxy that strips client-supplied `x-forwarded-user`.

Team mode does not add a JSON API yet: the pages are server-rendered and the MCP endpoint stays `/mcp`. A `/api/v1` for automation is the next step, not this one.

## Theme

Light and dark are both first-class. Every colour is a CSS custom property; the light palette is not an inversion — the accent darkens to keep contrast on white (`#0b8f68` against `#f6f9f7`), and the semantic colours (warn, error, read-only) get their own light values.

The page follows `prefers-color-scheme` until you choose otherwise. The toggle in the topbar cycles **auto → light → dark**; the choice lives in `localStorage` under `mcp-theme` and is applied by a small script in `<head>`, before first paint, so there is no dark flash on a light-mode reload. Nothing is stored server-side, so it is a per-browser preference.

```
🌗 auto     ← follows the OS
☀ light
☾ dark
```

The login page and the one-time token page carry the same toggle, since they are the first thing an operator sees.

## Docker

The UI runs unchanged in the container; it just has to bind inside it and be told which URL to print.

```bash
# scratch image: HTTP backends only, ~30 MB
docker build -t mcp:dev .

docker run --rm -d --name mcp-ui \
  -p 127.0.0.1:7332:7332 \
  -v "$HOME/.config/mcp:/root/.config/mcp" \
  mcp:dev ui --addr 0.0.0.0:7332 --no-open

docker logs mcp-ui | grep http://
# http://localhost:7332/?token=…
```

`--addr 0.0.0.0:7332` is required: the default is loopback *inside* the container, which no published port can reach. Publish to `127.0.0.1` as above so the UI is not exposed on your LAN — the session token is the only credential it has.

For a team, the proxy serves the same pages:

```bash
docker run --rm -d --name mcp-proxy \
  -p 127.0.0.1:7332:7332 \
  -v "$HOME/.config/mcp:/root/.config/mcp" \
  mcp:dev serve --http 0.0.0.0:7332 --insecure --management
```

Sign in at `http://localhost:7332/` with a token from `serverAuth.bearer.tokens`.

Three container-specific things:

| | |
|---|---|
| **Audit and cache are off by default** | The image sets `MCP_AUDIT_ENABLED=false` (the database downloads a native library on first open). Activity is empty and discovery lives in memory for the session. Pass `-e MCP_AUDIT_ENABLED=true` with a writable volume if you want persistence — the ChronDB library still has to be fetchable for your platform. |
| **stdio backends need the `full` image** | `docker build --target full-source -t mcp:full .` adds `npx`, `uvx`, `docker`, `kubectl` and `gh`. In the scratch image a stdio backend shows up as **unavailable here**, with the reason from the same preflight `mcp --list` runs (`command not found in PATH: npx`), and *Connect now* is disabled instead of failing after the click. |
| **Files are written as root on Linux** | The config is edited in place, so backups created from inside the container belong to root. On Docker Desktop this is invisible; on Linux, run with `--user "$(id -u):$(id -g)" -e HOME=/tmp` and mount the config explicitly. |
| **Mount `:ro` means start with `--read-only`** | Editing needs to write a temp file next to the config. With a read-only mount every apply fails; `mcp ui --read-only` disables the forms up front instead. |

## Managing people

Admins can do the two things that actually change who has access: mint or revoke a token, and change which roles a subject holds.

| Action | Where | What it writes |
|---|---|---|
| Create a token | Access → Bearer tokens | `serverAuth.bearer.tokens.<token>` as `{subject, roles}` |
| Revoke a token | Access → row → Revoke | removes that key |
| Add or change a subject's roles | Access → Subjects | `serverAuth.acl.subjects.<name>.roles`, keeping `extra` grants |
| Remove a subject | Access → row → Remove | removes the subject entry |
| Create a role | Access → Roles → "Create role" | copies the grant list from an existing role into `serverAuth.acl.roles.<new>` |
| Remove a role | Access → row → Remove | removes the role, if nothing uses it |

Rules the page enforces, because getting them wrong locks people out:

- **A new token is shown once.** The page that displays it is reached by an unguessable id, is not a redirect, and is consumed on first view. After that the config holds only the token as a map key, and the UI shows a fingerprint (`sha256[..12]`) — there is no way to read it back, so "I lost the token" means revoke and create another.
- **You cannot revoke the token you are signed in with.** From another session, yes; from the same browser it is refused, or the next click would sign you out mid-action.
- **The last admin credential is protected.** Removing a token is refused when no remaining bearer token would hold a role from `serverAuth.adminRoles` — a role on a *subject* does not count, since nobody could authenticate as it. With `forwarded`/`oauth_as` providers the guard steps aside: identities come from elsewhere and cannot be enumerated here.
- **Roles cannot be deleted while in use**, while listed in `adminRoles`, or when the ACL uses the legacy `rules` schema (in that case the page also disables subject editing).
- **Role grants are not editable here.** Creating a role copies an existing grant list; changing grants is a file edit. The alternative — a nested editor for `server, access, tools, resources, prompts, deny` — is a form nobody trusts and a diff nobody reads.

Every one of these writes goes through the same plan/apply path as a server edit: atomic write, backup, `409` if the file moved underneath, and an audit entry whose `identity` is the admin's subject.

## Limits worth knowing

- **The ACL is not enforced here.** It is policy for `mcp serve --http`. The local UI, like the CLI, runs as you and can call any configured backend; the Access screen says so and is a *simulator*, not a gate.
- **Activity needs audit.** With `audit.enabled = false` the page is empty by design — there is no log to show.
- **The database is optional.** If the embedded database cannot be opened (no native library for the platform, read-only filesystem, `audit.enabled = false`), `mcp ui` still starts: the Activity trail is empty, the on-disk tool cache is off, and discovery results live in memory for the session. A banner says so. Config editing is unaffected.
- **Discovery spawns processes.** "Connect now" starts the backend exactly like `mcp <server> --list` does.
- **Signals are not acknowledgements.** Reload sends `SIGHUP` and reports how many processes were signalled; the proxy applies the new config on its own.
- **No JSON API yet.** The UI and the MCP endpoint are the surface; scripting against the UI's own data needs `/api/v1`, which is not built.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--addr <host:port>` | `127.0.0.1:7332` | Bind address |
| `--no-open` | off | Do not launch a browser |
| `--read-only` | off | Disable every mutating route |
