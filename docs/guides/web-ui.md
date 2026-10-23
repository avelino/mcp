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

## Limits worth knowing

- **The ACL is not enforced here.** It is policy for `mcp serve --http`. The local UI, like the CLI, runs as you and can call any configured backend; the Access screen says so and is a *simulator*, not a gate.
- **Activity needs audit.** With `audit.enabled = false` the page is empty by design — there is no log to show.
- **The database is optional.** If the embedded database cannot be opened (no native library for the platform, read-only filesystem, `audit.enabled = false`), `mcp ui` still starts: the Activity trail is empty, the on-disk tool cache is off, and discovery results live in memory for the session. A banner says so. Config editing is unaffected.
- **Discovery spawns processes.** "Connect now" starts the backend exactly like `mcp <server> --list` does.
- **Signals are not acknowledgements.** Reload sends `SIGHUP` and reports how many processes were signalled; the proxy applies the new config on its own.
- **Local mode only, for now.** A team-mode endpoint behind `serverAuth`/`adminRoles` is designed but not implemented.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--addr <host:port>` | `127.0.0.1:7332` | Bind address |
| `--no-open` | off | Do not launch a browser |
| `--read-only` | off | Disable every mutating route |
