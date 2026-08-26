# Troubleshooting

Common issues and how to fix them.

## Connection errors

### "server closed stdout (EOF)"

The server process exited unexpectedly. Common causes:

- **Missing dependencies** — The server needs npm packages that aren't installed. Try running the command manually to see the error:
  ```bash
  npx -y @anthropic/fs-mcp-server
  ```
- **Bad arguments** — Check `args` in your config. Some servers need specific flags.
- **Environment variables** — A required env var might be missing or empty.

### "timeout waiting for server response"

The server took too long to respond.

**Fix:** Increase the timeout:

```bash
MCP_TIMEOUT=120 mcp slack --list
```

Some servers (especially npm-based ones) take a long time on first run because they need to download packages. Subsequent runs are faster.

### "failed to spawn process: <command>"

The command in your config doesn't exist or isn't in your PATH.

**Check:**

```bash
which npx          # Is npx installed?
which node         # Is Node.js installed?
```

For `npx` servers, make sure Node.js is installed.

## Authentication errors

### "Server returned 401"

The token is invalid, expired, or missing.

**Fixes:**

1. **Clear saved tokens** — Delete the entry from `~/.config/mcp/auth.json` or the whole file:
   ```bash
   rm ~/.config/mcp/auth.json
   ```
   Next request will trigger a fresh auth flow.

2. **Check config headers** — If you have an `Authorization` header in config, make sure the env var is set:
   ```bash
   echo $MY_TOKEN   # Should print your token
   ```

3. **Re-authenticate** — Just call any command, the auth flow will start:
   ```bash
   mcp sentry --list
   ```

### "OAuth registration not available"

The server doesn't support OAuth Dynamic Client Registration. `mcp` will fall back to asking for a manual token. Follow the instructions it prints.

### "could not bind to any port in range 8085-8099"

Another process is using the ports `mcp` needs for the OAuth callback. Close any other `mcp` instances or processes on those ports.

## Config errors

### "server not found in config"

The server name you used doesn't match any entry in `servers.json`.

```bash
mcp --list    # See what's configured
```

Check for typos. Server names are case-sensitive.

### "conflicts with a reserved command name"

You named a server with a reserved name. Rename it in `servers.json`:

```
warning: server "search" conflicts with a reserved command name
```

Reserved names: `search`, `add`, `remove`, `list`, `help`, `version`.

### "failed to parse config file"

Your `servers.json` has invalid JSON. Common issues:

- Trailing comma after the last entry
- Missing quotes around keys
- Unescaped special characters

Validate your JSON:

```bash
python3 -m json.tool ~/.config/mcp/servers.json
```

## Proxy mode errors

### Backend stuck in discovery retry

When a backend fails to connect during `mcp serve`, the proxy applies exponential backoff before retrying: 30s → 60s → 120s → 240s (capped at 300s). This prevents a flaky backend from stealing the discovery lock and blocking healthy backends.

If you see repeated discovery failures in stderr:

```
[serve] backend "slack" discovery failed: timeout waiting for server response
```

**Fixes:**

1. **Check the backend command works standalone:**
   ```bash
   mcp slack --list
   ```
2. **Increase timeout for slow backends:**
   ```bash
   MCP_TIMEOUT=120 mcp serve --http
   ```
3. **Check credentials** — a backend stuck on an auth prompt will hang until timeout.

After fixing the issue, restart `mcp serve` — the backoff state is in-memory and resets on restart.

### A backend silently disappears from `tools/list`

The proxy discovers each backend independently, so one that dies on startup just stops appearing. Everything else keeps working: the process stays up, `/health` returns 200, the container never restarts. Nothing surfaces the loss until someone asks where a tool went.

**1. Get the roll call.** One line per backend, healthy and broken:

```bash
mcp serve --http 2>&1 \
  | grep -E "discovered capabilities|failed to discover|discovery timed out"
```

`discovered capabilities server=X tools=N` means it came up. `failed to discover` or `discovery timed out` names your culprit.

**2. Read the backend's own stderr.** The proxy captures it and replays it inside the failure message, which is where the real cause lives. The proxy-level error only tells you the pipe closed:

```
failed to discover server=slack error=backend 'slack-mcp-server' failed
during the server/discover compatibility probe (server closed stdout (EOF)

server stderr:
{"level":"error","message":"Failed to fetch channels","error":"missing_scope"}
{"level":"fatal","message":"Error booting provider"}
```

The `EOF` is the symptom. `missing_scope` is the bug.

**3. Call the backend's API directly** with the same credentials and from the same network the proxy uses. In a container, exec into it and reference the env var so the secret never leaves the process:

```bash
kubectl exec deploy/mcp-proxy -- sh -c \
  'curl -s -H "Authorization: Bearer $MY_TOKEN" https://api.example.com/v1/thing'
```

This separates "the credential is wrong" from "the wrapper is broken", which the proxy log alone can't tell you apart.

**Common causes:**

| What the backend stderr says | Actual cause |
|---|---|
| A permission or scope error, then a fatal exit | The backend refuses to boot without some API call succeeding. Grant the scope; the API response usually names the missing one. |
| Nothing — it just times out | Discovery is capped at 30s per backend and is not configurable. If the endpoint answers fast when you curl it, the wrapper process is the problem, not the network. |
| `invalid character '<' looking for beginning of value` | It got HTML, not JSON. See below. |

### Backend returns HTML instead of JSON

A parse error pointing at `<` or at "line 1 column 1" means an auth gateway (Cloudflare Access, an SSO proxy, a captive portal) answered instead of the MCP server. Your token was never evaluated.

For backends declared with `url`, `mcp` refuses to follow redirects precisely so this reports as a redirect rather than a confusing parse error. Backends that speak to their own API over HTTP do their own requests, so they surface the raw parse failure instead.

Confirm by looking at the status code rather than the body:

```bash
curl -s -o /dev/null -w "http=%{http_code} type=%{content_type}\n" \
  -H "Authorization: Bearer $TOKEN" https://backend.example.com/api/thing
```

A `302` with `text/html` is the gateway. Fix it at the gateway: issue a service token for machine traffic, or allow the proxy's egress range. No amount of backend config gets past it.

### "access denied" on tools/call

The ACL blocks both `tools/call` requests **and** filters `tools/list` responses. If a tool doesn't appear in `tools/list`, the identity doesn't have access to it. If a tool appears but `tools/call` returns access denied, the ACL rules may have changed between the list and the call, or the tool's read/write classification doesn't match the identity's access level.

**Debug:** Check what the classifier thinks about the tool:

```bash
mcp acl classify --server <backend>
```

Tools marked `[!]` (ambiguous) are treated as write by default. Add explicit `tool_acl` overrides in `servers.json` if the classifier is wrong.

### Request timeout in proxy mode

Each client request has a hard timeout of 120 seconds (configurable via `MCP_PROXY_REQUEST_TIMEOUT`). If a backend takes longer than this, the client gets a JSON-RPC error with code `-32000`. Other concurrent requests are unaffected.

```bash
MCP_PROXY_REQUEST_TIMEOUT=300 mcp serve --http
```

## Tool errors

### "tools/call failed: ..."

The tool returned an error. This is a server-side error — the tool itself failed. Check:

- **Arguments** — Use `mcp <server> --info` to see the expected input schema
- **Permissions** — Your token might not have the required scopes
- **Server-specific** — Check the server's documentation

### Response has `"isError": true`

The tool executed but returned an error result. This is different from a protocol error — the tool ran but the operation failed. Read the `content[0].text` for details.

## Debug tips

### See what config is loaded

```bash
mcp --list
```

### Check if a server is reachable

```bash
mcp sentry --list 2>&1
```

Watch stderr for auth messages and connection errors.

### Run the server command manually

For stdio servers, run the command directly to see what happens:

```bash
npx -y @anthropic/fs-mcp-server /home/me
```

If it prints errors to stderr, that's your problem.

### Check env var resolution

If you suspect env vars aren't being set, add a test server:

```json
{
  "mcpServers": {
    "debug": {
      "command": "echo",
      "args": [],
      "env": {
        "MY_TOKEN": "${MY_TOKEN}"
      }
    }
  }
}
```

```bash
mcp --list   # Will show the config with resolved values
```

### Network issues with HTTP servers

Check if you can reach the server:

```bash
curl -I https://mcp.sentry.dev/sse
```

If you get a 401, that's expected — auth will be handled by `mcp`. If you get a connection error, it's a network problem.
