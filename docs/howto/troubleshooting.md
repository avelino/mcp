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
