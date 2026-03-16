# Registry

The [MCP server registry](https://registry.modelcontextprotocol.io) is a public directory of MCP servers. `mcp` can search it and add servers directly from it.

## Searching

```bash
mcp search filesystem
```

```json
[
  {
    "name": "filesystem",
    "description": "MCP server for file system operations",
    "repository": "https://github.com/anthropics/mcp-servers",
    "install": ["npx @anthropic/fs-mcp-server"]
  }
]
```

Search with multiple words:

```bash
mcp search "database sql"
```

Results include:
- **name** — Server identifier (used with `mcp add`)
- **description** — What the server does
- **repository** — Source code link
- **install** — How to install/run (runtime + package)

## Adding from registry

```bash
mcp add filesystem
```

What happens:

1. Searches the registry for a server named `filesystem`
2. Reads the server metadata (command, args, env vars)
3. Generates a config entry in `~/.config/mcp/servers.json`
4. Prints which environment variables you need to set

```
✓ Server "filesystem" added to /home/you/.config/mcp/servers.json

Configure the following environment variables:
  ALLOWED_PATHS  — Directories the server can access

Run to test:
  mcp filesystem --list
```

### What gets generated

For a package-based server (most common), the config looks like:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic/fs-mcp-server"],
      "env": {
        "ALLOWED_PATHS": "${ALLOWED_PATHS}"
      }
    }
  }
}
```

For a remote server with HTTP transport:

```json
{
  "mcpServers": {
    "remote-service": {
      "url": "https://example.com/mcp/sse"
    }
  }
}
```

The registry entry determines which type is used. Packages (stdio) take priority over remotes (HTTP).

## Already exists?

If you try to add a server that's already in your config:

```bash
mcp add filesystem
```

```
error: server "filesystem" already exists in config
```

Remove it first if you want to re-add:

```bash
mcp remove filesystem
mcp add filesystem
```

## Manual HTTP servers

For servers not in the registry, add them manually:

```bash
mcp add --url https://mcp.example.com/sse my-server
```

This creates a minimal HTTP entry:

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://mcp.example.com/sse"
    }
  }
}
```
