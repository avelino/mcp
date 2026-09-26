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

For a server distributed as a container image (`oci` package):

```json
{
  "mcpServers": {
    "discord": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "DISCORD_TOKEN", "example/discord-mcp:latest"],
      "env": {
        "DISCORD_TOKEN": "${DISCORD_TOKEN}"
      }
    }
  }
}
```

Each declared variable gets a `-e NAME` in `args`, and that pair is load-bearing: `env` reaches the `docker` CLI process, never the container, so a secret listed only in `env` arrives empty inside the image. Keep the value in `env` as `${VAR}` rather than writing `-e NAME=value` into `args`, which would put the secret in your config file and in `docker inspect`.

Two consequences worth knowing:

- `-e NAME` forwards the variable even when it is unset on your machine, which **shadows** an `ENV NAME=default` baked into the image. If you want the image's own default for a declared variable, delete its `-e NAME` pair from `args` and its entry from `env`.
- A variable name the registry declares that isn't a valid shell variable name is skipped with a warning, since it would otherwise end up on a `docker run` command line.

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

> Added an `oci` server before this behavior existed? Its config has no `-e` flags, so its secrets never reached the container. `mcp update <name>` regenerates `command` and `args` from the registry and keeps the values you filled in.

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

> If you only want to pull fresh metadata from the registry (new package version, new env vars, updated args), use `mcp update <name>` instead — it preserves your customizations (filled env values, headers, idle_timeout, etc.). See [`mcp update`](../reference/cli.md#mcp-update-name).

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
