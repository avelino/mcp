# Getting started

This guide takes you from zero to calling your first MCP tool. It should take about 5 minutes.

## Installing mcp

**Homebrew (macOS and Linux):**

```bash
brew install avelino/mcp/mcp
```

**Pre-built binary:**

Download the latest binary for your platform from [GitHub Releases](https://github.com/avelino/mcp/releases), make it executable, and move it to your `$PATH`:

```bash
chmod +x mcp-*
sudo mv mcp-* /usr/local/bin/mcp
```

**Docker:**

```bash
docker pull ghcr.io/avelino/mcp
```

To use it like a native command, create an alias:

```bash
alias mcp='docker run --rm -v ~/.config/mcp:/root/.config/mcp ghcr.io/avelino/mcp'
```

Add the alias to your shell profile (`~/.bashrc`, `~/.zshrc`, or `~/.config/fish/config.fish`) to make it permanent. If your servers need environment variables (API tokens, etc.), pass them with `-e`:

```bash
alias mcp='docker run --rm -v ~/.config/mcp:/root/.config/mcp -e GITHUB_TOKEN ghcr.io/avelino/mcp'
```

**From source (requires Rust):**

```bash
# Install Rust if needed: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install --path .
```

Verify it works:

```bash
mcp --help
```

You should see:

```
mcp — CLI that turns MCP servers into terminal commands

Usage:
  mcp --list                          List configured servers
  mcp <server> --list                 List tools from a server
  mcp <server> --info                 List tools with input schemas
  mcp <server> <tool> [json]          Call a tool
  mcp search <query>                  Search MCP registry
  mcp add <name>                      Add server from registry
  mcp add --url <url> <name>          Add HTTP server manually
  mcp remove <name>                   Remove server from config
  mcp update <name>                   Refresh server config from registry
```

## Adding your first server

The fastest way to get started is adding a server from the [MCP registry](https://registry.modelcontextprotocol.io). Let's add the `filesystem` server — it lets you read, write, and search files through MCP.

```bash
mcp add filesystem
```

You'll see something like:

```
✓ Server "filesystem" added to /home/you/.config/mcp/servers.json

Run to test:
  mcp filesystem --list
```

## Listing available tools

Now see what tools the server provides:

```bash
mcp filesystem --list
```

Output:

```json
[
  {
    "name": "read_file",
    "description": "Read the complete contents of a file"
  },
  {
    "name": "write_file",
    "description": "Create a new file or overwrite an existing file"
  },
  {
    "name": "list_directory",
    "description": "List directory contents"
  }
]
```

## Calling a tool

Call a tool by passing its name and a JSON object with the arguments:

```bash
mcp filesystem read_file '{"path": "/etc/hostname"}'
```

Output:

```json
{
  "content": [
    {
      "type": "text",
      "text": "my-machine\n"
    }
  ]
}
```

That's it. You just called an MCP tool from your terminal.

## What's next?

- **[Tutorial](tutorial.md)** — Walk through more realistic examples: HTTP servers, authentication, piping, and scripting.
- **[Configuration](guides/configuration.md)** — Learn the full config file format.
- **[Supported services](howto/services.md)** — Setup guides for Sentry, Slack, Grafana, and more.
