# CLI as MCP

Any command-line tool can become an MCP server. No code, no wrapper — just config.

```json
{
  "mcpServers": {
    "kubectl": {
      "command": "kubectl",
      "cli": true
    }
  }
}
```

That's it. `mcp` runs `kubectl --help`, discovers subcommands and flags, and exposes them as MCP tools automatically.

## Why

MCP is becoming the standard protocol for AI tool integration. But most software ships as a CLI, not an MCP server. This bridge closes the gap: any CLI becomes accessible to GPT, Claude, Cursor, or any MCP-compatible client — without writing a single line of integration code.

```
You / AI agent  -->  mcp CLI  -->  CliTransport  -->  kubectl / docker / terraform / ...
                         |
                    servers.json
```

## How discovery works

When you add a CLI server, `mcp` automatically:

1. Runs `<command> --help` to discover subcommands
2. Runs `<command> <subcommand> --help` for each subcommand to discover flags
3. Generates MCP tool definitions with proper `inputSchema`

Each subcommand becomes a tool named `<command>_<subcommand>` (e.g. `kubectl_get`, `kubectl_describe`).

```bash
$ mcp kubectl --list
kubectl_get        Display one or many resources
kubectl_describe   Show details of a specific resource
kubectl_version    Print the client and server version information
...
```

Flags are parsed into typed schema properties:

```bash
$ mcp kubectl --info
# kubectl_get has: output (string), all_namespaces (boolean), selector (string), ...
```

## Calling tools

Tools accept a JSON object. Flags map to properties (dashes become underscores). Positional arguments go in `args`:

```bash
# kubectl get pods -n kube-system -o json
mcp kubectl kubectl_get '{"args": "pods", "namespace": "kube-system", "output": "json"}'

# kubectl version --client
mcp kubectl kubectl_version '{"client": true}'

# kubectl describe pod my-pod
mcp kubectl kubectl_describe '{"args": "pod my-pod"}'
```

The `args` field supports shell quoting for arguments with spaces:

```bash
# grep in a path with spaces
mcp grep grep '{"args": "pattern \"my directory/file.txt\""}'
```

Each call spawns the CLI process, captures stdout, and returns it as MCP content. No long-running process — each invocation is independent.

If the command writes to stderr on success (e.g. warnings), it's appended to the output under a `--- stderr ---` delimiter so nothing is lost silently.

## Configuration

### Minimal

```json
{
  "mcpServers": {
    "kubectl": {
      "command": "kubectl",
      "cli": true
    }
  }
}
```

### Full options

```json
{
  "mcpServers": {
    "kubectl": {
      "command": "kubectl",
      "cli": true,
      "cli_help": "--help",
      "cli_depth": 2,
      "cli_only": ["get", "describe", "logs", "version"],
      "args": [],
      "env": {
        "KUBECONFIG": "${HOME}/.kube/config"
      }
    }
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `command` | string | *required* | CLI executable to wrap |
| `cli` | bool | *required* | Must be `true` — marks this as a CLI server |
| `cli_help` | string | `"--help"` | Flag used to discover subcommands and options |
| `cli_depth` | number | `2` | How deep to recurse into subcommands for flag discovery |
| `cli_only` | string[] | `[]` (all) | Whitelist of subcommands to expose — everything else is hidden |
| `args` | string[] | `[]` | Base arguments prepended to every invocation |
| `env` | object | `{}` | Environment variables for the CLI process |

### `cli_help`

Most CLIs use `--help`. Some don't:

```json
{
  "mcpServers": {
    "busybox": {
      "command": "busybox",
      "cli": true,
      "cli_help": "--list"
    }
  }
}
```

### `cli_only`

Limit exposure to safe, read-only commands:

```json
{
  "mcpServers": {
    "kubectl": {
      "command": "kubectl",
      "cli": true,
      "cli_only": ["get", "describe", "logs", "top", "version"]
    }
  }
}
```

This is important for security — you probably don't want an AI agent running `kubectl delete` or `kubectl exec`.

### `cli_depth`

Controls how deep the discovery goes:

- `1` — only parse the top-level `--help` (subcommand names + descriptions, no flag details)
- `2` (default) — also run `<subcommand> --help` to discover flags and build `inputSchema`

Values greater than `2` are accepted but currently behave the same as `2` (no additional recursion depth).

## Preset tools

If automatic discovery doesn't work for a specific CLI, you can define tools manually:

```json
{
  "mcpServers": {
    "custom": {
      "command": "my-tool",
      "cli": true,
      "tools": [
        {
          "name": "my_tool_export",
          "args": ["export", "--format", "json"],
          "description": "Export data as JSON"
        }
      ]
    }
  }
}
```

When `tools` is non-empty, automatic discovery is skipped. The `args` in each tool define the exact arguments passed to the CLI when that tool is called.

## Examples

### kubectl

```json
{
  "kubectl": {
    "command": "kubectl",
    "cli": true,
    "cli_only": ["get", "describe", "logs", "top", "version"]
  }
}
```

```bash
mcp kubectl kubectl_get '{"args": "pods -A", "output": "json"}'
mcp kubectl kubectl_logs '{"args": "deploy/api -n production", "tail": "100"}'
```

### docker

```json
{
  "docker": {
    "command": "docker",
    "cli": true,
    "cli_only": ["ps", "images", "logs", "inspect", "stats"]
  }
}
```

```bash
mcp docker docker_ps '{"all": true}'
mcp docker docker_logs '{"args": "my-container", "tail": "50"}'
```

### terraform

```json
{
  "terraform": {
    "command": "terraform",
    "cli": true,
    "cli_only": ["plan", "show", "state", "output", "validate"]
  }
}
```

```bash
mcp terraform terraform_plan '{}'
mcp terraform terraform_output '{"json": true}'
```

### git (read-only)

```json
{
  "git": {
    "command": "git",
    "cli": true,
    "cli_only": ["log", "diff", "status", "show", "branch"]
  }
}
```

```bash
mcp git git_log '{"args": "--oneline -20"}'
mcp git git_diff '{"args": "HEAD~1"}'
```

## How it works with proxy mode

CLI servers work with `mcp serve` just like any other server. Tools are namespaced the same way:

```bash
mcp serve
# Tools appear as: kubectl__kubectl_get, docker__docker_ps, etc.
```

Idle timeout applies: since each CLI call is a separate process spawn, the CLI transport itself has no persistent connection to shut down. The idle timeout controls when the discovered tool cache is dropped.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `MCP_TIMEOUT` | `60` | Timeout in seconds for each CLI command execution |
| `MCP_MAX_OUTPUT` | `1048576` | Max output size in bytes (1 MB). Larger output is truncated |
| `MCP_DISCOVERY_CONCURRENCY` | `10` | Max parallel `--help` calls during subcommand discovery |

## Help format support

The discovery parser handles these common formats:

| CLI framework | Example | Supported |
|---|---|---|
| Cobra (Go) | kubectl, docker, gh | Yes |
| Clap (Rust) | ripgrep, fd | Yes |
| Click (Python) | flask, black | Yes |
| Argparse (Python) | most Python CLIs | Yes |
| Custom | varies | Best-effort, fallback to single tool |

If a CLI's `--help` output doesn't follow standard patterns, discovery falls back to exposing the command as a single tool with a free-form `args` parameter.
