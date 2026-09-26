# Running with Docker

The `mcp` CLI is available as a multi-arch Docker image (amd64/arm64) on GitHub Container Registry.

## Pull the image

```bash
docker pull ghcr.io/avelino/mcp
```

## Available tags

| Tag | Description |
|---|---|
| `latest` | Latest stable release, `scratch` base, `mcp` binary only |
| `x.y.z` | Pinned version (e.g. `0.1.0`) |
| `full` | Latest stable release plus `npx`, `uvx`, `docker`, `kubectl` and `gh`, for backends that spawn a command |
| `x.y.z-full` | Pinned version of the full image |
| `beta` | Latest build from main branch |
| `beta-full` | Latest full build from main branch |

Both images ship the same `mcp` binary; `full` only adds runtimes. See [which image](#which-image) for how to choose.

## Basic usage

The CLI runs as the container entrypoint. Pass arguments directly:

```bash
docker run --rm ghcr.io/avelino/mcp --help
docker run --rm ghcr.io/avelino/mcp search github
```

## Using your config

There are two ways to provide configuration: **file mount** (traditional) or **inline JSON** (container-friendly).

### Option A: Inline config (recommended for containers)

Pass the entire config as an environment variable — no file mounts needed:

```bash
docker run --rm \
  -e MCP_SERVERS_CONFIG='{
    "mcpServers": {
      "sentry": {
        "url": "https://mcp.sentry.dev/sse",
        "headers": {"Authorization": "Bearer ${SENTRY_TOKEN}"}
      }
    }
  }' \
  -e SENTRY_TOKEN \
  ghcr.io/avelino/mcp sentry search_issues '{"query": "is:unresolved"}'
```

You can also read the JSON from an existing file with `$(cat ...)`:

```bash
docker run --rm \
  -e MCP_SERVERS_CONFIG="$(cat servers.json)" \
  -e SENTRY_TOKEN \
  ghcr.io/avelino/mcp sentry search_issues '{"query": "is:unresolved"}'
```

This is ideal for Docker Compose, Kubernetes, and CI/CD — the config lives in the orchestrator, not the filesystem.

### Option B: File mount

Mount your local config directory so the container can access your server definitions:

```bash
docker run --rm \
  -v ~/.config/mcp:/root/.config/mcp \
  ghcr.io/avelino/mcp --list
```

## Passing environment variables

Servers that need API tokens or other secrets require environment variables. Pass them with `-e`:

```bash
docker run --rm \
  -e MCP_SERVERS_CONFIG='{"mcpServers":{"github":{"url":"https://api.github.com/mcp","headers":{"Authorization":"Bearer ${GITHUB_TOKEN}"}}}}' \
  -e GITHUB_TOKEN \
  ghcr.io/avelino/mcp github list_repositories '{"query": "mcp"}'
```

You can also use an env file:

```bash
# .env
GITHUB_TOKEN=ghp_xxxx
SLACK_TOKEN=xoxb-xxxx
MCP_SERVERS_CONFIG={"mcpServers":{"github":{"url":"https://api.github.com/mcp","headers":{"Authorization":"Bearer ${GITHUB_TOKEN}"}}}}
```

```bash
docker run --rm \
  --env-file .env \
  ghcr.io/avelino/mcp github list_repositories '{"query": "mcp"}'
```

## Proxy mode (long-running)

Run the MCP proxy as a long-running service:

```bash
docker run -d \
  -e MCP_SERVERS_CONFIG='{
    "mcpServers": {
      "sentry": {"url": "https://mcp.sentry.dev/sse"}
    },
    "serverAuth": {
      "providers": ["bearer"],
      "bearer": {
        "tokens": { "my-secret-token": "ops" }
      }
    }
  }' \
  -p 8080:8080 \
  ghcr.io/avelino/mcp serve --http 0.0.0.0:8080 --insecure
```

### With audit logging

The default image disables audit logging (`MCP_AUDIT_ENABLED=false`) because `scratch` images have no writable filesystem. You have two options:

**Option A: Stream to stdout (no volume needed)**

```bash
docker run -d \
  -e MCP_SERVERS_CONFIG='{"mcpServers":{...}}' \
  -e MCP_AUDIT_OUTPUT=stdout \
  -p 8080:8080 \
  ghcr.io/avelino/mcp serve --http 0.0.0.0:8080 --insecure
```

Audit entries are emitted as JSON lines to stdout, captured by your container log driver (CloudWatch, Datadog, etc.).

**Option B: Persist to a volume**

```bash
docker run -d \
  -e MCP_SERVERS_CONFIG='{"mcpServers":{...}}' \
  -e MCP_AUDIT_ENABLED=true \
  -e MCP_AUDIT_PATH=/data/audit/data \
  -e MCP_AUDIT_INDEX_PATH=/data/audit/index \
  -v audit-data:/data/audit \
  -p 8080:8080 \
  ghcr.io/avelino/mcp serve --http 0.0.0.0:8080 --insecure
```

### Application logs (stderr, JSON for log drivers)

Tracing logs (startup, backend discovery, request errors) go to **stderr**. Two env vars tune them for production:

```bash
docker run -d \
  -e MCP_SERVERS_CONFIG='{"mcpServers":{...}}' \
  -e MCP_LOG_LEVEL='mcp=debug,hyper=warn,reqwest=warn,h2=warn' \
  -e MCP_LOG_FORMAT=json \
  -p 8080:8080 \
  ghcr.io/avelino/mcp serve --http 0.0.0.0:8080 --insecure
```

- `MCP_LOG_LEVEL` uses [`tracing` EnvFilter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax — global level (`info`/`debug`) or per-module (`mcp=debug,hyper=warn`). The example silences noisy HTTP-stack libraries while keeping the proxy at `debug`.
- `MCP_LOG_FORMAT=json` emits newline-delimited JSON, one event per line — drop straight into Datadog, CloudWatch, Loki, etc.

Pair with `MCP_AUDIT_OUTPUT=stdout` and you get a single Docker log stream where every line is JSON: app/tracing on stderr, audit on stdout — both captured by `docker logs`.

```bash
# Filter app errors:
docker logs mcp-proxy 2>&1 | jq -c 'select(.level=="ERROR")'
```

## Container environment variables

These variables are especially useful for container deployments. See the full list in the [environment variables reference](../reference/environment-variables.md).

| Variable | Default | Purpose |
|---|---|---|
| `MCP_SERVERS_CONFIG` | — | Inline JSON config, no file mount needed |
| `MCP_CONFIG_DIR` | `~/.config/mcp` | Override config directory |
| `MCP_LOG_LEVEL` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `MCP_LOG_FORMAT` | `text` | Log format: `text` or `json` (structured, for log drivers) |
| `MCP_AUDIT_ENABLED` | `false` (in Docker image) | Disable audit for read-only fs |
| `MCP_AUDIT_OUTPUT` | unset (→ `file+stdout` in `mcp serve --http`) | `stdout`/`stderr` for log driver only, `file` for ChronDB only (setting this env var is treated as explicit and skips auto-promotion in serve), `file+stdout`/`file+stderr` for both, `none` to disable |
| `MCP_AUDIT_PATH` | `~/.config/mcp/db/data` | Override audit data path |
| `MCP_AUDIT_INDEX_PATH` | `~/.config/mcp/db/index` | Override audit index path |
| `MCP_AUTH_CONFIG` | — | Inline `auth.json` content (read-only, writes are no-ops). Same idea as `MCP_SERVERS_CONFIG`. |
| `MCP_AUTH_PATH` | `~/.config/mcp/auth.json` | Override OAuth token storage (file path) |
| `MCP_CLASSIFIER_CACHE` | `~/.config/mcp/tool-classification.json` | Override classifier cache |

## Kubernetes

See the dedicated [Kubernetes deployment guide](./kubernetes.md) for complete manifests with probes, security context, audit logging, and operational guidance.

Quick start:

```bash
kubectl apply -k deploy/kubernetes/
```

## Shell alias

For day-to-day use, create an alias so `mcp` works like a native command:

```bash
# bash / zsh — add to ~/.bashrc or ~/.zshrc
alias mcp='docker run --rm -v ~/.config/mcp:/root/.config/mcp --env-file ~/.config/mcp/.env ghcr.io/avelino/mcp'

# fish — add to ~/.config/fish/config.fish
alias mcp 'docker run --rm -v ~/.config/mcp:/root/.config/mcp --env-file ~/.config/mcp/.env ghcr.io/avelino/mcp'
```

Then use it normally:

```bash
mcp --list
mcp sentry search_issues '{"query": "is:unresolved"}'
mcp search filesystem
```

## Piping JSON

Pipe input via stdin with `-i` (Docker's interactive flag):

```bash
echo '{"query": "is:unresolved"}' | docker run --rm -i \
  -e MCP_SERVERS_CONFIG='{"mcpServers":{"sentry":{"url":"https://mcp.sentry.dev/sse"}}}' \
  ghcr.io/avelino/mcp sentry search_issues
```

## Pinning a version

For CI/CD or reproducible environments, pin to a specific version:

```bash
docker run --rm ghcr.io/avelino/mcp:0.1.0 --help
```

## Backends that ship as a Docker image

Some MCP servers are distributed as an image instead of an npm or pip package. They run on stdio like any other local server, so the only difference in your config is that `command` is `docker`:

```json
{
  "mcpServers": {
    "discord": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "DISCORD_TOKEN",
        "-e", "DISCORD_GUILD_ID",
        "saseq/discord-mcp:latest"
      ],
      "env": {
        "DISCORD_TOKEN": "${DISCORD_TOKEN}",
        "DISCORD_GUILD_ID": "${DISCORD_GUILD_ID}"
      }
    }
  }
}
```

Three flags matter:

- `-i` keeps stdin open. Without it the container gets EOF immediately and the handshake never happens.
- `--rm` removes the container when it exits, so idle shutdown in `mcp serve` doesn't pile up dead containers.
- `-e NAME` (no `=`) tells docker to copy that variable from the CLI's environment into the container. `env` in the config only reaches the `docker` process, never the container, so a secret declared there and not listed with `-e` silently arrives empty.

`mcp add <name>` writes all three for you when the registry entry is an OCI package.

Never pass secrets as `-e NAME=value` in `args`: that value lands in your config file and in the container's `docker inspect`. Keep it in `env` with `${VAR}` and let `-e NAME` forward it.

Backends in a container behave like any other stdio backend under the proxy: one process per backend, shared across clients, idle shutdown, `--list` and tool calls unchanged.

## Serving `mcp` itself over stdio

`mcp serve` without `--http` speaks MCP on stdio, so the proxy can be wired into a client as a container, the same shape a dockerized MCP server uses. No port, no service to keep running, no boot script: the client starts it and stops it.

```json
{
  "mcpServers": {
    "all": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/Users/you/.config/mcp:/root/.config/mcp",
        "ghcr.io/avelino/mcp:full", "serve"
      ]
    }
  }
}
```

`-i` is what makes it work: without it the container gets EOF before the handshake. Most clients don't expand `~`, so write the host path out.

Use `-e MCP_SERVERS_CONFIG` instead of the volume when the config is inline and you don't need OAuth tokens or the tool cache to survive a restart.

### Which image

| | `ghcr.io/avelino/mcp` | `ghcr.io/avelino/mcp:full` |
|---|---|---|
| Base | `scratch` | `alpine` |
| Size | ~30 MB | ~390 MB |
| HTTP backends (`url`) | yes | yes |
| `npx` / `uvx` backends | no | yes |
| `docker` backends | no | yes, with the socket mounted |
| `cli: true` on `kubectl` / `gh` | no | yes, with credentials mounted |
| Any other host binary | no | no |
| Audit | off by default | off by default |

Pick the small one for a config that is entirely HTTP. Pick `:full` when the registry handed you `npx` or `uvx` backends.

### What cannot follow you into a container

A backend whose `command` is a binary installed on your host (`/opt/homebrew/bin/something`, `~/.local/bin/something`, a Go or Rust tool on your `PATH`) does not exist inside any of these images, and a macOS binary would not execute on Linux even if mounted. Neither image can run it.

`mcp --list` reports this without spawning anything, so you can check before switching a client over:

```
$ docker run --rm -v ~/.config/mcp:/root/.config/mcp ghcr.io/avelino/mcp:full --list

 Server        Type   Endpoint                        Status
 buser_sentry  http   https://mcp.sentry.dev/mcp      ok
 buser_slack   stdio  npx -y slack-mcp-server@latest  ok
 github        cli    gh                              ok
 outl          stdio  outl                            unavailable: command not found in PATH: outl
 roam          stdio  /opt/homebrew/bin/roam-tui      unavailable: command does not exist: /opt/homebrew/bin/roam-tui

 5 server(s) configured, 2 unavailable here
```

In JSON those backends carry `"available": false` and `"unavailable_reason"`. The proxy reports the same reason when a client calls one of their tools, instead of an OS spawn error.

If that list has entries you need, keep running `mcp serve` on the host. A mixed setup can also split: host-native binaries stay in a local `mcp serve`, everything else moves into a container.

### Backends that need more than the runtime

```bash
# a dockerized backend inside the full image
docker run --rm -i \
  -v ~/.config/mcp:/root/.config/mcp \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/avelino/mcp:full serve

# kubectl and gh as CLI-as-MCP backends
docker run --rm -i \
  -v ~/.config/mcp:/root/.config/mcp \
  -v ~/.kube:/root/.kube:ro \
  -e GH_TOKEN \
  ghcr.io/avelino/mcp:full serve
```

A backend pointing at `127.0.0.1` on the host needs `host.docker.internal` instead of `127.0.0.1`, plus `--add-host=host.docker.internal:host-gateway` on Linux.

## Limitations

- **Stdio servers only work if the runtime is available inside the container.** The default image includes only the `mcp` binary and `ca-certificates`. Use `ghcr.io/avelino/mcp:full` for backends that need `npx`, `uvx`, `docker`, `kubectl` or `gh`; anything else needs an image derived from it. HTTP servers (configured with `url`) work in both. Either way `mcp --list` names what is unavailable before you hit it.
- **OAuth browser flow doesn't work in Docker.** For HTTP servers that need OAuth, run `mcp add <server>` on your host first to complete authentication, then either mount the config directory (which includes `auth.json`), set `MCP_AUTH_PATH` to a mounted volume, or pass the JSON inline via `MCP_AUTH_CONFIG` (read-only — useful for read-only containers and Kubernetes Secrets).
- **Audit logging is disabled by default** in the Docker image because `scratch` images have no writable filesystem. Use `MCP_AUDIT_OUTPUT=stdout` to stream to the container log driver, or mount a volume and set `MCP_AUDIT_ENABLED=true`.
- **A dockerized backend that ignores stdin EOF survives idle shutdown.** When the proxy reaps an idle backend it kills the `docker run` client, which closes the container's stdin but does not stop the container. A server that exits on EOF (most do) shuts down and `--rm` cleans up; one that keeps running stays up until you `docker rm -f` it. Check with `docker ps` if you suspect a backend is lingering.
