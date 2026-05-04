# Running with Docker

The `mcp` CLI is available as a multi-arch Docker image (amd64/arm64) on GitHub Container Registry.

## Pull the image

```bash
docker pull ghcr.io/avelino/mcp
```

## Available tags

| Tag | Description |
|---|---|
| `latest` | Latest stable release |
| `x.y.z` | Pinned version (e.g. `0.1.0`) |
| `beta` | Latest build from main branch |

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
      "provider": "bearer",
      "tokens": ["my-secret-token"]
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

## Container environment variables

These variables are especially useful for container deployments. See the full list in the [environment variables reference](../reference/environment-variables.md).

| Variable | Default | Purpose |
|---|---|---|
| `MCP_SERVERS_CONFIG` | — | Inline JSON config, no file mount needed |
| `MCP_CONFIG_DIR` | `~/.config/mcp` | Override config directory |
| `MCP_LOG_LEVEL` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `MCP_LOG_FORMAT` | `text` | Log format: `text` or `json` (structured, for log drivers) |
| `MCP_AUDIT_ENABLED` | `false` (in Docker image) | Disable audit for read-only fs |
| `MCP_AUDIT_OUTPUT` | `file` | `stdout`/`stderr` for container log drivers, `none` to disable |
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

## Limitations

- **Stdio servers only work if the runtime is available inside the container.** The default image includes only the `mcp` binary and `ca-certificates`. Servers that require `npx`, `python`, or other runtimes won't work unless you build a custom image. HTTP servers (configured with `url`) work out of the box.
- **OAuth browser flow doesn't work in Docker.** For HTTP servers that need OAuth, run `mcp add <server>` on your host first to complete authentication, then either mount the config directory (which includes `auth.json`), set `MCP_AUTH_PATH` to a mounted volume, or pass the JSON inline via `MCP_AUTH_CONFIG` (read-only — useful for read-only containers and Kubernetes Secrets).
- **Audit logging is disabled by default** in the Docker image because `scratch` images have no writable filesystem. Use `MCP_AUDIT_OUTPUT=stdout` to stream to the container log driver, or mount a volume and set `MCP_AUDIT_ENABLED=true`.
