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
  -v ~/.config/mcp:/root/.config/mcp \
  -e GITHUB_TOKEN \
  -e SLACK_TOKEN \
  ghcr.io/avelino/mcp github list_repositories '{"query": "mcp"}'
```

You can also use an env file:

```bash
# .env
GITHUB_TOKEN=ghp_xxxx
SLACK_TOKEN=xoxb-xxxx
```

```bash
docker run --rm \
  -v ~/.config/mcp:/root/.config/mcp \
  --env-file .env \
  ghcr.io/avelino/mcp sentry search_issues '{"query": "is:unresolved"}'
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
  -v ~/.config/mcp:/root/.config/mcp \
  ghcr.io/avelino/mcp sentry search_issues
```

## Pinning a version

For CI/CD or reproducible environments, pin to a specific version:

```bash
docker run --rm ghcr.io/avelino/mcp:0.1.0 --help
```

## Limitations

- **Stdio servers only work if the runtime is available inside the container.** The default image includes only the `mcp` binary and `ca-certificates`. Servers that require `npx`, `python`, or other runtimes won't work unless you build a custom image. HTTP servers (configured with `url`) work out of the box.
- **OAuth browser flow doesn't work in Docker.** For HTTP servers that need OAuth, run `mcp add <server>` on your host first to complete authentication, then mount the config directory (which includes `auth.json`).
