# mcp documentation

CLI that turns MCP servers into terminal commands.

## Why?

Companies invested years building MCP server integrations. 5,800+ servers, 10,000+ in production, 97M+ monthly SDK downloads. All that work exposes structured APIs over a standard protocol. **[Why MCP on the command line?](why-mcp-cli.md)** explains why this matters and how `mcp` lets you reuse all of it from your terminal.

## First steps

Are you new to `mcp`? Start here:

* **[Getting started](getting-started.md)** — Install, configure your first server, call your first tool. 5 minutes from zero to working.
* **[Tutorial](tutorial.md)** — A hands-on walkthrough that covers everything you need to use `mcp` day-to-day.

## Guides

Focused explanations for specific topics:

* **[Configuration](guides/configuration.md)** — Config file format, environment variables, server types.
* **[Authentication](guides/authentication.md)** — OAuth, API tokens, service-specific setup.
* **[Registry](guides/registry.md)** — Finding and adding servers from the MCP registry.
* **[Scripting](guides/scripting.md)** — Using `mcp` in shell scripts, piping, CI/CD.
* **[Proxy mode](guides/proxy-mode.md)** — Expose all servers as a single MCP endpoint for LLM tools.

## Reference

Technical details and complete specifications:

* **[CLI reference](reference/cli.md)** — Every command, flag, and option.
* **[Config file reference](reference/config-file.md)** — Full `servers.json` specification.
* **[Environment variables](reference/environment-variables.md)** — All supported env vars.
* **[Architecture](reference/architecture.md)** — How the codebase is organized.

## How-to

Recipes for common tasks:

* **[Supported services](howto/services.md)** — Setup guides for Sentry, Slack, Grafana, GitHub, and more.
* **[Troubleshooting](howto/troubleshooting.md)** — Common errors and how to fix them.
