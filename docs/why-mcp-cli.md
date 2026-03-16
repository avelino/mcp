# Why MCP on the command line?

Companies invested millions building MCP servers. Sentry, Slack, Grafana, Honeycomb, GitHub — all of them shipped production-grade integrations. These servers expose structured APIs over a standard protocol. Why would we limit them to AI assistants?

We don't have to. Every MCP server is also a CLI tool waiting to happen.

## The investment is already done

The MCP ecosystem exploded since Anthropic [launched the protocol](https://www.anthropic.com/news/model-context-protocol) in November 2024. In less than a year:

- **5,800+ MCP servers** available across the ecosystem
- **10,000+ servers** actively running in production
- **97 million+ monthly SDK downloads** (Python + TypeScript combined)
- Server downloads grew from ~100k to 8 million between November 2024 and April 2025

Sources: [MCP Adoption Statistics 2025](https://mcpmanager.ai/blog/mcp-adoption-statistics/), [MCP Statistics](https://www.mcpevals.io/blog/mcp-statistics)

Every one of those servers implements a standardized interface: JSON-RPC 2.0 over stdio or HTTP. They handle auth, rate limiting, pagination, error handling. They expose structured tools with JSON Schema inputs. That's years of engineering work across hundreds of companies.

## From AI-only to everywhere

MCP was designed for AI assistants, but the protocol itself is simple: send a JSON request, get a JSON response. There's nothing AI-specific about calling `search_issues` or `list_channels`.

The industry is realizing this. Projects like [`mcp-tools`](https://blog.fka.dev/blog/2025-03-26-introducing-mcp-tools-cli/) and [`mcp-cmd`](https://github.com/developit/mcp-cmd) started exploring MCP servers as CLI tools in early 2025. The insight is the same: **why rewrite what already exists?**

If Sentry already built an MCP server that can search issues, get event details, and analyze errors — why would you write a separate Sentry CLI? Just talk to their MCP server directly.

## Who's behind MCP

This isn't a niche experiment. MCP moved to the [Linux Foundation's Agentic AI Foundation](https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation) in December 2025, co-founded by **Anthropic**, **Block**, and **OpenAI**, with support from **AWS**, **Google**, **Microsoft**, **Cloudflare**, and **Bloomberg**.

Before that:

- **OpenAI** adopted MCP in March 2025 across ChatGPT desktop, Agents SDK, and Responses API
- **Google** added native support in Gemini 2.5 Pro
- **Microsoft** integrated MCP into Copilot Studio and Azure
- **Salesforce** adopted MCP for Agentforce 3
- **Cloudflare** launched MCP Server Portals

Source: [Why the Model Context Protocol Won](https://thenewstack.io/why-the-model-context-protocol-won/), [A Year of MCP: From Internal Experiment to Industry Standard](https://www.pento.ai/blog/a-year-of-mcp-2025-review)

When this many companies converge on a protocol, the integrations become infrastructure. They're not going away.

## Don't throw away the work

Every MCP server is three things:

1. **An API client** — Handles authentication, rate limits, pagination for a specific service
2. **A tool catalog** — Structured operations with typed inputs and outputs
3. **A transport layer** — Standard JSON-RPC over stdio or HTTP

Traditionally, to use a service from the terminal, you'd either use a service-specific CLI (if one exists) or write curl commands with manual auth. With MCP, you get a uniform interface across all services. Same command structure, same output format, same auth flow.

```bash
# Same pattern, different services
mcp sentry search_issues '{"query": "is:unresolved"}'
mcp grafana search_dashboards '{"query": "api-latency"}'
mcp slack list_channels
mcp github search_repositories '{"query": "mcp"}'
```

One binary replaces a dozen service-specific CLIs. And every new MCP server that ships — from any company, in any language — immediately becomes another command you can use.

## The "good enough" protocol

As [The New Stack observed](https://thenewstack.io/why-the-model-context-protocol-won/), MCP won because it was "good enough at the right time." The protocol is simple. A server exposes tools. A client calls them. That's it.

This simplicity is a feature. MCP didn't try to solve every problem — it solved the integration problem. And because it's simple, it's easy to build clients for it. A CLI client is one of the most natural forms.

## What this means for you

If you use services that have MCP servers (and increasingly, most do), you can:

- **Query them from your terminal** without installing service-specific CLIs
- **Script across services** with a consistent interface
- **Pipe JSON output** through standard Unix tools
- **Automate** in CI/CD, cron jobs, and monitoring scripts
- **Prototype** integrations before writing code

The MCP servers already exist. The protocol is standard. The ecosystem is growing. `mcp` just gives you a front door to all of it from the command line.

## Further reading

- [Introducing the Model Context Protocol](https://www.anthropic.com/news/model-context-protocol) — Anthropic's original announcement (Nov 2024)
- [Why the Model Context Protocol Won](https://thenewstack.io/why-the-model-context-protocol-won/) — Analysis of MCP's adoption trajectory
- [One Year of MCP](https://thenewstack.io/one-year-of-mcp-looking-back-and-forward/) — Looking back at the first year
- [A Year of MCP: From Internal Experiment to Industry Standard](https://www.pento.ai/blog/a-year-of-mcp-2025-review) — Comprehensive review of MCP's evolution
- [Goodbye Plugins: MCP Is Becoming the Universal Interface for AI](https://thenewstack.io/goodbye-plugins-mcp-is-becoming-the-universal-interface-for-ai/) — MCP replacing proprietary plugin models
- [Linux Foundation Announces the Agentic AI Foundation](https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation) — MCP moves to Linux Foundation
- [Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp) — Anthropic engineering on MCP capabilities
- [Introducing MCP Tools CLI](https://blog.fka.dev/blog/2025-03-26-introducing-mcp-tools-cli/) — CLI inspector for MCP servers
- [Inspecting and Debugging MCP Servers Using CLI and jq](https://blog.fka.dev/blog/2025-03-25-inspecting-mcp-servers-using-cli/) — Using MCP servers as standalone tools
