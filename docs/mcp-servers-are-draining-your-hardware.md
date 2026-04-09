# MCP servers are draining your hardware (and nobody talks about it)

You open Claude Code. It spawns 10 MCP server processes. You open another session. 10 more. Cursor? 10 more. By lunch you're running 30+ background processes that sit idle 95% of the time, eating RAM and CPU just to exist.

This is the dirty secret of MCP adoption in 2025: **every client treats backend servers as permanent fixtures**. Connect on start, keep alive forever, kill on exit. No intelligence, no resource awareness.

## The problem

Here's what happens today when you configure MCP servers in any major client:

```
Claude Code session 1  →  spawns slack, sentry, github, grafana, honeycomb...
Claude Code session 2  →  spawns slack, sentry, github, grafana, honeycomb...
Cursor                 →  spawns slack, sentry, github, grafana, honeycomb...
```

Each session gets its own copy of every server. A typical stdio MCP server (Node.js via `npx`) uses 80-150 MB of RAM. Configure 10 servers, open 3 sessions:

**30 processes × ~100 MB = ~3 GB of RAM doing nothing.**

And it's not just RAM. Each process holds open connections, file descriptors, and event loops. Your laptop fan spins up. Your battery drains. Docker containers balloon. CI runners choke.

The irony: you probably use 2-3 of those servers in any given session. The other 7 are zombie processes waiting for a request that never comes.

## Why clients do this

The current behavior makes sense from a simplicity standpoint:

1. Connect to everything at startup — tools are available instantly
2. Keep connections alive — no latency on tool calls
3. Kill on exit — clean shutdown

It's the easiest thing to implement. And when MCP was new and people had 1-2 servers, nobody noticed the cost. But the ecosystem grew. People now configure 5, 10, 15 servers. The linear cost became unsustainable.

The MCP spec itself doesn't say anything about lifecycle management. It defines how to connect, how to list tools, how to call them — but not **when** to connect or **when** to disconnect. That decision is left to clients. And most clients chose the simplest path: always on.

## What we built

We solved this in the [`mcp` CLI](https://mcp.avelino.run) proxy with two mechanisms: **lazy initialization** and **adaptive idle shutdown**.

### Lazy initialization

No backend connects at startup. Zero processes spawned. The proxy starts instantly.

When a client sends `tools/list` for the first time, the proxy connects to all backends, discovers their tools, and caches the results. After that, idle backends are shut down — but their tools remain visible.

When a client calls `tools/call` targeting a disconnected backend, the proxy reconnects it transparently. The client never knows the difference.

```
Startup:     0 processes (instant start)
tools/list:  10 backends connect, discover tools, idle ones shut down
tools/call:  only the target backend reconnects on demand
```

### Adaptive idle shutdown

A background task checks every 30 seconds which backends are idle and shuts them down. But not all backends get the same timeout — it adapts to usage patterns.

The proxy tracks per-backend statistics:
- Request count
- Time since first use
- Exponential moving average (EMA) of intervals between requests

From this it classifies each backend into tiers:

| Usage | Requests/hour | Idle timeout |
|-------|--------------|-------------|
| **Hot** — you're actively using it | > 20 | 5 min |
| **Warm** — occasional use | 5–20 | 3 min |
| **Cold** — barely touched | < 5 | 1 min |

A backend you haven't touched in 60 seconds gets shut down. One you're actively querying gets 5 minutes of grace. The algorithm adapts as your usage changes — a backend that was cold in the morning becomes hot when you start debugging a Sentry issue.

Usage stats survive reconnections. If a backend is shut down and reconnected, its history is preserved so the adaptive timeout has continuity.

### The result

Same scenario as before — 10 servers, 3 sessions — but using the `mcp` proxy:

```
Before:  30 processes running permanently (~3 GB RAM)
After:   1 proxy process + only active backends (~200-400 MB)
```

And there's no tradeoff in functionality. Every tool is still visible. Every call still works. The reconnection adds ~1-2 seconds of latency on the first call to a cold backend — after that, it's instant.

## How to use it

Run the proxy as a persistent service:

```bash
mcp serve --http
```

Point your clients to it:

```json
{
  "mcpServers": {
    "all": {
      "type": "sse",
      "url": "http://localhost:8080/mcp/sse"
    }
  }
}
```

All sessions share one proxy. The proxy manages backend lifecycles. You can configure per-backend behavior:

```json
{
  "mcpServers": {
    "slack": {
      "command": "npx",
      "args": ["@anthropic/mcp-slack"],
      "idle_timeout": "adaptive"
    },
    "sentry": {
      "url": "https://mcp.sentry.io",
      "idle_timeout": "never"
    },
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github"],
      "idle_timeout": "2m"
    }
  }
}
```

- `"adaptive"` (default) — usage-based timeout
- `"never"` — keep alive forever
- `"2m"`, `"30s"`, `"1h"` — fixed timeout

Full configuration reference: [idle timeout options](https://mcp.avelino.run/reference/config-file#idle-timeout). Proxy mode setup: [proxy mode guide](https://mcp.avelino.run/guides/proxy-mode).

### Update (April 2026): N clients, M backends

The original `mcp serve` only solved half the problem — it stopped *one* client from spawning duplicate backends, but if you had multiple editors connecting at the same time, the proxy itself could serialize them or, worse, accumulate orphan processes when a client died. After [#51](https://github.com/avelino/mcp/issues/51) the proxy is now an actual orchestrator: a single backend process is shared across **every connected client**, requests run in parallel through the stdio multiplexer, and dead clients can never leak backend children. The numbers from a real run with 5 editor sessions and 9 backends:

```json
{
  "backends_configured": 9,
  "backends_connected": 9,
  "active_clients": 5,
  "tools": 213
}
```

9 processes serving 5 clients, not 45. That's the full version of the win this post described.

## What should change in the ecosystem

This isn't just a `mcp` CLI problem. Every MCP client should implement some form of lazy lifecycle management:

1. **Don't connect at startup.** Wait until the user actually needs a tool.
2. **Cache tool lists.** You don't need a live connection to advertise tools.
3. **Shut down idle backends.** If a backend hasn't been used in N minutes, kill it. Reconnect on demand.
4. **Track usage patterns.** Not all backends are equal. The one you use 50 times a day deserves a longer timeout than the one you use once a week.

The MCP spec could help by defining optional lifecycle hints — a `keepAlive` capability, a recommended idle timeout, a "lightweight discovery" mode that returns tool metadata without a full connection. But even without spec changes, clients can be smarter today.

## The math is simple

Every MCP server process you don't run is:
- ~100 MB of RAM you keep
- One fewer event loop burning CPU cycles
- One fewer set of open file descriptors
- One fewer process for your OS to schedule

Multiply by the number of servers. Multiply by the number of sessions. The savings compound fast.

MCP is becoming infrastructure. Infrastructure that doesn't manage its own resource footprint doesn't survive at scale. It's time for MCP clients to grow up.

---

`mcp` is an open-source CLI that turns MCP servers into terminal commands. [Getting started](https://mcp.avelino.run/getting-started) takes 5 minutes. Source code: [github.com/avelino/mcp](https://github.com/avelino/mcp).
