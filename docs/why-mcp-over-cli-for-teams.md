# Why MCP instead of CLI when your team uses LLMs

Your team already has CLIs. kubectl, terraform, aws, docker — they work. Why add MCP to the mix?

Because when AI agents enter the picture, CLI stops scaling. The problem isn't the tool — it's how credentials, access control, and observability work when 30 engineers have AI agents calling tools autonomously.

## The CLI model breaks with AI agents

A developer running `kubectl get pods` is one thing. An AI agent running it across 15 concurrent sessions is another.

**With CLI:**
- Every developer machine needs credentials for every tool
- Every AI tool (Claude Code, Cursor, Windsurf) needs its own config with the same credentials
- No central visibility into what agents are doing
- No way to restrict which commands an agent can run
- Credentials scattered across laptops — impossible to audit

**With MCP:**
- One proxy holds all credentials — developer machines have zero service tokens
- One config for all AI tools — they all connect to the same MCP endpoint
- Every tool call is logged with who, what, when
- ACL rules control exactly which tools each person can use
- Onboarding is one token, offboarding is one revocation

## The math

| | CLI | MCP (proxy) |
|---|---|---|
| Credentials to manage (50 devs, 8 services) | 400 tokens on 50 laptops | 8 tokens on 1 server |
| Onboarding a new dev | Generate 8 tokens, configure 3 AI tools | 1 proxy token |
| Offboarding | Hunt down tokens across machines | Delete 1 token |
| Token rotation | Update 50 machines | Update 1 server |
| Audit trail | None | Every call logged |
| Access control | All or nothing | Per-user, per-tool ACL |

## CLI as MCP — best of both worlds

You don't need to choose. With [CLI as MCP](guides/cli-as-mcp.md), your existing CLIs become MCP servers:

```json
{
  "mcpServers": {
    "kubectl": {
      "command": "kubectl",
      "cli": true,
      "cli_only": ["get", "describe", "logs", "top"]
    },
    "terraform": {
      "command": "terraform",
      "cli": true,
      "cli_only": ["plan", "show", "state", "output"]
    }
  }
}
```

Deploy this as a [centralized proxy](https://mcp.avelino.run/guides/enterprise-token-management) and your team gets:

1. **AI agents access kubectl and terraform via MCP** — no kubeconfig on developer machines
2. **`cli_only` restricts dangerous commands** — agents can `get` and `describe`, but not `delete` or `exec`
3. **Every call is audited** — `mcp logs` shows who ran what
4. **Credentials stay on the proxy** — `KUBECONFIG`, `AWS_ACCESS_KEY_ID` live in one place

## Real scenario

**Before:** 30 engineers, each with kubeconfig, AWS credentials, Terraform state access, GitHub token, Sentry token on their laptops. 3 AI tools per engineer, each with its own config. An engineer leaves — good luck revoking everything.

**After:**

```
Developer laptop                    Internal proxy (mcp serve --http)
┌──────────────┐                    ┌──────────────────────────────┐
│ Claude Code  │──── 1 token ──────>│  kubectl (cli, read-only)   │
│ Cursor       │                    │  terraform (cli, plan only)  │
│ Windsurf     │                    │  sentry (MCP server)         │
│              │                    │  grafana (MCP server)        │
│ Zero service │                    │  slack (MCP server)          │
│ credentials  │                    │                              │
└──────────────┘                    │  All credentials here.       │
                                    │  All calls logged.           │
                                    │  ACL per user.               │
                                    └──────────────────────────────┘
```

Engineer joins? One proxy token. Engineer leaves? Delete one token. Rotate AWS keys? Update one config.

## When CLI alone is fine

Not every situation needs MCP:

- **Solo developer** — credentials on your own machine is fine
- **CI/CD pipelines** — already have controlled environments with secret management
- **Interactive debugging** — you're the one typing commands, not an AI agent

MCP adds value when **AI agents act on behalf of people** and you need control over what they can do, where credentials live, and what gets logged.

## Get started

1. [CLI as MCP](guides/cli-as-mcp.md) — wrap your CLIs as MCP servers
2. [Enterprise token management](guides/enterprise-token-management.md) — centralize credentials with the MCP proxy
3. [Proxy mode](guides/proxy-mode.md) — deploy `mcp serve` for your team
4. [Audit logging](guides/audit-logging.md) — monitor what agents are doing
