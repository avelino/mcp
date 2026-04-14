# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest release | ✅ |
| older releases | ❌ |

Only the latest release receives security fixes. Upgrade to stay protected.

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/avelino/mcp/security/advisories/new) to report vulnerabilities privately. This ensures the issue is triaged before public disclosure.

When reporting, include:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected component (e.g., `server_auth`, `transport`, `config`)
- Impact assessment (what an attacker could achieve)

## Response Timeline

- **Acknowledgment:** within 3 business days
- **Triage and initial assessment:** within 7 business days
- **Fix or mitigation:** depends on severity, targeting 30 days for critical issues

## Scope

The following areas are in scope:

- Authentication and authorization bypass (`src/server_auth/`, `src/auth/`)
- ACL policy enforcement
- Transport security (stdio, HTTP, SSE)
- Configuration parsing that could lead to privilege escalation
- Dependency vulnerabilities with exploitable impact

Out of scope:

- Denial of service via resource exhaustion on localhost-only deployments
- Vulnerabilities in upstream dependencies without a demonstrated exploit path
- Social engineering

## Disclosure

We follow coordinated disclosure. Once a fix is released, we will:

1. Publish a GitHub Security Advisory with full details
2. Credit the reporter (unless they prefer anonymity)
3. Release a patched version
