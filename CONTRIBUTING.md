# Contributing to mcp

Thanks for considering contributing! Every contribution matters — bug reports, docs improvements, tests, and code changes are all welcome.

## Table of Contents

- [Contribution Flow](#contribution-flow)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Community](#community)

## Contribution Flow

**Issue first, code second.** Every contribution follows this flow:

### 1. Open an Issue

Before writing any code, open an issue describing:

- **Bug?** What you expected, what happened, steps to reproduce, `mcp --version` and OS.
- **Feature?** The problem you're trying to solve (not just the solution), why it matters, alternatives you've considered.
- **Docs / typos:** small fixes can skip straight to a PR — no issue needed.

### 2. Discuss the Approach

In the issue comments, propose **how** you plan to implement the change — which files, what strategy, any trade-offs. Wait for alignment from a maintainer before writing code. This avoids wasted effort on approaches that don't fit the project.

### 3. Implement

Once we agree on the approach:

1. Fork the repo and create a branch from `main`.
2. Keep the scope focused — one concern per PR.
3. Add or update tests for any changed behavior.
4. Run the full validation locally (see [Testing](#testing)).

### 4. Open a Pull Request

Link the issue with `Closes #N` or `Fixes #N`. The PR description should summarize **what** changed and **why**, but the deeper discussion lives in the issue.

**PRs without a linked issue (except trivial fixes) will be asked to open one first.**

Look for issues labeled [`good first issue`](https://github.com/avelino/mcp/labels/good%20first%20issue) or [`help wanted`](https://github.com/avelino/mcp/labels/help%20wanted) if you want a starting point.

## Development Setup

**Prerequisites:**

- Rust stable toolchain (we track latest stable)
- `rustfmt` and `clippy` components (`rustup component add rustfmt clippy`)

**Clone and build:**

```bash
git clone https://github.com/avelino/mcp.git
cd mcp
cargo build
```

**With Docker (no local Rust needed):**

```bash
docker build -t mcp .
```

## Making Changes

1. Fork the repo and create a branch from `main`.
2. Make your changes — keep the scope focused. One concern per PR.
3. Add or update tests for any changed behavior.
4. Run the full validation locally (see below).
5. Push and open a PR.

## Testing

All three checks must pass before a PR is mergeable:

```bash
cargo fmt --check    # formatting
cargo clippy -- -D warnings   # lints, zero warnings allowed
cargo test           # all tests
```

Run them in this order — CI runs exactly these three commands.

### Writing Tests

- Tests live in `#[cfg(test)]` modules at the bottom of each source file.
- Test naming: `test_<component>_<scenario>` (e.g., `test_acl_deny_invalid_token`).
- Use `serde_json::json!()` for test fixtures, `tempfile` for temp directories.
- Test behavior, not implementation. Integration tests over excessive unit tests for glue code.
- Bug found? Write a failing test first, then fix.

### Security-Sensitive Areas

Any change touching `src/server_auth/`, ACL, auth providers, or credential parsing must include:

- Bypass tests (invalid/malformed/absent tokens, wrong scheme)
- Privilege escalation tests (role leaking, injection in trusted headers)
- Backwards compatibility tests (legacy auth forms still work)
- Parsing edge cases (CSV with spaces, empty entries, unicode, case-sensitivity)
- Deny tests in quantity ≥ allow tests

Happy path alone is not sufficient. See [`CLAUDE.md`](CLAUDE.md) for the full checklist.

## Code Style

### General

- No `#[allow(dead_code)]` — wire it up or delete it.
- Functions do one thing. Keep them under ~50 lines. Max 3 levels of nesting.
- Comments explain **why**, not what.
- Zero `unsafe` code.

### Error Handling

- All functions return `anyhow::Result<T>`. No custom error types.
- Add context on propagation: `.context("what failed")?`.
- Use `bail!("message")` for early error returns.
- Never silently swallow errors.

### Async

- `Arc<Mutex<T>>` for shared mutable state across tasks.
- Bounded `mpsc::channel` for task communication.
- High-throughput writes go through a channel → `spawn_blocking` writer. Don't block async tasks with db calls.
- Always use `tokio::time::timeout` — never block indefinitely.

### Serialization

- `#[serde(skip_serializing_if = "Option::is_none")]` on all `Option` fields.
- `#[serde(default)]` on optional deserialization fields.
- `#[serde(rename = "camelCase")]` for protocol-facing fields matching JSON-RPC/MCP spec.

### State & Persistence (ChronDB)

All persistent state goes through `DbPool` (`src/db.rs`). Key rules:

- Every key uses a **namespaced prefix** (`audit:`, `cache:tools:`). New consumers must define a unique prefix.
- Acquire db via `pool.acquire()`, use it, drop it. Never hold `Arc<ChronDB>` across `.await` points.
- Respect `DbPool::disabled()` — code must not panic when db is unavailable.
- High-throughput writes: channel + `spawn_blocking`. Cache reads: inline (fast and infrequent).

### Logging

- Diagnostics to stderr: `eprintln!("[prefix] message")` with component tag (`[db]`, `[cache]`, etc.).
- User-facing output to stdout via `OutputFormat` (auto-detects JSON vs text by TTY).

## Submitting a Pull Request

### Before Submitting

- [ ] Linked issue exists and approach was discussed
- [ ] Code compiles: `cargo build`
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes with zero warnings
- [ ] `cargo test` passes
- [ ] New behavior has tests
- [ ] Security-sensitive changes include the full test battery
- [ ] PR description explains **what** and **why**, links issue with `Closes #N`

### PR Guidelines

- Keep PRs small and focused. Large PRs take longer to review and are more likely to need rework.
- PR title should be concise and descriptive.
- Respond to review feedback — we aim for constructive, fast reviews.

## Security Vulnerabilities

**Do not open public issues.** Use [GitHub Security Advisories](https://github.com/avelino/mcp/security/advisories/new) instead. See [`SECURITY.md`](SECURITY.md) for details.

## Community

- Be respectful and constructive.
- Help others when you can.
- Give credit where it's due.

Questions? Open a [discussion](https://github.com/avelino/mcp/discussions) or comment on an issue.
