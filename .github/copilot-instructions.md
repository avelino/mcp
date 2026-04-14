# Copilot Instructions

## Project Overview

`mcp` is a Rust CLI that turns MCP (Model Context Protocol) servers into terminal commands. It supports stdio and HTTP transports, a proxy/gateway mode, server registry, audit logging, and ACL-based auth.

## Tech Stack

- **Language:** Rust (edition 2021)
- **Async runtime:** Tokio (full features)
- **HTTP:** Axum (server), Reqwest with rustls-tls (client)
- **Serialization:** Serde + serde_json
- **Error handling:** `anyhow::Result` throughout
- **Storage:** chrondb for persistent state
- **Tests:** built-in `#[cfg(test)]` modules, `tempfile` for test fixtures

## Code Style & Conventions

- No `#[allow(dead_code)]` — wire it up or delete it.
- Functions do one thing. Max ~50 lines. Max 3 levels of nesting.
- Comments explain **why**, not what.
- No unnecessary abstractions — solve the actual problem, not a hypothetical one.
- Zero `unsafe` code — all concurrency through safe abstractions.

### Error Handling

- All functions return `anyhow::Result<T>`. No custom error types.
- Use `.context("msg")?` or `.with_context(|| format!("msg {var}"))?` to add context on propagation.
- Use `bail!("msg")` for early returns with error.
- Use `.map_err(|e| anyhow::anyhow!("msg: {e:?}"))` only when wrapping external library errors that don't implement `std::error::Error`.
- Never silently swallow errors — at minimum log with `eprintln!`.

### Async Patterns

- All async via Tokio. Entry point is `#[tokio::main]`.
- Interior mutability with `Arc<Mutex<T>>` or `Arc<RwLock<T>>` for shared state across tasks.
- Bounded `mpsc::channel` for task communication, `oneshot` for request-response matching.
- `tokio::spawn` for background tasks (readers, writers). `spawn_blocking` for sync-heavy work (db writes).
- Timeouts via `tokio::time::timeout(Duration, future)` — never block indefinitely.

### Serialization

- Derive order: `#[derive(Debug, Serialize, Deserialize, Clone)]`.
- `#[serde(rename = "camelCase")]` for protocol fields matching JSON-RPC/MCP spec.
- `#[serde(skip_serializing_if = "Option::is_none")]` on all `Option` fields for compact JSON.
- `#[serde(default)]` on optional deserialization fields.
- `#[serde(untagged)]` for config enums with variant ordering (serde tries in declaration order).

### Module Organization

- Binary crate (`main.rs`), no `lib.rs`.
- Private submodules with selective re-exports: `mod foo; pub use foo::handle_foo;`.
- Trait objects (`Arc<dyn Trait>`) over generics for polymorphism (e.g., `Arc<dyn Transport>`).
- `#[async_trait]` with `Send + Sync` bounds on all trait definitions.

### Logging & Output

- Debug/diagnostic output to stderr via `eprintln!("[prefix] message")` with component prefix: `[db]`, `[cache]`, `[server stderr]`.
- User-facing output through `OutputFormat` enum — auto-detects JSON (piped) vs Text (TTY).
- Results always to stdout, diagnostics always to stderr.

### Environment Variables

- Pattern: `std::env::var("MCP_*").ok().and_then(|v| v.parse().ok()).unwrap_or(default)`.
- No dotenv or external config library. Pure JSON config files + env var overrides.

## State & Persistence (ChronDB)

The project uses **ChronDB** as its single persistent key-value store. All state manipulation follows these rules:

### Architecture

- `DbPool` (`src/db.rs`) wraps `ChronDB` with `Option<Arc<ChronDB>>` — supports a `disabled()` state for environments without writable filesystem (containers, CI).
- A single `Arc<DbPool>` is created at startup via `create_pool()` and shared across all consumers.
- ChronDB manages its own GraalVM isolate lifecycle with idle timeout (120s default) — no external GC thread needed.

### Key Schema

All keys use a **prefixed namespace** pattern to avoid collisions:

| Consumer | Key pattern | Value |
|----------|------------|-------|
| Audit log | `audit:{timestamp_ms}-{uuid}` | Serialized `AuditEntry` |
| Tool cache | `cache:tools:{server_name}` | Serialized `BackendToolCache` |

**New consumers must** define a unique prefix and document it in this table.

### Read/Write Patterns

- **Read:** `db.get(&key, None)` returns `serde_json::Value`. Deserialize with `serde_json::from_value`. Always handle `Ok`/`Err` — missing keys return error, not `None`.
- **Write:** Serialize to `serde_json::Value` first, then `db.put(&key, &value, None)`. The third parameter is reserved (pass `None`).
- **List:** `db.list_by_prefix("prefix:", None)` for range queries (e.g., audit log retrieval).
- **No delete API is used** — data is append-only or overwritten by key.

### Concurrency Rules

- Audit writes go through an **unbounded mpsc channel** → `spawn_blocking` writer thread. This decouples hot paths from db latency.
- Cache reads/writes are **synchronous on the caller** (blocking the async task briefly). Acceptable because cache ops are fast and infrequent.
- Always acquire the db handle via `pool.acquire()` — never hold `Arc<ChronDB>` across await points.

### Review Checklist for DB Changes

When reviewing code that touches ChronDB:

- [ ] Key prefix is unique and documented in the table above
- [ ] Serialization round-trips correctly (write + read produces identical struct)
- [ ] Errors on `acquire()`, `put()`, `get()` are handled — at minimum logged, never silently ignored
- [ ] No `Arc<ChronDB>` held across `.await` — acquire, use, drop
- [ ] High-throughput writes use a channel + `spawn_blocking`, not inline `put()`
- [ ] `DbPool::disabled()` path is respected — code must not panic when db is unavailable
- [ ] New keys don't collide with existing prefixes

## CI Requirements

CI runs these three checks in order — all must pass before merging:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Always validate locally before submitting a PR.

## Security & ACL

Any change touching `src/server_auth/`, ACL logic, auth providers, or credential parsing **must** include tests for:

- **Bypass:** invalid/malformed/absent tokens, wrong auth scheme, malformed JSON
- **Privilege escalation:** role leaking between identities, legacy tokens never returning roles, injection in trusted headers
- **Backwards compatibility:** legacy auth forms continue working without changes
- **Parsing edge cases:** CSV with spaces, empty entries, unicode, case-sensitivity
- **Deny tests ≥ allow tests** — happy path alone is not sufficient security coverage

## Guidelines for PRs

- Keep PRs focused — one concern per PR.
- If a PR touches auth/ACL, include the full security test battery described above.
- Don't add features or refactoring beyond what was asked.
- Test behavior, not implementation details.
- Integration tests over excessive unit tests for glue code.
