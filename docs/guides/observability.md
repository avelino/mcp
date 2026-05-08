# Observability — OpenTelemetry traces & metrics

`mcp serve` (proxy mode) emits native OTLP **traces** and **metrics**.
Default-off: without an env var, behavior is byte-identical to 0.5.2 —
structured logs on stderr + local audit trail in chrondb.

> **Want to try it now?** Jump to the [hands-on quickstart](../howto/observability-quickstart.md)
> — it spins up Jaeger + `mcp serve` in 3 minutes and proves the full path
> end-to-end (including `traceparent` propagation and metrics).
>
> This page is the **reference** — what each attribute means, how to
> configure each vendor, and the escape hatches for when something goes
> sideways.

## Escape hatches (read this first)

Running `mcp serve` in production and nervous about turning OTel on? Two
switches worth knowing:

- **Unset `OTEL_EXPORTER_OTLP_ENDPOINT`** → telemetry is **fully**
  disabled. Behavior is identical to 0.5.2. No rebuild, no rollback,
  just remove the env var from the deploy.
- **`MCP_OTEL_INJECT_TRACEPARENT=0`** → keeps traces and metrics on,
  **only** disables `traceparent` injection on outbound calls. Use this
  if some odd backend rejects unknown headers (W3C `traceparent` is
  standard, but bad servers exist).

## Configuration — standard OTel env vars

Everything is driven by OTel env vars. **Nothing** lives in `servers.json`.

| Variable | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | **Sole activator.** Empty or unset = OTel off. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` (default) or `http/protobuf`. |
| `OTEL_EXPORTER_OTLP_HEADERS` | CSV `k1=v1,k2=v2`. HTTP only per spec. |
| `OTEL_SERVICE_NAME` | Resource `service.name`. Default `mcp`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, CSV format. |
| `MCP_OTEL_INJECT_TRACEPARENT` | `0`/`false`/`no` disables outbound injection. |

> **Quick diagnostic**: when OTel boots, the very first line on stderr is
> `[telemetry] OpenTelemetry initialized — endpoint=... protocol=...`.
> It prints directly to stderr and **does not** respect `MCP_LOG_LEVEL`.
> If you don't see it, OTel didn't start — check the env var.

## Vendor recipes

### Honeycomb

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=YOUR_API_KEY" \
OTEL_SERVICE_NAME=mcp-prod \
OTEL_RESOURCE_ATTRIBUTES="deployment.environment=production" \
mcp serve --http 0.0.0.0:7331 --insecure
```

The public Honeycomb ingest **only accepts HTTP/protobuf** — gRPC won't
work. Don't forget the `x-honeycomb-team` header.

### Grafana Tempo (self-hosted)

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317 \
OTEL_EXPORTER_OTLP_PROTOCOL=grpc \
OTEL_SERVICE_NAME=mcp \
mcp serve --http 0.0.0.0:7331 --insecure
```

`grpc` is the OTel SDK default — you can omit `OTEL_EXPORTER_OTLP_PROTOCOL`
if you want.

### Datadog (via Agent)

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://datadog-agent:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_SERVICE_NAME=mcp \
OTEL_RESOURCE_ATTRIBUTES="env=prod,team=platform" \
mcp serve --http 0.0.0.0:7331 --insecure
```

The Datadog Agent exposes an OTLP receiver on 4317/4318 once enabled.

### Local (development)

To bring up Jaeger + see the whole flow on your machine, follow the
[hands-on quickstart](../howto/observability-quickstart.md).

## Span attributes

Every request produces a single root span `mcp.request` with:

| Attribute | Meaning |
|---|---|
| `otel.kind` | `server` |
| `mcp.method` | JSON-RPC method (`tools/call`, `tools/list`, `resources/read`, …) |
| `mcp.transport` | `serve:http` or `serve:stdio` |
| `mcp.identity` | Authenticated subject (JWT `sub`, bearer-token name, or `anonymous`) |
| `mcp.server` | Backend alias, **only** after routing resolves (tools/call, resources/read, prompts/get) |
| `mcp.tool` | Backend tool name |
| `mcp.status` | `ok` or `error` |

Span duration = total time inside `dispatch_request`. Includes ACL
evaluation, the brief proxy lock, the backend connection, and the backend
call itself — useful to see where latency is going.

Inbound `traceparent` (from the client) is honored: the `mcp` span
becomes a child of the client's span, no new trace is created. Outbound,
`mcp` injects `traceparent`/`tracestate` automatically — an instrumented
backend continues the trace.

## Metrics

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `mcp.proxy.requests` | counter | — | `mcp.method`, `mcp.transport`, `mcp.status`, `mcp.identity`, `mcp.server`*, `mcp.tool`* |
| `mcp.proxy.request.duration` | histogram | ms | same as the counter |
| `mcp.proxy.classifier.cache.hits` | counter | — | `mcp.server` |
| `mcp.proxy.classifier.cache.misses` | counter | — | `mcp.server` |
| `mcp.proxy.backends.connected` | gauge | — | — |
| `mcp.proxy.sessions.active` | gauge | — | — |

\* `mcp.server` and `mcp.tool` only appear when the request resolves to
a backend (absent on `auth/failure`, unknown methods, malformed payload).
The `mcp.tool` label carries the backend tool name (un-namespaced) — the
namespace lives in `mcp.server`.

The PeriodicReader exports every 60s (OTel SDK default). When testing
locally, wait ~65s after the first request before checking the exporter.

## Cardinality — heads-up

`mcp.identity` discriminates per authenticated subject. If your subjects
are per-user UUID JWTs, you'll generate many series. Honeycomb / Tempo /
Datadog handle it, but it's a deliberate trade-off — if you only care
about role-level breakdowns, drop the label upstream (in your collector
config).

## What it does NOT do

- **No Sentry / panic tracking.** Errors flow as `mcp.status=error` on
  the span. Sentry is tracked in a separate issue.
- **No continuous profiling.**
- **No OTLP logs signal.** The audit trail stays in chrondb (`mcp logs`);
  the structured log keeps going to stderr, controlled by `MCP_LOG_LEVEL`
  / `MCP_LOG_FORMAT`.

## Troubleshooting

If something went wrong, [the quickstart](../howto/observability-quickstart.md#troubleshooting)
has a longer checklist. In short:

- **No `[telemetry] OpenTelemetry initialized` on stderr** = the env var
  wasn't read. Check `OTEL_EXPORTER_OTLP_ENDPOINT`.
- **It initialized but nothing arrives** = wrong endpoint, firewall, or
  a vendor that only accepts HTTP (`OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`).
- **`traceparent` not reaching the backend** = either telemetry didn't
  initialize, or `MCP_OTEL_INJECT_TRACEPARENT=0` is set.
