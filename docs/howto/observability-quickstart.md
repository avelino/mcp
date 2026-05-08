# Quickstart — OpenTelemetry on `mcp serve`

Copy-paste tutorial to bring up traces + metrics in ~3 minutes. Runs
locally with Jaeger (nice UI) and then shows how to inspect metrics
with the OTel Collector. Ends with the regression test (default-off).

Prerequisites: Docker + a build of `mcp` that includes native OTel
support (any post-OpenTelemetry release; check `mcp --version`).

> Why bother running this? Before pointing `mcp serve` at a production
> Honeycomb / Datadog / Tempo, you want to **prove locally** that the
> trace flows, that `traceparent` propagates, and that without the env
> var nothing changes. This walkthrough proves all three.

---

## 1. Start Jaeger

Jaeger v2 speaks OTLP natively (gRPC on `:4317`, HTTP on `:4318`) and
ships a UI on `:16686`. One container does it:

```bash
docker run -d --rm --name mcp-jaeger \
  -p 16686:16686 -p 4317:4317 -p 4318:4318 \
  jaegertracing/jaeger:latest
```

Wait until it's up:

```bash
until curl -fsS http://127.0.0.1:16686/api/services >/dev/null; do sleep 1; done
echo READY
```

UI: <http://localhost:16686>.

---

## 2. Start `mcp serve` with OTel enabled

Point it at Jaeger's HTTP receiver (port 4318).
`OTEL_EXPORTER_OTLP_ENDPOINT` is the **sole** activator — every other
env var below is optional:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_SERVICE_NAME=mcp-local \
mcp serve --http 127.0.0.1:7331
```

On stderr, **the very first line** must be:

```
[telemetry] OpenTelemetry initialized — endpoint=http://127.0.0.1:4318 protocol=HttpProto
```

> Without that line, OTel did **not** start. Double-check the env var.

Leave it running.

---

## 3. Fire some requests

In another terminal:

```bash
# tools/list — span without mcp.tool/mcp.server (no backend resolved)
for i in 1 2 3; do
  curl -s -X POST http://127.0.0.1:7331/mcp \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/list\"}" \
    -o /dev/null -w "tools/list $i: %{http_code}\n"
done

# tools/call — span with mcp.tool and mcp.server resolved
# (replace filesystem__list_allowed_directories with one of your own tools)
curl -s -X POST http://127.0.0.1:7331/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":99,"method":"tools/call",
       "params":{"name":"filesystem__list_allowed_directories","arguments":{}}}' \
  -o /dev/null -w "tools/call: %{http_code}\n"
```

Wait for the batch to flush (default ~5s):

```bash
sleep 8
```

---

## 4. Inspect the spans in Jaeger

Open <http://localhost:16686>:

1. **Service:** pick `mcp-local`
2. **Operation:** `mcp.request`
3. Click **Find Traces**

You'll see N traces, each with one `mcp.request` span. Click any of
them — under **Tags** you should find:

```
otel.kind       = server
mcp.method      = tools/list (or tools/call)
mcp.transport   = serve:http
mcp.identity    = anonymous
mcp.status      = ok
mcp.server      = filesystem      ← only on resolved tools/call
mcp.tool        = list_allowed_directories
```

Span duration is the total time `dispatch_request` took — includes ACL,
the proxy lock, backend connection, and the backend call itself.

### Sanity check via API (no clicking)

```bash
curl -s "http://127.0.0.1:16686/api/traces?service=mcp-local&limit=3" \
  | python3 -c '
import json, sys
for t in json.load(sys.stdin)["data"]:
    for s in t["spans"]:
        tags = {tg["key"]: tg.get("value") for tg in s["tags"]}
        mcp = {k:v for k,v in tags.items() if k.startswith("mcp.")}
        print(f"{s[\"operationName\"]:14} dur={s[\"duration\"]:>7}us {mcp}")
'
```

---

## 5. Test parent context (inbound `traceparent`)

When the client is OTel-aware (Claude.ai, an instrumented gateway, an
OTel SDK), it sends `traceparent` in the headers. `mcp serve` should
**continue the trace** — its span becomes a child of the client's
span instead of starting a new trace.

Send a fake `traceparent` and check stitching:

```bash
TRACEPARENT='00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

curl -s -X POST http://127.0.0.1:7331/mcp \
  -H 'Content-Type: application/json' \
  -H "traceparent: $TRACEPARENT" \
  -d '{"jsonrpc":"2.0","id":42,"method":"tools/list"}' \
  -o /dev/null -w "HTTP %{http_code}\n"

sleep 5

# Pull the trace by the traceID we injected
curl -s "http://127.0.0.1:16686/api/traces/0af7651916cd43dd8448eb211c80319c" \
  | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]
if not data:
    print("FAIL: parent context did not work")
else:
    for s in data[0]["spans"]:
        refs = s.get("references", [])
        parent = refs[0]["spanID"] if refs else "ROOT"
        print(f"  span {s[\"operationName\"]} parent={parent}")
'
```

Expected output:

```
  span mcp.request parent=b7ad6b7169203331
```

`parent=b7ad6b7169203331` confirms the `mcp.request` span became a child
of the span we sent in `traceparent`. Trace stitching ✓.

---

## 6. Inspect the metrics

Jaeger v2 only stores traces. To see counters / histograms / gauges,
swap it out for an OTel Collector with a debug exporter:

```bash
docker stop mcp-jaeger

cat > /tmp/otel-debug.yaml <<'EOF'
receivers:
  otlp:
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }
      http: { endpoint: 0.0.0.0:4318 }
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:  { receivers: [otlp], exporters: [debug] }
    metrics: { receivers: [otlp], exporters: [debug] }
EOF

docker run -d --rm --name mcp-otelcol \
  -v /tmp/otel-debug.yaml:/etc/otelcol-contrib/config.yaml \
  -p 4317:4317 -p 4318:4318 \
  otel/opentelemetry-collector-contrib:latest
```

Keep firing requests at `mcp serve`. **Important:** the PeriodicReader
exports metrics every 60s (OTel SDK default), so **wait ~65 seconds**
after the first request.

After 65s:

```bash
docker logs mcp-otelcol 2>&1 | grep -E "Name:|Value:|mcp\." | head -40
```

Expected output:

```
     -> Name: mcp.proxy.requests
     -> mcp.method: Str(tools/call)
     -> mcp.server: Str(filesystem)
     -> mcp.tool: Str(list_allowed_directories)
Value: 6
     -> Name: mcp.proxy.classifier.cache.hits
     -> mcp.server: Str(filesystem)
Value: 28
     -> Name: mcp.proxy.backends.connected
Value: 6
     -> Name: mcp.proxy.sessions.active
Value: 0
```

> The metrics `mcp` emits, in one line:
> - `mcp.proxy.requests` (counter) and `mcp.proxy.request.duration` (histogram, ms) — one per request, with labels `method/server/tool/status/transport/identity`
> - `mcp.proxy.classifier.cache.hits/misses` per server
> - `mcp.proxy.backends.connected` and `mcp.proxy.sessions.active` (gauges) refreshed at every export

---

## 7. Regression test — no OTel = 0.5.2 behavior

This is the step that **proves your current production version won't
break**. Kill the running `mcp serve` and bring it back up **without
any OTel env var**:

```bash
# from another terminal
pkill -f "mcp serve"
sleep 1

mcp serve --http 127.0.0.1:7331
```

On stderr you **must not** see `[telemetry] OpenTelemetry initialized`.
Boot should look exactly like 0.5.2:

```
INFO database opened idle_timeout=120s
INFO HTTP server listening addr=127.0.0.1:7331
```

`tools/list` keeps responding:

```bash
curl -s -X POST http://127.0.0.1:7331/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  -o /dev/null -w "no-otel HTTP %{http_code}\n"
# no-otel HTTP 200
```

This is the **fail-safe**: if OTel ever goes wrong in production, just
**unset** `OTEL_EXPORTER_OTLP_ENDPOINT` in the deploy and the system
reverts to the previous behavior. No rebuild, no image rollback.

---

## 8. Cleanup

```bash
pkill -f "mcp serve"
docker stop mcp-otelcol mcp-jaeger 2>/dev/null
rm -f /tmp/otel-debug.yaml
```

---

## Next steps

- In production, swap the endpoint for Honeycomb / Tempo / Datadog —
  examples in the [observability reference guide](../guides/observability.md).
- If a backend MCP rejects `traceparent` (rare, it's a W3C standard
  header), enable the escape hatch without touching anything else:
  `MCP_OTEL_INJECT_TRACEPARENT=0`.
- Sampling lives at the exporter side — `mcp serve` always creates the
  span; Honeycomb / Tempo / your collector decides what to keep.
  Configure it there, not here.

## Troubleshooting

**Nothing shows up in Jaeger or in the collector logs.** Check the very
first line of `mcp serve` stderr — if `[telemetry] OpenTelemetry
initialized` is missing, the env var wasn't read. The line goes
**straight to stderr**, before the logging subscriber wires up, and
**does not** respect `MCP_LOG_LEVEL`.

**It said "OpenTelemetry initialized" but nothing reaches the
collector.** Endpoint is probably wrong. `mcp` accepts the **base URL**
(e.g. `http://host:4318`), not the full path (`/v1/traces`) — but it
also tolerates a pre-suffixed value. If you swapped receivers and didn't
clean up the old env var, you might still be sending elsewhere.

**Span without `mcp.server`/`mcp.tool`.** Normal for `tools/list`,
`auth/failure`, unknown methods, or requests with malformed payloads —
those don't resolve to a specific backend. On a resolved `tools/call`
they always show up.

**`tonic` connection refused on an HTTPS endpoint.** Honeycomb (and a
few other vendors) **only accept HTTP/protobuf** on the public ingest.
Set `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` and use `https://` in
the endpoint.

**Metrics don't show up even after 60s.** PeriodicReader is "best
effort": if the process dies before the first flush, the export is
gone. The `TelemetryGuard` in `main`'s `Drop` performs a graceful
shutdown (which forces a flush). In production this is covered by a
normal SIGTERM — but a `kill -9` may drop the last batch.
