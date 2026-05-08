# Quickstart — OpenTelemetry no `mcp serve`

Tutorial copy-paste pra subir traces + metrics em ~3 minutos. Roda local
com Jaeger (UI bonita) e depois mostra como ver métricas com OTel
Collector. No final tem o teste de regressão (default-off).

Pré-requisito: Docker + `mcp` 0.6.0+ (`mcp --version`).

> Por que rodar isso? Antes de plugar `mcp serve` num Honeycomb /
> Datadog / Tempo de produção, você quer **provar local** que o trace
> tá fluindo, que o `traceparent` propaga, e que sem env var nada
> muda. Esse passo a passo prova as três coisas.

---

## 1. Sobe Jaeger

Jaeger v2 já fala OTLP nativo (gRPC em `:4317`, HTTP em `:4318`) e tem
UI em `:16686`. Um container só:

```bash
docker run -d --rm --name mcp-jaeger \
  -p 16686:16686 -p 4317:4317 -p 4318:4318 \
  jaegertracing/jaeger:latest
```

Espera ficar de pé:

```bash
until curl -fsS http://127.0.0.1:16686/api/services >/dev/null; do sleep 1; done
echo READY
```

UI: <http://localhost:16686>.

---

## 2. Sobe `mcp serve` com OTel ligado

Aponta pra Jaeger HTTP (porta 4318). `OTEL_EXPORTER_OTLP_ENDPOINT` é o
**único** ativador — qualquer outro env var abaixo é opcional:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_SERVICE_NAME=mcp-local \
mcp serve --http 127.0.0.1:7331
```

No stderr, **a primeira linha** tem que ser:

```
[telemetry] OpenTelemetry initialized — endpoint=http://127.0.0.1:4318 protocol=HttpProto
```

> Sem essa linha = OTel **não** subiu. Confere o env var.

Deixa rodando.

---

## 3. Dispara requests

Em outro terminal, dispara umas chamadas:

```bash
# tools/list — span sem mcp.tool/mcp.server (não resolve em backend)
for i in 1 2 3; do
  curl -s -X POST http://127.0.0.1:7331/mcp \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/list\"}" \
    -o /dev/null -w "tools/list $i: %{http_code}\n"
done

# tools/call — span com mcp.tool e mcp.server resolvidos
# (troca filesystem__list_allowed_directories por algum tool seu)
curl -s -X POST http://127.0.0.1:7331/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":99,"method":"tools/call",
       "params":{"name":"filesystem__list_allowed_directories","arguments":{}}}' \
  -o /dev/null -w "tools/call: %{http_code}\n"
```

Aguarda o batch flushar (default ~5s):

```bash
sleep 8
```

---

## 4. Vê os spans no Jaeger

Abre <http://localhost:16686>:

1. **Service:** escolhe `mcp-local`
2. **Operation:** `mcp.request`
3. Click **Find Traces**

Aparecem N traces, cada um com 1 span `mcp.request`. Click em qualquer
um — em **Tags** você vê:

```
otel.kind       = server
mcp.method      = tools/list (ou tools/call)
mcp.transport   = serve:http
mcp.identity    = anonymous
mcp.status      = ok
mcp.server      = filesystem      ← só nos tools/call resolvidos
mcp.tool        = list_allowed_directories
```

A duração do span é o tempo total que o `dispatch_request` levou —
inclui ACL, lock do proxy, conexão com backend e o backend call em si.

### Sanity check via API (sem clicar)

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

## 5. Testa parent context (`traceparent` inbound)

Quando o cliente é OTel-aware (Claude.ai, gateway instrumentado, OTel
SDK), ele manda `traceparent` no header. O `mcp serve` deve **continuar
o trace** — span dele vira filho do span do cliente, não cria trace
novo.

Manda um `traceparent` fake e confere stitching:

```bash
TRACEPARENT='00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

curl -s -X POST http://127.0.0.1:7331/mcp \
  -H 'Content-Type: application/json' \
  -H "traceparent: $TRACEPARENT" \
  -d '{"jsonrpc":"2.0","id":42,"method":"tools/list"}' \
  -o /dev/null -w "HTTP %{http_code}\n"

sleep 5

# Pega o trace pelo traceID que injetamos
curl -s "http://127.0.0.1:16686/api/traces/0af7651916cd43dd8448eb211c80319c" \
  | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]
if not data:
    print("FAIL: parent context não funcionou")
else:
    for s in data[0]["spans"]:
        refs = s.get("references", [])
        parent = refs[0]["spanID"] if refs else "ROOT"
        print(f"  span {s[\"operationName\"]} parent={parent}")
'
```

Saída esperada:

```
  span mcp.request parent=b7ad6b7169203331
```

`parent=b7ad6b7169203331` confirma que o span do `mcp.request` virou
filho do span que mandamos no `traceparent`. Trace stitching ✓.

---

## 6. Vê as métricas

Jaeger v2 só guarda traces. Pra ver counter/histogram/gauge, troca por
um OTel Collector com debug exporter:

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

Continua disparando requests no `mcp serve`. **Importante:** o
PeriodicReader exporta métricas a cada 60s (default OTel SDK), então
**aguarda ~65 segundos** depois do primeiro request.

Depois de 65s:

```bash
docker logs mcp-otelcol 2>&1 | grep -E "Name:|Value:|mcp\." | head -40
```

Saída esperada:

```
     -> Name: mcp.proxy.requests
     -> mcp.method: Str(tools/call)
     -> mcp.server: Str(filesystem)
     -> mcp.tool: Str(filesystem__list_allowed_directories)
Value: 6
     -> Name: mcp.proxy.classifier.cache.hits
     -> mcp.server: Str(filesystem)
Value: 28
     -> Name: mcp.proxy.backends.connected
Value: 6
     -> Name: mcp.proxy.sessions.active
Value: 0
```

> Métricas que a `mcp` emite, em uma frase:
> - `mcp.proxy.requests` (counter) e `mcp.proxy.request.duration` (histogram, ms) — uma por request, com labels `method/server/tool/status/transport/identity`
> - `mcp.proxy.classifier.cache.hits/misses` por server
> - `mcp.proxy.backends.connected` e `mcp.proxy.sessions.active` (gauges) atualizados a cada export

---

## 7. Teste de regressão — sem OTel = comportamento 0.5.2

Esse é o passo que **prova que sua versão atual em produção não
quebra**. Mata o serve atual e religa **sem nenhuma env var OTel**:

```bash
# em outro terminal
pkill -f "mcp serve"
sleep 1

mcp serve --http 127.0.0.1:7331
```

No stderr você **não pode ver** a linha `[telemetry] OpenTelemetry
initialized`. Boot tem que abrir igualzinho à 0.5.2:

```
INFO database opened idle_timeout=120s
INFO HTTP server listening addr=127.0.0.1:7331
```

`tools/list` continua respondendo:

```bash
curl -s -X POST http://127.0.0.1:7331/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  -o /dev/null -w "no-otel HTTP %{http_code}\n"
# no-otel HTTP 200
```

Esse é o **fail-safe**: se o OTel der pau em produção, basta
**unset** do `OTEL_EXPORTER_OTLP_ENDPOINT` no deploy e o sistema
volta exatamente ao comportamento anterior. Sem rebuild, sem
rollback de imagem.

---

## 8. Cleanup

```bash
pkill -f "mcp serve"
docker stop mcp-otelcol mcp-jaeger 2>/dev/null
rm -f /tmp/otel-debug.yaml
```

---

## Próximos passos

- Em produção, troca o endpoint pra Honeycomb / Tempo / Datadog —
  exemplos no [guia conceitual de observability](../guides/observability.md).
- Se um backend MCP rejeitar `traceparent` (raro, é header W3C
  padrão), ative o escape hatch sem mexer no resto:
  `MCP_OTEL_INJECT_TRACEPARENT=0`.
- Sampling fica do lado do exporter — `mcp serve` sempre cria o span;
  Honeycomb/Tempo/seu collector decide o que sample. Configure lá, não
  aqui.

## Troubleshooting

**Não aparece nada no Jaeger nem nos logs do collector.**
Confere a primeira linha do stderr do `mcp serve` — se não tem
`[telemetry] OpenTelemetry initialized`, o env var não foi lido. A
linha sai **direto pra stderr**, antes do logging subscriber, **não**
respeita `MCP_LOG_LEVEL`.

**Saiu "OpenTelemetry initialized" mas nada chega no collector.**
Provavelmente o endpoint está errado. A `mcp` espera o **base URL**
(ex: `http://host:4318`), não o caminho completo (`/v1/traces`). Mas
ela aceita ambos. Se você trocou de receiver e não cleanou env var
antiga, ainda pode estar mandando pro lugar errado.

**Span sem `mcp.server`/`mcp.tool`.**
Isso é normal pra `tools/list`, `auth/failure`, métodos
desconhecidos, ou requests com payload malformado — esses não
resolvem pra um backend específico. Em `tools/call` resolvido eles
sempre aparecem.

**`tonic` connection refused em endpoint HTTPS.**
Honeycomb (e alguns outros vendors) **só aceitam HTTP/protobuf** no
endpoint público. Defina `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`
e use `https://` no endpoint.

**Métricas não aparecem mesmo depois de 60s.**
PeriodicReader é "best-effort": se o processo cair antes do primeiro
flush, o export some. O `TelemetryGuard` no `Drop` de `main` faz
shutdown gracioso (que força flush). Em prod isso é coberto pelo
SIGTERM normal — mas se você der `kill -9` pode perder o último
batch.
