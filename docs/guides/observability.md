# Observability — OpenTelemetry traces & metrics

`mcp serve` (proxy mode) emite **traces** e **métricas** OTLP nativas. Default-off:
sem env var, comportamento é bit-idêntico à 0.5.2 — log estruturado em stderr +
audit local em chrondb.

> **Quer testar agora?** Vai direto pro [quickstart hands-on](../howto/observability-quickstart.md)
> — sobe Jaeger + `mcp serve` em 3 minutos e prova end-to-end (incluindo `traceparent`
> propagation e métricas).
>
> Esta página aqui é a **referência** — o que cada atributo significa, como
> configurar pra cada vendor, e os escape hatches pra quando algo der ruim.

## Escape hatches (lê isso primeiro)

Roda `mcp serve` em produção e tá nervoso de ligar OTel? Dois switches que valem
ouro:

- **Unset `OTEL_EXPORTER_OTLP_ENDPOINT`** → telemetria **inteira** desliga. Comportamento
  idêntico ao 0.5.2. Sem rebuild, sem rollback, é só remover do deploy.
- **`MCP_OTEL_INJECT_TRACEPARENT=0`** → mantém traces e métricas, **só** desliga a
  injeção do header `traceparent` em chamadas outbound. Use se algum backend MCP
  estranho rejeitar header desconhecido (W3C `traceparent` é padrão, mas servidor
  ruim existe).

## Configuração — env vars padrão OTel

Tudo controlado por env var OTel. **Nada** vai pro `servers.json`.

| Variável | Efeito |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | **Único ativador.** Vazio ou ausente = OTel off. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` (default) ou `http/protobuf`. |
| `OTEL_EXPORTER_OTLP_HEADERS` | CSV `k1=v1,k2=v2`. Só HTTP por spec. |
| `OTEL_SERVICE_NAME` | Resource `service.name`. Default `mcp`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Resource attrs extras, CSV. |
| `MCP_OTEL_INJECT_TRACEPARENT` | `0`/`false`/`no` desliga injeção outbound. |

> **Diagnóstico rápido**: a primeira linha do stderr quando OTel inicia é
> `[telemetry] OpenTelemetry initialized — endpoint=... protocol=...`.
> Sai direto pra stderr, **não** respeita `MCP_LOG_LEVEL`. Se essa linha não
> aparece, OTel não subiu — confere o env var.

## Recipes por vendor

### Honeycomb

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=YOUR_API_KEY" \
OTEL_SERVICE_NAME=mcp-prod \
OTEL_RESOURCE_ATTRIBUTES="deployment.environment=production" \
mcp serve --http 0.0.0.0:7331 --insecure
```

Honeycomb público **só aceita HTTP/protobuf** — gRPC não roda. Não esquece o
`x-honeycomb-team` header.

### Grafana Tempo (self-hosted)

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317 \
OTEL_EXPORTER_OTLP_PROTOCOL=grpc \
OTEL_SERVICE_NAME=mcp \
mcp serve --http 0.0.0.0:7331 --insecure
```

`grpc` é o default da spec OTel — pode omitir `OTEL_EXPORTER_OTLP_PROTOCOL` se
quiser.

### Datadog (via Agent)

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://datadog-agent:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_SERVICE_NAME=mcp \
OTEL_RESOURCE_ATTRIBUTES="env=prod,team=platform" \
mcp serve --http 0.0.0.0:7331 --insecure
```

Datadog Agent expõe OTLP receiver na 4317/4318 quando habilitado.

### Local (desenvolvimento)

Pra subir Jaeger + ver tudo end-to-end na sua máquina, segue o
[quickstart hands-on](../howto/observability-quickstart.md).

## Span attributes

Toda request gera um span raiz `mcp.request` com:

| Attribute | Significado |
|---|---|
| `otel.kind` | `server` |
| `mcp.method` | método JSON-RPC (`tools/call`, `tools/list`, `resources/read`, …) |
| `mcp.transport` | `serve:http` ou `serve:stdio` |
| `mcp.identity` | subject autenticado (JWT `sub`, nome do bearer-token, ou `anonymous`) |
| `mcp.server` | alias do backend, **só** depois que routing resolve (tools/call, resources/read, prompts/get) |
| `mcp.tool` | nome do tool no backend |
| `mcp.status` | `ok` ou `error` |

A duração do span = tempo total do `dispatch_request`. Inclui ACL, lock do
proxy, conexão com backend e o backend call em si — útil pra entender onde tá
gastando latência.

`traceparent` inbound (do cliente) é honrado: o span da `mcp` vira filho do
span do cliente, não cria trace novo. Saindo pra backends HTTP, a `mcp` injeta
`traceparent`/`tracestate` automaticamente — backend instrumentado continua o
trace.

## Metrics

| Métrica | Tipo | Unidade | Atributos |
|---|---|---|---|
| `mcp.proxy.requests` | counter | — | `mcp.method`, `mcp.transport`, `mcp.status`, `mcp.identity`, `mcp.server`*, `mcp.tool`* |
| `mcp.proxy.request.duration` | histogram | ms | mesmos da counter |
| `mcp.proxy.classifier.cache.hits` | counter | — | `mcp.server` |
| `mcp.proxy.classifier.cache.misses` | counter | — | `mcp.server` |
| `mcp.proxy.backends.connected` | gauge | — | — |
| `mcp.proxy.sessions.active` | gauge | — | — |

\* `mcp.server` e `mcp.tool` só presentes quando a request resolve pra um
backend (ausentes em `auth/failure`, métodos desconhecidos, payload
malformado).

PeriodicReader exporta a cada 60s (default OTel SDK). Se for testar local, espera
~65s depois do primeiro request pra ver no exporter.

## Cardinalidade — atenção

`mcp.identity` discrimina por subject autenticado. Se subjects são UUIDs por
usuário (JWT `sub` único), você gera muita série. Honeycomb/Tempo/Datadog
aguentam, mas é trade-off consciente — se só interessa breakdown por role,
remove o label upstream (config do collector).

## O que NÃO faz

- **Sem Sentry / panic tracking.** Erros viram `mcp.status=error` no span.
  Sentry vai em issue separada.
- **Sem profiling contínuo.**
- **Sem OTLP logs signal.** Audit fica em chrondb (`mcp logs`); log
  estruturado continua em stderr controlado por `MCP_LOG_LEVEL` /
  `MCP_LOG_FORMAT`.

## Troubleshooting

Se algo deu ruim, [o quickstart](../howto/observability-quickstart.md#troubleshooting)
tem checklist mais completo. Resumo:

- **Sem `[telemetry] OpenTelemetry initialized` no stderr** = env var não foi
  lido. Confere `OTEL_EXPORTER_OTLP_ENDPOINT`.
- **Inicializou mas nada chega** = endpoint errado, firewall, ou vendor que só
  aceita HTTP (`OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`).
- **`traceparent` não chega no backend** = telemetria não inicializou OU
  `MCP_OTEL_INJECT_TRACEPARENT=0` está setado.
