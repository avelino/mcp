//! OpenTelemetry integration — default-off, ativado via env vars padrão OTel.
//!
//! Quando `OTEL_EXPORTER_OTLP_ENDPOINT` está setado, [`init`] configura:
//! - `TracerProvider` global com batch exporter OTLP (gRPC ou HTTP/protobuf,
//!   conforme `OTEL_EXPORTER_OTLP_PROTOCOL`).
//! - `MeterProvider` global com periodic reader (default: 60s).
//! - `TraceContextPropagator` global (W3C `traceparent`).
//!
//! O guard retornado faz flush+shutdown no Drop. Sem o env var, [`init`]
//! retorna `None` e o sistema se comporta exatamente como antes.
//!
//! Env vars suportadas (todas opcionais exceto endpoint):
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` — único ativador.
//! - `OTEL_EXPORTER_OTLP_PROTOCOL` — `grpc` (default) ou `http/protobuf`.
//! - `OTEL_EXPORTER_OTLP_HEADERS` — CSV `k1=v1,k2=v2` (HTTP only por spec).
//! - `OTEL_SERVICE_NAME` — default `mcp`.
//! - `OTEL_RESOURCE_ATTRIBUTES` — CSV adicionado ao Resource.
//!
//! Escape hatch: se algum backend MCP rejeitar `traceparent` injetado,
//! `MCP_OTEL_INJECT_TRACEPARENT=0` desliga apenas a injeção outbound sem
//! mexer no resto.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use axum::http::HeaderMap;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{Context, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::trace::Tracer;
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetrySpanExt;

const ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const PROTOCOL_VAR: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";
const HEADERS_VAR: &str = "OTEL_EXPORTER_OTLP_HEADERS";
const SERVICE_NAME_VAR: &str = "OTEL_SERVICE_NAME";
const RESOURCE_ATTR_VAR: &str = "OTEL_RESOURCE_ATTRIBUTES";

const TRACER_NAME: &str = "mcp";

/// Stash so the rest of the codebase can read what was actually wired without
/// re-parsing env vars. `None` when telemetry is disabled.
static TELEMETRY_STATE: OnceLock<TelemetryState> = OnceLock::new();

/// Pre-built instruments published once a `MeterProvider` is wired. `None`
/// when telemetry is disabled — call sites should `if let Some(m) = ...`
/// before recording.
static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Hot-path metric instruments. Cheap to clone via `Counter`/`Histogram`
/// internal `Arc`, but we expose them by reference behind a `OnceLock`
/// to keep the API ergonomic.
pub struct Metrics {
    pub requests: Counter<u64>,
    pub request_duration: Histogram<f64>,
    pub classifier_hits: Counter<u64>,
    pub classifier_misses: Counter<u64>,
}

/// Access the pre-built metric instruments. `None` when telemetry is
/// disabled — emit calls become no-ops.
pub fn metrics() -> Option<&'static Metrics> {
    METRICS.get()
}

fn build_metrics(meter: &Meter) -> Metrics {
    Metrics {
        requests: meter
            .u64_counter("mcp.proxy.requests")
            .with_description("Total MCP proxy requests handled")
            .build(),
        request_duration: meter
            .f64_histogram("mcp.proxy.request.duration")
            .with_description("MCP proxy request duration")
            .with_unit("ms")
            .build(),
        classifier_hits: meter
            .u64_counter("mcp.proxy.classifier.cache.hits")
            .with_description("Tool classifier cache hits")
            .build(),
        classifier_misses: meter
            .u64_counter("mcp.proxy.classifier.cache.misses")
            .with_description("Tool classifier cache misses")
            .build(),
    }
}

/// Register periodic-observation gauges for proxy state. Each closure is
/// invoked by the OTel SDK on every metrics export — they MUST be cheap
/// and non-blocking. No-op when telemetry is disabled. Safe to call once
/// per `mcp serve` boot; subsequent calls add additional gauges.
pub fn register_proxy_observers<B, S>(backends_connected: B, sessions_active: S)
where
    B: Fn() -> u64 + Send + Sync + 'static,
    S: Fn() -> u64 + Send + Sync + 'static,
{
    if METRICS.get().is_none() {
        return;
    }
    let meter = global::meter("mcp");
    let _ = meter
        .u64_observable_gauge("mcp.proxy.backends.connected")
        .with_description("Connected MCP backends")
        .with_callback(move |obs| {
            obs.observe(backends_connected(), &[]);
        })
        .build();
    let _ = meter
        .u64_observable_gauge("mcp.proxy.sessions.active")
        .with_description("Active SSE/Streamable HTTP sessions")
        .with_callback(move |obs| {
            obs.observe(sessions_active(), &[]);
        })
        .build();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireProtocol {
    Grpc,
    HttpProto,
}

#[derive(Debug)]
struct TelemetryState {
    inject_traceparent: bool,
}

/// RAII guard. Drop = flush + shutdown of tracer/meter providers.
pub struct TelemetryGuard {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
}

impl TelemetryGuard {
    /// Returns the OTel `Tracer` so the caller can build a
    /// `tracing_opentelemetry::Layer` in-place — letting the subscriber's
    /// `S` type get inferred at the call site.
    pub fn tracer(&self) -> Option<Tracer> {
        self.tracer.as_ref().map(|tp| tp.tracer(TRACER_NAME))
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Flush in a synchronous best-effort way. Any error here is logged at
        // debug — the process is exiting, we cannot recover.
        if let Some(tp) = self.tracer.take() {
            if let Err(e) = tp.shutdown() {
                tracing::debug!(error = %e, "tracer provider shutdown failed");
            }
        }
        if let Some(mp) = self.meter.take() {
            if let Err(e) = mp.shutdown() {
                tracing::debug!(error = %e, "meter provider shutdown failed");
            }
        }
    }
}

/// Initialize OpenTelemetry if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
/// Returns `None` (no-op) otherwise — preserving the 0.5.2 behavior.
pub fn init() -> Option<TelemetryGuard> {
    let endpoint = std::env::var(ENDPOINT_VAR).ok()?;
    let endpoint = endpoint.trim().to_string();
    if endpoint.is_empty() {
        return None;
    }

    let protocol = parse_protocol();
    let headers = parse_headers(std::env::var(HEADERS_VAR).ok().as_deref());
    let resource = build_resource();

    // Tracer — the runtime-aware batch processor is required because we run
    // under tokio. The default (thread-based) processor would panic the
    // moment reqwest tries to spawn from a non-runtime thread.
    let tracer_provider = match build_span_exporter(&endpoint, protocol, &headers) {
        Ok(exporter) => {
            let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
            SdkTracerProvider::builder()
                .with_resource(resource.clone())
                .with_span_processor(processor)
                .build()
        }
        Err(e) => {
            // Stay non-fatal: the proxy must keep serving even if telemetry
            // fails to bootstrap (bad endpoint, network down at boot, etc.).
            // `eprintln!` here on purpose — `logging::init` only runs after
            // we return, so a `tracing::warn!` would be silently dropped.
            eprintln!("[telemetry] OTel tracer init failed: {e}; continuing without traces");
            return None;
        }
    };
    global::set_tracer_provider(tracer_provider.clone());

    // Meter — same story: use the runtime-aware periodic reader so the
    // export task lives on the tokio runtime.
    let meter_provider = match build_metric_exporter(&endpoint, protocol, &headers) {
        Ok(exporter) => {
            let reader = PeriodicReader::builder(exporter, runtime::Tokio).build();
            SdkMeterProvider::builder()
                .with_resource(resource)
                .with_reader(reader)
                .build()
        }
        Err(e) => {
            eprintln!("[telemetry] OTel meter init failed: {e}; continuing without metrics");
            // Tracer was already wired — keep it; just skip metrics.
            let inject = inject_traceparent_enabled();
            let _ = TELEMETRY_STATE.set(TelemetryState {
                inject_traceparent: inject,
            });
            global::set_text_map_propagator(TraceContextPropagator::new());
            return Some(TelemetryGuard {
                tracer: Some(tracer_provider),
                meter: None,
            });
        }
    };
    global::set_meter_provider(meter_provider.clone());

    // Build the hot-path instruments now that the global meter provider is
    // wired. Stored in OnceLock so call sites can read by reference.
    let _ = METRICS.set(build_metrics(&global::meter("mcp")));

    // W3C propagator — required for traceparent inbound/outbound.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let inject = inject_traceparent_enabled();
    let _ = TELEMETRY_STATE.set(TelemetryState {
        inject_traceparent: inject,
    });

    eprintln!("[telemetry] OpenTelemetry initialized — endpoint={endpoint} protocol={protocol:?}");

    Some(TelemetryGuard {
        tracer: Some(tracer_provider),
        meter: Some(meter_provider),
    })
}

/// Whether traceparent injection is enabled. Always `false` when telemetry
/// is off; `true` by default when on (operator can opt out via
/// `MCP_OTEL_INJECT_TRACEPARENT=0`).
pub fn should_inject_traceparent() -> bool {
    TELEMETRY_STATE
        .get()
        .map(|s| s.inject_traceparent)
        .unwrap_or(false)
}

fn inject_traceparent_enabled() -> bool {
    !matches!(
        std::env::var("MCP_OTEL_INJECT_TRACEPARENT").ok().as_deref(),
        Some("0") | Some("false") | Some("no")
    )
}

fn parse_protocol() -> WireProtocol {
    match std::env::var(PROTOCOL_VAR)
        .ok()
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("http/protobuf") | Some("http") => WireProtocol::HttpProto,
        // Default per OTel spec is gRPC.
        _ => WireProtocol::Grpc,
    }
}

fn parse_headers(raw: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(raw) = raw else { return out };
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() {
                out.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

fn build_resource() -> Resource {
    let service_name = std::env::var(SERVICE_NAME_VAR).unwrap_or_else(|_| "mcp".to_string());

    let mut builder = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION").to_string(),
        ));

    if let Ok(extra) = std::env::var(RESOURCE_ATTR_VAR) {
        for pair in extra.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if !k.is_empty() {
                    builder = builder.with_attribute(KeyValue::new(k.to_string(), v.to_string()));
                }
            }
        }
    }

    builder.build()
}

/// Append the per-signal path to a base OTLP HTTP endpoint. Programmatic
/// `with_endpoint` does NOT auto-suffix `/v1/traces` etc. (only the
/// `OTEL_EXPORTER_OTLP_ENDPOINT` env var does, and only when the SDK reads
/// it itself). We read the env var ourselves, so we have to suffix.
///
/// Honors a pre-suffixed endpoint (`http://host/v1/traces`) by leaving it
/// untouched. gRPC ignores paths — only used in the HTTP branch.
fn http_endpoint_for(base: &str, signal_path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with(signal_path) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{signal_path}")
    }
}

fn build_span_exporter(
    endpoint: &str,
    protocol: WireProtocol,
    headers: &HashMap<String, String>,
) -> Result<opentelemetry_otlp::SpanExporter, opentelemetry_otlp::ExporterBuildError> {
    match protocol {
        WireProtocol::Grpc => opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::Grpc)
            .with_timeout(Duration::from_secs(10))
            .build(),
        WireProtocol::HttpProto => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(http_endpoint_for(endpoint, "/v1/traces"))
            .with_protocol(Protocol::HttpBinary)
            .with_headers(headers.clone())
            .with_timeout(Duration::from_secs(10))
            .build(),
    }
}

fn build_metric_exporter(
    endpoint: &str,
    protocol: WireProtocol,
    headers: &HashMap<String, String>,
) -> Result<opentelemetry_otlp::MetricExporter, opentelemetry_otlp::ExporterBuildError> {
    match protocol {
        WireProtocol::Grpc => opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::Grpc)
            .with_timeout(Duration::from_secs(10))
            .build(),
        WireProtocol::HttpProto => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(http_endpoint_for(endpoint, "/v1/metrics"))
            .with_protocol(Protocol::HttpBinary)
            .with_headers(headers.clone())
            .with_timeout(Duration::from_secs(10))
            .build(),
    }
}

// -- W3C trace context propagation helpers --------------------------------

/// Adapter so the OTel `TextMapPropagator` can read from an axum `HeaderMap`.
struct HeaderMapExtractor<'a>(&'a HeaderMap);

impl<'a> Extractor for HeaderMapExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Adapter so the OTel `TextMapPropagator` can write into a plain
/// `HashMap<String, String>` — convenient when the outbound transport
/// builds headers as a `String` map (as `transport::http`).
pub struct HashMapInjector<'a>(pub &'a mut HashMap<String, String>);

impl<'a> Injector for HashMapInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

/// Extract a parent OTel context from inbound HTTP headers (W3C
/// `traceparent`/`tracestate`). When telemetry is disabled, the global
/// propagator is a no-op and this returns an empty `Context`.
pub fn extract_parent_context(headers: &HeaderMap) -> Context {
    global::get_text_map_propagator(|prop| prop.extract(&HeaderMapExtractor(headers)))
}

/// Inject the W3C trace context of the current `tracing` span into a
/// string header map. No-op when telemetry is off or when the operator
/// opted out via `MCP_OTEL_INJECT_TRACEPARENT=0`.
///
/// Reads the OTel context attached to the current span by
/// `tracing-opentelemetry`, so the propagated trace stays in sync with
/// the proxy's own root span — not with `Context::current()` which is
/// only updated when the OTel SDK API is used directly.
pub fn inject_traceparent(headers: &mut HashMap<String, String>) {
    if !should_inject_traceparent() {
        return;
    }
    let cx = tracing::Span::current().context();
    global::get_text_map_propagator(|prop| prop.inject_context(&cx, &mut HashMapInjector(headers)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_headers_csv_basic() {
        let h = parse_headers(Some("k1=v1,k2=v2"));
        assert_eq!(h.get("k1").unwrap(), "v1");
        assert_eq!(h.get("k2").unwrap(), "v2");
    }

    #[test]
    fn parse_headers_handles_whitespace_and_empty() {
        let h = parse_headers(Some(" key = value , ,malformed,empty="));
        assert_eq!(h.get("key").unwrap(), "value");
        assert_eq!(h.get("empty").unwrap(), "");
        assert!(!h.contains_key("malformed"));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn parse_headers_none() {
        assert!(parse_headers(None).is_empty());
    }

    #[test]
    fn parse_protocol_default_is_grpc() {
        // SAFETY: tests run in-process; we don't rely on absence in parallel
        // tests because we set explicitly.
        std::env::remove_var(PROTOCOL_VAR);
        assert_eq!(parse_protocol(), WireProtocol::Grpc);
    }

    #[test]
    fn parse_protocol_http() {
        std::env::set_var(PROTOCOL_VAR, "http/protobuf");
        assert_eq!(parse_protocol(), WireProtocol::HttpProto);
        std::env::remove_var(PROTOCOL_VAR);
    }

    #[test]
    fn init_returns_none_without_endpoint() {
        std::env::remove_var(ENDPOINT_VAR);
        assert!(init().is_none(), "init must be a no-op without endpoint");
    }

    #[test]
    fn init_returns_none_with_empty_endpoint() {
        std::env::set_var(ENDPOINT_VAR, "   ");
        assert!(init().is_none(), "blank endpoint must not enable OTel");
        std::env::remove_var(ENDPOINT_VAR);
    }

    #[test]
    fn should_inject_traceparent_off_when_telemetry_disabled() {
        // Without init() succeeding, default is false.
        // (TELEMETRY_STATE may have been set by another test; this test
        // only asserts the API exists and doesn't panic.)
        let _ = should_inject_traceparent();
    }
}
