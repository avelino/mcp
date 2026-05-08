use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::telemetry::TelemetryGuard;

/// Initialize the tracing subscriber for structured logging.
///
/// Reads `MCP_LOG_LEVEL` (default: "info") and `MCP_LOG_FORMAT` (default: "text").
/// When `MCP_LOG_FORMAT=json`, emits newline-delimited JSON to stderr — ideal for
/// container log drivers and centralized logging pipelines.
///
/// When an active [`TelemetryGuard`] is supplied, the OpenTelemetry tracing
/// layer is attached so spans created via `tracing` automatically flow to
/// the OTLP exporter. With `None`, behavior is byte-identical to the
/// pre-OTel logging path.
pub fn init(otel: Option<&TelemetryGuard>) {
    let level = std::env::var("MCP_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let format = std::env::var("MCP_LOG_FORMAT").unwrap_or_else(|_| "text".into());

    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Box the fmt layer so the json/text branches share a single concrete
    // type. `with_filter` keeps the EnvFilter scoped to the stderr layer so
    // OTel spans aren't suppressed when MCP_LOG_LEVEL is restrictive.
    let fmt_layer: Box<dyn Layer<Registry> + Send + Sync> = match format.as_str() {
        "json" => Box::new(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_filter(filter),
        ),
        _ => Box::new(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_filter(filter),
        ),
    };

    // OTel layer is an `Option` — `tracing_subscriber` provides a blanket
    // `Layer` impl for `Option<L>` so it's a no-op when telemetry is off.
    // Building the layer in-place lets `S` get inferred to whatever the
    // composed subscriber is.
    let otel_layer = otel
        .and_then(|g| g.tracer())
        .map(tracing_opentelemetry::OpenTelemetryLayer::new);

    Registry::default().with(fmt_layer).with(otel_layer).init();
}
