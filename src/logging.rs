use tracing_subscriber::EnvFilter;

/// Initialize the tracing subscriber for structured logging.
///
/// Reads `MCP_LOG_LEVEL` (default: "info") and `MCP_LOG_FORMAT` (default: "text").
/// When `MCP_LOG_FORMAT=json`, emits newline-delimited JSON to stderr — ideal for
/// container log drivers and centralized logging pipelines.
pub fn init() {
    let level = std::env::var("MCP_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let format = std::env::var("MCP_LOG_FORMAT").unwrap_or_else(|_| "text".into());

    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    match format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
    }
}
