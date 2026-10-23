use axum::extract::{Query, State};
use axum::response::Html;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::ui::data;
use crate::ui::render;
use crate::ui::MapExt;
use crate::ui::{Flash, UiResult, UiState};

pub async fn index(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;
    let snapshot = data::audit_snapshot(&state, 24, 5_000);
    let servers = data::server_rows(&cfg, &state, &snapshot.per_server);
    let instances = data::instances_view();

    let mut http = 0;
    let mut stdio = 0;
    let mut cli = 0;
    for config in cfg.servers.values() {
        match data::kind_of(config) {
            "http" => http += 1,
            "cli" => cli += 1,
            _ => stdio += 1,
        }
    }
    let tools: i64 = servers.iter().filter_map(|s| s["tools"].as_i64()).sum();
    let read: i64 = servers.iter().filter_map(|s| s["read"].as_i64()).sum();
    let write: i64 = servers.iter().filter_map(|s| s["write"].as_i64()).sum();

    let auth_summary = if cfg.server_auth.providers.is_empty() {
        "none (anonymous)".to_string()
    } else {
        cfg.server_auth.providers.join(" + ")
    };
    let audit_summary = if cfg.audit.enabled {
        "on".to_string()
    } else {
        "off".to_string()
    };

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "overview",
        "Overview",
        cfg.servers.len(),
        &label,
        &Flash::from_query(&query),
    );
    ctx.put(
        "stats",
        json!({
            "servers": cfg.servers.len(),
            "http": http,
            "stdio": stdio,
            "cli": cli,
            "tools": tools,
            "read": read,
            "write": write,
            "calls": snapshot.calls,
            "errors": snapshot.errors,
            "denied": snapshot.denied,
        }),
    );
    ctx.put("servers", json!(servers));
    ctx.put("instances", json!(instances));
    ctx.put("denials", json!(snapshot.denials));
    ctx.put(
        "config_hash",
        json!(source.hash().chars().take(12).collect::<String>()),
    );
    ctx.put("auth_summary", json!(auth_summary));
    ctx.put("audit_summary", json!(audit_summary));

    Ok(Html(render::page("overview.html", ctx)?))
}
