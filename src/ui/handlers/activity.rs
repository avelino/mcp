use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::audit::AuditFilter;
use crate::ui::data;
use crate::ui::MapExt;
use crate::ui::{render, Flash, UiResult, UiState};

pub async fn index(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;
    let filter = filter_from(&query);
    let entries = state.audit.query_filtered(&filter).unwrap_or_default();

    let mut server_names: Vec<String> = cfg.servers.keys().cloned().collect();
    server_names.sort();
    let mut identities: Vec<String> = entries
        .iter()
        .map(|e| e.identity.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    identities.sort();

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "activity",
        "Activity",
        cfg.servers.len(),
        &label,
        &Flash::from_query(&query),
    );
    ctx.put("rows", json!(rows(&entries)));
    ctx.put(
        "filters",
        json!({
            "server": query.get("server").cloned().unwrap_or_default(),
            "identity": query.get("identity").cloned().unwrap_or_default(),
            "since": query.get("since").cloned().unwrap_or_else(|| "24h".to_string()),
        }),
    );
    ctx.put("errors", json!(query.contains_key("errors")));
    ctx.put("server_names", json!(server_names));
    ctx.put("identities", json!(identities));
    ctx.put("since_options", json!(["15m", "1h", "24h", "7d", "30d"]));
    ctx.put("query_string", json!(query_string(&query)));
    ctx.put("db_path", json!(db_path()));
    ctx.put("entries", json!(entries.len()));

    Ok(Html(render::page("activity.html", ctx)?))
}

pub async fn rows_only(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let filter = filter_from(&query);
    let entries = state.audit.query_filtered(&filter).unwrap_or_default();
    let mut ctx = serde_json::Map::new();
    ctx.put("rows", json!(rows(&entries)));
    ctx.put("db_path", json!(db_path()));
    Ok(Html(render::render("partials/activity_rows.html", ctx)?))
}

pub async fn export(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Response> {
    let filter = filter_from(&query);
    let entries = state.audit.query_filtered(&filter).unwrap_or_default();
    let body = serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".into());
    Ok((
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"mcp-audit.json\"",
            ),
        ],
        body,
    )
        .into_response())
}

fn filter_from(query: &HashMap<String, String>) -> AuditFilter {
    let mut filter = AuditFilter {
        limit: 200,
        errors_only: query.contains_key("errors"),
        ..Default::default()
    };
    if let Some(server) = non_empty(query.get("server")) {
        filter.server = Some(server);
    }
    if let Some(identity) = non_empty(query.get("identity")) {
        filter.identity = Some(identity);
    }
    let since = query.get("since").map(String::as_str).unwrap_or("24h");
    filter.since = crate::audit::parse_duration(since).ok();
    filter
}

fn non_empty(value: Option<&String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn query_string(query: &HashMap<String, String>) -> String {
    let mut parts = Vec::new();
    for key in ["server", "identity", "since"] {
        if let Some(value) = non_empty(query.get(key)) {
            parts.push(format!("{key}={}", crate::ui::urlencode(&value)));
        }
    }
    if query.contains_key("errors") {
        parts.push("errors=1".to_string());
    }
    parts.join("&")
}

fn rows(entries: &[crate::audit::AuditEntry]) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|e| {
            let denied = e.acl_decision.as_deref() == Some("deny");
            let status = if denied {
                "denied"
            } else if e.success {
                "ok"
            } else {
                "error"
            };
            let acl = match (&e.acl_decision, &e.acl_matched_rule) {
                (Some(decision), Some(rule)) => format!("{decision} · {rule}"),
                (Some(decision), None) => decision.clone(),
                _ => "—".to_string(),
            };
            json!({
                "at": data::short_time(&e.timestamp),
                "identity": e.identity,
                "item": e.tool_name.clone().unwrap_or_else(|| e.method.clone()),
                "source": e.source,
                "acl": acl,
                "denied": denied,
                "status": status,
                "ms": if e.duration_ms == 0 { "—".to_string() } else { format!("{}ms", e.duration_ms) },
                "error": e.error_message.as_deref().map(|m| super::truncate(m, 300)),
            })
        })
        .collect()
}

fn db_path() -> String {
    crate::config::db_data_path().unwrap_or_else(|_| "—".to_string())
}
