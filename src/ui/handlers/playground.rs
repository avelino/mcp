use axum::extract::{Query, State};
use axum::response::Html;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::ui::data;
use crate::ui::MapExt;
use crate::ui::{render, Flash, UiError, UiResult, UiState};

pub async fn index(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;

    let mut servers: Vec<Value> = Vec::new();
    let mut names: Vec<&String> = cfg.servers.keys().collect();
    names.sort();
    for name in names {
        let config = &cfg.servers[name];
        let Some(cached) = state.cache.load_backend(name) else {
            continue;
        };
        let (rows, _, _, _) = data::tool_rows(&cached.tools, config.tool_acl());
        let tools: Vec<Value> = rows
            .into_iter()
            .map(|row| json!({ "name": row["name"], "kind": row["kind"] }))
            .collect();
        if !tools.is_empty() {
            servers.push(json!({ "name": name, "tools": tools }));
        }
    }

    let want_server = query.get("server").cloned().unwrap_or_default();
    let want_tool = query.get("tool").cloned().unwrap_or_default();

    let mut selected: Option<Value> = None;
    let mut fields: Vec<Value> = Vec::new();
    let mut rpc = String::new();
    let mut selected_tool: Option<crate::protocol::Tool> = None;

    if !want_server.is_empty() && !want_tool.is_empty() {
        if let Some(cached) = state.cache.load_backend(&want_server) {
            if let Some(tool) = cached.tools.iter().find(|t| t.name == want_tool) {
                let class = crate::classifier::classify(
                    tool,
                    cfg.servers.get(&want_server).and_then(|c| c.tool_acl()),
                );
                fields = data::schema_fields(tool.input_schema.as_ref());
                selected = Some(json!({
                    "key": format!("{want_server}__{want_tool}"),
                    "server": want_server,
                    "tool": want_tool,
                    "kind": class.kind.as_str(),
                    "description": tool.description.clone().unwrap_or_default(),
                }));
                rpc = serde_json::to_string_pretty(&json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": format!("{want_server}__{want_tool}"),
                        "arguments": {},
                    }
                }))
                .unwrap_or_default();
                selected_tool = Some(tool.clone());
            }
        }
    }

    let recent = state
        .audit
        .query_filtered(&crate::audit::AuditFilter {
            limit: 5,
            method: Some("tools/call".to_string()),
            ..Default::default()
        })
        .unwrap_or_default();
    let runs: Vec<Value> = recent
        .iter()
        .map(|e| {
            json!({
                "at": data::short_time(&e.timestamp),
                "ms": format!("{}ms", e.duration_ms),
                "ok": e.success,
                "status": if e.success { "ok" } else { "error" },
            })
        })
        .collect();

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "playground",
        "Playground",
        cfg.servers.len(),
        &label,
        &Flash::from_query(&query),
    );
    ctx.put("servers", json!(servers));
    ctx.put("selected", selected.unwrap_or(Value::Null));
    ctx.put("fields", json!(fields));
    ctx.put("args_json", json!(""));
    ctx.put("rpc_preview", json!(rpc));
    ctx.put("runs", json!(runs));
    let _ = selected_tool;

    Ok(Html(render::page("playground.html", ctx)?))
}

pub async fn call(
    State(state): State<Arc<UiState>>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    data::csrf_ok(&state, &form)?;
    let (_source, cfg) = data::load_source()?;

    let server_name = form.get("server").cloned().unwrap_or_default();
    let tool_name = form.get("tool").cloned().unwrap_or_default();
    let config = cfg
        .servers
        .get(&server_name)
        .ok_or_else(|| UiError::NotFound(format!("server \"{server_name}\" not found")))?;

    let tool = state
        .cache
        .load_backend(&server_name)
        .and_then(|c| c.tools.into_iter().find(|t| t.name == tool_name))
        .ok_or_else(|| {
            UiError::NotFound(format!(
                "tool \"{tool_name}\" is not in the cache — open the server and run discovery"
            ))
        })?;

    let fields = data::schema_fields(tool.input_schema.as_ref());
    let raw_override = form.get("raw_args").cloned().unwrap_or_default();
    let arguments =
        data::form_arguments(&fields, &form, &raw_override).map_err(UiError::BadRequest)?;

    let started = std::time::Instant::now();
    let result = async {
        let client = super::connect(config).await?;
        let outcome = client.call_tool(&tool_name, arguments.clone()).await?;
        client.shutdown().await?;
        Ok::<_, anyhow::Error>(outcome)
    }
    .await;
    let elapsed = started.elapsed().as_millis() as u64;

    let mut ctx = Map::new();
    ctx.put("ms", json!(elapsed));
    ctx.put("key", json!(format!("{server_name}__{tool_name}")));
    ctx.put(
        "arguments",
        json!(serde_json::to_string_pretty(&arguments).unwrap_or_default()),
    );

    match result {
        Ok(outcome) => {
            let value = serde_json::to_value(&outcome).unwrap_or(Value::Null);
            let is_error = value["isError"].as_bool().unwrap_or(false);
            let items = value["content"].as_array().cloned().unwrap_or_default();
            let single_text = items.len() == 1 && items[0]["type"] == "text";
            let pretty = serde_json::to_string_pretty(&value).unwrap_or_default();

            data::audit_ui(
                &state,
                "tools/call",
                Some(&tool_name),
                Some(&server_name),
                !is_error,
                elapsed,
                None,
            );

            ctx.put("ok", json!(!is_error));
            ctx.put("status", json!(if is_error { "tool error" } else { "ok" }));
            ctx.put(
                "size",
                json!(format!("{:.1} KB", pretty.len() as f64 / 1024.0)),
            );
            ctx.put("single_text", json!(single_text));
            ctx.put(
                "text",
                json!(items.first().and_then(|i| i["text"].as_str()).unwrap_or("")),
            );
            ctx.put("json", json!(pretty));
        }
        Err(e) => {
            let message = format!("{e:#}");
            data::audit_ui(
                &state,
                "tools/call",
                Some(&tool_name),
                Some(&server_name),
                false,
                elapsed,
                Some(message.clone()),
            );
            ctx.put("ok", json!(false));
            ctx.put("status", json!("error"));
            ctx.put("error", json!(message));
            ctx.put("json", json!("{}"));
            ctx.put("single_text", json!(false));
            ctx.put("text", json!(""));
            ctx.put("size", json!("0 KB"));
        }
    }

    Ok(Html(render::page("partials/result.html", ctx)?))
}
