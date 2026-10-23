use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::ui::data;
use crate::ui::MapExt;
use crate::ui::{render, Flash, UiResult, UiState};

pub async fn index(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;
    let instances = data::instances_view();
    let total = state
        .audit
        .query_filtered(&crate::audit::AuditFilter {
            limit: usize::MAX,
            ..Default::default()
        })
        .map(|e| e.len())
        .unwrap_or(0);

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "settings",
        "Settings",
        cfg.servers.len(),
        &label,
        &Flash::from_query(&query),
    );
    ctx.put("instances", json!(instances));
    ctx.put(
        "audit",
        json!({
            "enabled": cfg.audit.enabled,
            "arguments": if cfg.audit.log_arguments { "recorded" } else { "redacted" },
            "entries": total,
        }),
    );
    ctx.put(
        "audit_output",
        json!(format!("{:?}", cfg.audit.output).to_lowercase()),
    );
    ctx.put(
        "telemetry",
        json!(if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
        {
            "OTLP enabled"
        } else {
            "OTLP disabled (no OTEL_EXPORTER_OTLP_ENDPOINT)"
        }),
    );
    ctx.put(
        "db_path",
        json!(crate::config::db_data_path().unwrap_or_default()),
    );
    ctx.put(
        "auth_path",
        json!(crate::config::config_dir()
            .map(|d| d.join("auth.json").display().to_string())
            .unwrap_or_default()),
    );
    ctx.put(
        "instances_dir",
        json!(crate::instances::instances_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_default()),
    );
    ctx.put(
        "token_prefix",
        json!(state.token.chars().take(6).collect::<String>()),
    );

    Ok(Html(render::page("settings.html", ctx)?))
}

pub async fn reload(
    State(state): State<Arc<UiState>>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    data::csrf_ok(&state, &form)?;
    if state.read_only {
        return Err(crate::ui::UiError::BadRequest("read-only mode".to_string()));
    }
    let pid = form.get("pid").and_then(|p| p.trim().parse::<u32>().ok());
    let (signalled, tried, errors) = super::reload_instances(pid);

    data::audit_ui(
        &state,
        "config/reload",
        None,
        None,
        signalled == tried && errors.is_empty(),
        0,
        (!errors.is_empty()).then(|| errors.join("; ")),
    );

    let message = if tried == 0 {
        "no running mcp serve instance to signal".to_string()
    } else if errors.is_empty() {
        format!("signalled {signalled} of {tried} instance(s) — SIGHUP delivered, not acknowledged")
    } else {
        format!(
            "signalled {signalled} of {tried} instance(s); errors: {}",
            errors.join("; ")
        )
    };

    let target = form
        .get("return")
        .map(String::as_str)
        .unwrap_or("/settings")
        .to_string();
    let target = if target.starts_with('/') && !target.starts_with("//") {
        target
    } else {
        "/settings".to_string()
    };
    let key = if errors.is_empty() { "ok" } else { "err" };
    Ok(Redirect::to(&format!(
        "{target}?{key}={}",
        crate::ui::urlencode(&message)
    ))
    .into_response())
}
