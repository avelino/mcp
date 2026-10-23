use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config_source::ConfigSource;
use crate::ui::data::{self, EditForm};
use crate::ui::MapExt;
use crate::ui::{redirect_with, render, CurrentViewer, Flash, UiError, UiResult, UiState};

// ---------------------------------------------------------------------------
// List + add
// ---------------------------------------------------------------------------

pub async fn list(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;
    let snapshot = data::audit_snapshot(&state, 24, 5_000, None);
    let rows = data::server_rows(&cfg, &state, &viewer, &snapshot.per_server);

    let search = query
        .get("q")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mut registry_results: Vec<Value> = Vec::new();
    let mut registry_error: Option<String> = None;
    if !search.is_empty() {
        match crate::registry::search_servers(&search).await {
            Ok(found) => {
                for server in found.into_iter().take(8) {
                    registry_results.push(json!({
                        "name": server.name,
                        "description": super::truncate(server.description.as_deref().unwrap_or(""), 110),
                        "exists": cfg.servers.contains_key(&server.name),
                    }));
                }
            }
            Err(e) => registry_error = Some(format!("registry unreachable: {e}")),
        }
    }

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "servers",
        "Servers",
        cfg.servers.len(),
        &label,
        &viewer,
        &Flash::from_query(&query),
    );
    ctx.put("servers", json!(rows));
    ctx.put("query", json!(search));
    ctx.put("registry_results", json!(registry_results));
    ctx.put("registry_error", json!(registry_error));

    Ok(Html(render::page("servers.html", ctx)?))
}

pub async fn add(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;

    let name = form.get("name").map(|s| s.trim()).unwrap_or("").to_string();
    if name.is_empty() {
        return Err(UiError::BadRequest("name is required".into()));
    }
    if crate::config::is_reserved_name(&name) {
        return Err(UiError::BadRequest(format!(
            "\"{name}\" is a reserved command name — pick another"
        )));
    }
    if source.server(&name)?.is_some() {
        return Err(UiError::Conflict(format!(
            "server \"{name}\" already exists"
        )));
    }

    let entry = match form.get("source").map(String::as_str).unwrap_or("url") {
        "stdio" => {
            let command = form.get("command").map(|s| s.trim()).unwrap_or("");
            if command.is_empty() {
                return Err(UiError::BadRequest("command is required".into()));
            }
            let args: Vec<&str> = form
                .get("args")
                .map(|a| a.split_whitespace().collect())
                .unwrap_or_default();
            json!({ "command": command, "args": args })
        }
        "registry" => {
            let found = crate::registry::find_server(&name)
                .await
                .map_err(UiError::Internal)?;
            let found = found.ok_or_else(|| {
                UiError::NotFound(format!(
                    "no registry entry named \"{name}\" in the top results"
                ))
            })?;
            crate::manager::build_config_entry(&found).map_err(UiError::Internal)?
        }
        _ => {
            let url = form.get("url").map(|s| s.trim()).unwrap_or("");
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(UiError::BadRequest(
                    "URL must start with http:// or https://".into(),
                ));
            }
            json!({ "url": url })
        }
    };

    let next = source.set_server(&name, &entry)?;
    source.apply(&next)?;
    data::audit_ui(
        &state,
        &viewer,
        data::UiAction {
            method: "ui/config/add",
            tool: None,
            server: Some(&name),
            ok: true,
            duration_ms: 0,
            error: None,
        },
    );
    let published = super::publish(&state).await;
    Ok(redirect_with(
        &format!("/servers/{}", crate::ui::urlencode(&name)),
        "ok",
        &format!("Added {name}. {published}"),
    )
    .into_response())
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

pub async fn detail(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;
    let config = cfg
        .servers
        .get(&name)
        .ok_or_else(|| UiError::NotFound(format!("server \"{name}\" not found")))?;
    let raw = source
        .server(&name)?
        .ok_or_else(|| UiError::NotFound(format!("server \"{name}\" is not in the file")))?;

    let cached = state.cached(&name);
    let overrides = config.tool_acl();
    let tools = cached
        .as_ref()
        .map(|c| data::visible_tools(&viewer, &cfg, &name, &c.tools))
        .unwrap_or_default();
    let (tool_rows, read, write, ambiguous) = data::tool_rows(&tools, overrides);

    let stale = match (&cached, cfg.config_hashes.get(&name)) {
        (Some(c), Some(hash)) => &c.config_hash != hash,
        _ => false,
    };

    let redacted = data::redact(&raw);
    let pretty = serde_json::to_string_pretty(&redacted).unwrap_or_default();

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "servers",
        &name,
        cfg.servers.len(),
        &label,
        &viewer,
        &Flash::from_query(&query),
    );
    let unavailable = data::unavailable_reason(config);
    ctx.put(
        "server",
        json!({
            "name": name,
            "kind": data::kind_of(config),
            "endpoint": data::endpoint_of(config),
            "idle": data::idle_label(config),
            "stale": stale,
            "has_cache": cached.is_some(),
            "available": unavailable.is_none(),
            "unavailable_reason": unavailable,
        }),
    );
    ctx.put("tools", json!(tool_rows));
    ctx.put("read_count", json!(read));
    ctx.put("write_count", json!(write));
    ctx.put("ambiguous_count", json!(ambiguous));
    ctx.put(
        "cached_at",
        json!(cached
            .as_ref()
            .map(|c| data::short_time(&c.cached_at))
            .unwrap_or_else(|| "never".into())),
    );
    ctx.put("config_json", json!(pretty));

    Ok(Html(render::page("server.html", ctx)?))
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

pub async fn edit_form(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    let (source, cfg) = data::load_source()?;
    if !cfg.servers.contains_key(&name) {
        return Err(UiError::NotFound(format!("server \"{name}\" not found")));
    }
    let raw = source
        .server(&name)?
        .ok_or_else(|| UiError::NotFound(format!("server \"{name}\" is not in the file")))?;
    data::ensure_writable(&state, &source, &viewer)?;

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "servers",
        &format!("Edit {name}"),
        cfg.servers.len(),
        &label,
        &viewer,
        &Flash::from_query(&query),
    );
    ctx.put("server", form_view(&name, &raw));
    ctx.put("hash", json!(source.hash()));
    ctx.put(
        "idle_options",
        json!(["adaptive", "never", "30s", "1m", "3m", "5m", "15m"]),
    );

    Ok(Html(render::page("edit.html", ctx)?))
}

pub async fn plan_edit(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    data::csrf_ok(&state, &form)?;
    let (source, cfg) = data::load_source()?;
    data::ensure_writable(&state, &source, &viewer)?;
    let raw = source
        .server(&name)?
        .ok_or_else(|| UiError::NotFound(format!("server \"{name}\" not found")))?;

    let next = EditForm { form: &form }.apply_to(&raw);
    let outcome = propose(&source, &name, &raw, &next);
    let instances = crate::instances::list_live().map(|v| v.len()).unwrap_or(0);

    let mut ctx = Map::new();
    ctx.put("ok", json!(outcome.valid));
    ctx.put("diff", json!(outcome.diff_html));
    ctx.put("error", json!(outcome.error));
    ctx.put(
        "impact",
        json!({
            "instances": format!("{instances} receive SIGHUP on apply"),
            "cache": format!("{name} cache is invalidated when its hash changes"),
            "restart": false,
            "restart_text": "no",
        }),
    );
    let _ = cfg;
    Ok(Html(render::page("partials/plan.html", ctx)?))
}

pub async fn apply_edit(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    data::csrf_ok(&state, &form)?;
    let (source, _cfg) = data::load_source()?;
    data::ensure_writable(&state, &source, &viewer)?;

    if let Some(expected) = form.get("expected_hash") {
        if expected != &source.hash() {
            return Err(UiError::Conflict(
                "the file changed while this form was open — reopen the editor and re-apply".into(),
            ));
        }
    }

    let raw = source
        .server(&name)?
        .ok_or_else(|| UiError::NotFound(format!("server \"{name}\" not found")))?;
    let next = EditForm { form: &form }.apply_to(&raw);
    let outcome = propose(&source, &name, &raw, &next);
    if !outcome.valid {
        return Err(UiError::BadRequest(
            outcome
                .error
                .unwrap_or_else(|| "the edit is invalid".into()),
        ));
    }

    match source.apply(&outcome.text) {
        Ok(applied) => {
            data::audit_ui(
                &state,
                &viewer,
                data::UiAction {
                    method: "ui/config/update",
                    tool: None,
                    server: Some(&name),
                    ok: true,
                    duration_ms: 0,
                    error: None,
                },
            );
            let published = super::publish(&state).await;
            let mut message = format!("Saved {name}. {published}");
            if let Some(backup) = applied.backup {
                message.push_str(&format!(" · backup {}", backup.display()));
            }
            Ok(redirect_with(
                &format!("/servers/{}", crate::ui::urlencode(&name)),
                "ok",
                &message,
            )
            .into_response())
        }
        Err(e) if crate::config_source::is_conflict(&e) => Err(UiError::Conflict(format!(
            "{e} — reopen the editor and re-apply"
        ))),
        Err(e) => {
            data::audit_ui(
                &state,
                &viewer,
                data::UiAction {
                    method: "ui/config/update",
                    tool: None,
                    server: Some(&name),
                    ok: false,
                    duration_ms: 0,
                    error: Some(format!("{e:#}")),
                },
            );
            Err(UiError::Internal(e))
        }
    }
}

struct Proposal {
    text: String,
    diff_html: String,
    valid: bool,
    error: Option<String>,
}

/// Computes the new document, its diff and whether it validates — without
/// writing anything.
fn propose(source: &ConfigSource, name: &str, raw: &Value, next: &Value) -> Proposal {
    let ops = field_ops(raw, next);
    let text = match source.patch_server(name, &ops) {
        Ok(text) => text,
        Err(e) => {
            return Proposal {
                text: source.text().to_string(),
                diff_html: String::new(),
                valid: false,
                error: Some(format!("{e:#}")),
            };
        }
    };
    let diff = crate::config_source::unified_diff(source.text(), &text, 3);
    let (valid, error) = match source.validate(&text) {
        Ok(_) => (true, None),
        Err(e) => (false, Some(format!("{e:#}"))),
    };
    Proposal {
        text,
        diff_html: diff_html(&diff),
        valid,
        error,
    }
}

/// Field-level edits: only the keys that actually changed are rewritten, so
/// comments around them survive.
fn field_ops(current: &Value, next: &Value) -> Vec<(String, Option<Value>)> {
    let empty = Map::new();
    let cur = current.as_object().unwrap_or(&empty);
    let nxt = next.as_object().unwrap_or(&empty);
    let mut ops = Vec::new();
    for (key, value) in nxt {
        if cur.get(key) != Some(value) {
            ops.push((key.clone(), Some(value.clone())));
        }
    }
    for key in cur.keys() {
        if !nxt.contains_key(key) {
            ops.push((key.clone(), None));
        }
    }
    ops.sort_by(|a, b| a.0.cmp(&b.0));
    ops
}

fn diff_html(diff: &str) -> String {
    diff.lines()
        .map(|line| {
            let class =
                if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
                    "hunk"
                } else if line.starts_with('+') {
                    "add"
                } else if line.starts_with('-') {
                    "del"
                } else {
                    "ctx"
                };
            format!("<span class=\"{class}\">{}</span>", render::escape(line))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Builds the edit form from the **raw** entry, never from the loaded config.
///
/// `load_config` expands `${VAR}` before parsing, so using the typed value here
/// would show "Bearer " instead of "Bearer ${SENTRY_TOKEN}" — and applying the
/// form would write that empty value back, destroying the placeholder. The raw
/// document is the only safe source for anything the user edits.
fn form_view(name: &str, raw: &Value) -> Value {
    let kind = if raw.get("url").is_some() {
        "http"
    } else if raw.get("cli").and_then(Value::as_bool).unwrap_or(false) {
        "cli"
    } else {
        "stdio"
    };

    let url = raw.get("url").and_then(Value::as_str).unwrap_or("");
    let command = raw.get("command").and_then(Value::as_str).unwrap_or("");
    let args = raw
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let headers_text = pairs_text(raw.get("headers"), ": ");
    let env_text = pairs_text(raw.get("env"), "=");

    let idle = raw
        .get("idle_timeout")
        .and_then(Value::as_str)
        .unwrap_or("adaptive");

    let acl = raw.get("tool_acl");
    let read = globs(acl, "read");
    let write = globs(acl, "write");

    json!({
        "name": name,
        "kind": kind,
        "url": url,
        "command": command,
        "args": args,
        "headers_text": headers_text,
        "env_text": env_text,
        "idle": idle,
        "tool_acl_read": read,
        "tool_acl_write": write,
    })
}

fn pairs_text(value: Option<&Value>, separator: &str) -> String {
    let Some(map) = value.and_then(Value::as_object) else {
        return String::new();
    };
    let mut lines: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("{k}{separator}{}", v.as_str().unwrap_or_default()))
        .collect();
    lines.sort();
    lines.join("\n")
}

fn globs(acl: Option<&Value>, key: &str) -> String {
    acl.and_then(|a| a.get(key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Delete + discover
// ---------------------------------------------------------------------------

pub async fn delete(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;
    if source.server(&name)?.is_none() {
        return Err(UiError::NotFound(format!("server \"{name}\" not found")));
    }
    let next = source.remove_server(&name)?;
    source.apply(&next)?;
    data::audit_ui(
        &state,
        &viewer,
        data::UiAction {
            method: "ui/config/remove",
            tool: None,
            server: Some(&name),
            ok: true,
            duration_ms: 0,
            error: None,
        },
    );
    let published = super::publish(&state).await;
    Ok(redirect_with("/servers", "ok", &format!("Removed {name}. {published}")).into_response())
}

pub async fn discover(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    data::csrf_ok(&state, &form)?;
    if !viewer.can_write() {
        return Err(UiError::Forbidden(
            "discovery starts a backend process and needs an admin role".to_string(),
        ));
    }
    let (_source, cfg) = data::load_source()?;
    let config = cfg
        .servers
        .get(&name)
        .ok_or_else(|| UiError::NotFound(format!("server \"{name}\" not found")))?;

    // Fail with the config-view answer before spawning anything: "command does
    // not exist: npx" is actionable, and it is the same reason `mcp --list`
    // already reports.
    if let Some(reason) = data::unavailable_reason(config) {
        return Ok(redirect_with(
            &format!("/servers/{}", crate::ui::urlencode(&name)),
            "err",
            &format!("Cannot start {name} here: {reason}"),
        )
        .into_response());
    }

    let started = std::time::Instant::now();
    let result = async {
        let client = super::connect(config).await?;
        let tools = client.list_tools().await?;
        client.shutdown().await?;
        Ok::<_, anyhow::Error>(tools)
    }
    .await;

    match result {
        Ok(tools) => {
            let hash = cfg.config_hashes.get(&name).cloned().unwrap_or_default();
            state.remember(
                &name,
                crate::cache::BackendToolCache {
                    config_hash: hash,
                    tools: tools.clone(),
                    cached_at: chrono::Local::now().to_rfc3339(),
                },
            );
            data::audit_ui(
                &state,
                &viewer,
                data::UiAction {
                    method: "tools/list",
                    tool: None,
                    server: Some(&name),
                    ok: true,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: None,
                },
            );
            Ok(redirect_with(
                &format!("/servers/{}", crate::ui::urlencode(&name)),
                "ok",
                &format!("Discovered {} tool(s) from {name}", tools.len()),
            )
            .into_response())
        }
        Err(e) => {
            let message = format!("{e:#}");
            data::audit_ui(
                &state,
                &viewer,
                data::UiAction {
                    method: "tools/list",
                    tool: None,
                    server: Some(&name),
                    ok: false,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: Some(message.clone()),
                },
            );
            Ok(redirect_with(
                &format!("/servers/{}", crate::ui::urlencode(&name)),
                "err",
                &format!("Discovery failed: {}", super::truncate(&message, 200)),
            )
            .into_response())
        }
    }
}
