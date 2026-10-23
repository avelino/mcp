use axum::extract::{Query, State};
use axum::response::Html;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::server_auth::AclConfig;
use crate::server_auth::AuthIdentity;
use crate::ui::data;
use crate::ui::MapExt;
use crate::ui::{render, CurrentViewer, Flash, UiError, UiResult, UiState, Viewer};

pub async fn index(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Query(query): Query<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    require_admin(&viewer)?;
    let (source, cfg) = data::load_source()?;
    let auth = &cfg.server_auth;

    let mut names: Vec<String> = cfg.servers.keys().cloned().collect();
    names.sort();

    // The page renders the ACL as written, not as typed: that keeps legacy and
    // role-based configs on one layout and shows `${VAR}` placeholders intact.
    let raw_acl = source
        .parsed()?
        .get("serverAuth")
        .and_then(|s| s.get("acl"))
        .cloned();
    let view = acl_view(raw_acl.as_ref());

    let subject_names: Vec<String> = view
        .get("subjects")
        .and_then(|s| s.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let sample_subject = subject_names.first().cloned().unwrap_or_default();
    let sample_tool = state
        .cached(names.first().map(String::as_str).unwrap_or(""))
        .and_then(|c| c.tools.first().map(|t| t.name.clone()))
        .unwrap_or_default();

    let label = super::source_label(&source);
    let mut ctx = render::base_context(
        &state,
        "access",
        "Access",
        cfg.servers.len(),
        &label,
        &viewer,
        &Flash::from_query(&query),
    );
    ctx.put("has_acl", json!(raw_acl.is_some()));
    ctx.put("acl", view);
    ctx.put("server_names", json!(names));
    ctx.put(
        "tokens",
        json!(auth.bearer.as_ref().map(|b| b.tokens.len()).unwrap_or(0)),
    );
    ctx.put("sample_subject", json!(sample_subject));
    ctx.put("sample_tool", json!(sample_tool));

    Ok(Html(render::page("access.html", ctx)?))
}

pub async fn check(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Html<String>> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let (_source, cfg) = data::load_source()?;

    let subject = form
        .get("subject")
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();
    let server = form
        .get("server")
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();
    let tool = form
        .get("tool")
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();

    // `--subject` semantics: roles come from the ACL's subject map, not from
    // the bearer token that would have authenticated the request.
    let roles: Vec<String> = match &cfg.server_auth.acl {
        Some(AclConfig::RoleBased(rbac)) => rbac
            .subjects
            .get(&subject)
            .map(|s| s.roles.clone())
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let identity = AuthIdentity::new(subject.clone(), roles.clone());

    let classification = state
        .cached(&server)
        .and_then(|c| c.tools.into_iter().find(|t| t.name == tool))
        .map(|t| {
            crate::classifier::classify(&t, cfg.servers.get(&server).and_then(|c| c.tool_acl()))
        });

    let namespaced = format!("{server}__{tool}");
    let ctx = crate::server_auth::ToolContext {
        server_alias: &server,
        tool_name: &tool,
        classification: classification.as_ref(),
    };
    let decision = crate::server_auth::is_tool_allowed(
        &identity,
        &namespaced,
        &cfg.server_auth.acl,
        Some(&ctx),
    );

    let mut out = Map::new();
    out.put("allowed", json!(decision.allowed));
    out.put("subject", json!(subject));
    out.put("roles", json!(roles));
    out.put("key", json!(namespaced));
    out.put("rule", json!(decision.matched_rule.to_string()));
    out.put(
        "classification",
        json!(classification.map(|c| json!({
            "kind": c.kind.as_str(),
            "source": c.source.as_str(),
            "confidence": format!("{:.2}", c.confidence),
        }))),
    );
    out.put("has_acl", json!(cfg.server_auth.acl.is_some()));

    Ok(Html(render::render("partials/verdict.html", out)?))
}

/// Flattens both ACL schemas into one shape the template renders. Legacy rules
/// become a pseudo-role per rule so there is a single layout.
fn acl_view(acl: Option<&Value>) -> Value {
    let Some(acl) = acl else {
        return json!({ "default": "allow", "strict": false, "roles": [], "subjects": [] });
    };
    let default = acl
        .get("default")
        .and_then(|v| v.as_str())
        .unwrap_or("allow");
    let strict = acl
        .get("strictClassification")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if let Some(rules) = acl.get("rules").and_then(|r| r.as_array()) {
        let subjects = acl.get("subjects");
        let roles: Vec<Value> = rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                let policy = rule.get("policy").and_then(|v| v.as_str()).unwrap_or("allow");
                json!({
                    "name": format!("rule[{i}]"),
                    "subjects": rule.get("subjects").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                    "grants": [json!({
                        "server": list_or(rule.get("subjects"), "*"),
                        "access": policy,
                        "tools": list_or(rule.get("tools"), ""),
                        "deny": policy == "deny",
                    })],
                })
            })
            .collect();
        let subjects = subjects
            .and_then(|s| s.as_object())
            .map(|m| m.len())
            .unwrap_or(0);
        return json!({
            "default": default,
            "strict": strict,
            "roles": roles,
            "subjects": subject_rows(None),
            "legacy": true,
            "subject_count": subjects,
        });
    }

    let roles_map = acl.get("roles").and_then(|r| r.as_object());
    let subjects_map = acl.get("subjects").and_then(|s| s.as_object());

    let mut role_rows = Vec::new();
    if let Some(map) = roles_map {
        let mut names: Vec<&String> = map.keys().collect();
        names.sort();
        for name in names {
            let grants: Vec<Value> = map[name]
                .as_array()
                .map(|list| list.iter().map(grant_view).collect())
                .unwrap_or_default();
            let subject_count = subjects_map
                .map(|subjects| {
                    subjects
                        .values()
                        .filter(|s| {
                            s.get("roles")
                                .and_then(|r| r.as_array())
                                .map(|roles| {
                                    roles.iter().any(|r| r.as_str() == Some(name.as_str()))
                                })
                                .unwrap_or(false)
                        })
                        .count()
                })
                .unwrap_or(0);
            role_rows.push(json!({
                "name": name,
                "subject_count": if subject_count == 1 {
                    "1 subject".to_string()
                } else {
                    format!("{subject_count} subjects")
                },
                "grants": grants,
            }));
        }
    }

    json!({
        "default": default,
        "strict": strict,
        "roles": role_rows,
        "subjects": subject_rows(subjects_map),
        "legacy": false,
    })
}

fn grant_view(grant: &Value) -> Value {
    json!({
        "server": list_or(grant.get("server"), "*"),
        "access": grant.get("access").and_then(|v| v.as_str()).unwrap_or("read"),
        "tools": list_or(grant.get("tools"), ""),
        "deny": grant.get("deny").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

fn subject_rows(subjects: Option<&serde_json::Map<String, Value>>) -> Vec<Value> {
    let Some(map) = subjects else {
        return Vec::new();
    };
    let mut names: Vec<&String> = map.keys().collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let subject = &map[name];
            let roles: Vec<String> = subject
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let extra = subject
                .get("extra")
                .and_then(|e| e.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            json!({
                "name": name,
                "roles": roles,
                "extra": match extra {
                    0 => "—".to_string(),
                    1 => "1 extra grant".to_string(),
                    n => format!("{n} extra grants"),
                },
            })
        })
        .collect()
}

fn list_or(value: Option<&Value>, empty: &str) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => {
            let joined: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if joined.is_empty() {
                empty.to_string()
            } else {
                joined.join(", ")
            }
        }
        _ => empty.to_string(),
    }
}

/// The ACL page describes the whole policy, including who is in which role.
/// That is operator data, so it belongs to the same roles that may change it.
fn require_admin(viewer: &Viewer) -> UiResult<()> {
    if viewer.can_write() {
        Ok(())
    } else {
        Err(UiError::Forbidden(
            "the access policy is visible to roles listed in serverAuth.adminRoles".to_string(),
        ))
    }
}
