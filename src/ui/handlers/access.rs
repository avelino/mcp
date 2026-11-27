use axum::extract::{Query, State};
use axum::response::Html;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::server_auth::AclConfig;
use crate::server_auth::AuthIdentity;
use crate::ui::data;
use crate::ui::MapExt;
use crate::ui::{redirect_with, render, CurrentViewer, Flash, UiError, UiResult, UiState, Viewer};

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
    let last_used = last_used_by_subject(&state);
    let token_rows = token_rows_view(&source, &last_used)?;
    let roles = role_names(&source)?;
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
    ctx.put("token_rows", json!(token_rows));
    ctx.put("role_names", json!(roles));
    ctx.put("admin_roles", json!(cfg.server_auth.admin_roles));
    let mut view = view;
    if let Some(subjects) = view.get_mut("subjects").and_then(|v| v.as_array_mut()) {
        for subject in subjects.iter_mut() {
            let name = subject["name"].as_str().unwrap_or_default().to_string();
            subject["last_used"] = json!(last_used
                .get(&name)
                .cloned()
                .unwrap_or_else(|| "never".into()));
            let roles = subject["roles"].as_array().cloned().unwrap_or_default();
            let csv: Vec<String> = roles
                .iter()
                .filter_map(|r| r.as_str().map(str::to_string))
                .collect();
            subject["roles_csv"] = json!(csv.join(", "));
        }
    }
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
                // Numeric for the template's disabled check, string for display:
                // `r.subjects > 0` must work for RBAC exactly as the legacy rows
                // once made it look like it did.
                "subjects": subject_count,
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

// ---------------------------------------------------------------------------
// Mutations: bearer tokens, subjects, roles
// ---------------------------------------------------------------------------

use axum::extract::Path;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config_source::ConfigSource;
use crate::server_auth::BearerToken;

use super::publish;

pub async fn create_token(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;

    let subject = form.get("subject").map(|s| s.trim()).unwrap_or("");
    if subject.is_empty() {
        return Err(UiError::BadRequest("subject is required".into()));
    }
    let roles = split_list(form.get("roles"));
    let token = crate::auth::oauth_primitives::generate_random_string(48);

    let next = source.set_bearer_token(&token, subject, &roles)?;
    apply_auth(&state, &viewer, &source, &next, "ui/auth/token/add").await?;

    // The secret is shown once, on a page reached by an unguessable id, and
    // never put in a redirect URL.
    let id = state.stash_token(subject, &roles, &token);
    Ok(Redirect::to(&format!("/access/tokens/{id}")).into_response())
}

pub async fn token_created(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(id): Path<String>,
) -> UiResult<Html<String>> {
    require_admin(&viewer)?;
    let pending = state.take_token(&id).ok_or_else(|| {
        UiError::NotFound("this token was already shown, or never existed".into())
    })?;

    let mut ctx = serde_json::Map::new();
    ctx.put("page_title", json!("Token created"));
    ctx.put("subject", json!(pending.subject));
    ctx.put("roles", json!(pending.roles));
    ctx.put("token", json!(pending.token));
    ctx.put("version", json!(env!("CARGO_PKG_VERSION")));
    Ok(Html(render::render("access_token.html", ctx)?))
}

pub async fn revoke_token(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    headers: HeaderMap,
    Path(fingerprint): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;

    let tokens = bearer_tokens(&source)?;
    let (token, subject) = tokens
        .iter()
        .find(|t| t.fingerprint == fingerprint)
        .map(|t| (t.token.clone(), t.subject.clone()))
        .ok_or_else(|| UiError::NotFound("no token with that fingerprint".into()))?;

    // Revoking the credential the browser is using would sign the operator out
    // mid-action; make them do it deliberately from another session.
    if current_request_token(&headers).map(|t| fingerprint_of(&t)) == Some(fingerprint.clone()) {
        return Err(UiError::BadRequest(
            "that is the token this browser is signed in with — revoke it from another session"
                .into(),
        ));
    }

    let next = source.remove_bearer_token(&token)?;
    apply_auth(&state, &viewer, &source, &next, "ui/auth/token/revoke").await?;
    Ok(redirect_with("/access", "ok", &format!("Revoked the token for {subject}")).into_response())
}

pub async fn save_subject(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;
    ensure_rbac(&source)?;

    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() {
        return Err(UiError::BadRequest("subject is required".into()));
    }
    let roles = split_list(form.get("roles"));
    let known = role_names(&source)?;
    if let Some(unknown) = roles.iter().find(|r| !known.contains(*r)) {
        return Err(UiError::BadRequest(format!(
            "\"{unknown}\" is not a role defined in this ACL — create the role first"
        )));
    }

    let next = source.set_subject_roles(name, &roles)?;
    apply_auth(&state, &viewer, &source, &next, "ui/auth/subject/save").await?;
    Ok(redirect_with("/access", "ok", &format!("Saved subject {name}")).into_response())
}

pub async fn delete_subject(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;
    ensure_rbac(&source)?;

    let next = source.remove_subject(&name)?;
    apply_auth(&state, &viewer, &source, &next, "ui/auth/subject/delete").await?;
    Ok(redirect_with("/access", "ok", &format!("Removed subject {name}")).into_response())
}

pub async fn duplicate_role(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;
    ensure_rbac(&source)?;

    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    let from = form.get("from").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() || from.is_empty() {
        return Err(UiError::BadRequest(
            "name and source role are required".into(),
        ));
    }
    if role_names(&source)?.contains(name) {
        return Err(UiError::Conflict(format!("role \"{name}\" already exists")));
    }
    let grants = role_grants(&source, from)?
        .ok_or_else(|| UiError::NotFound(format!("role \"{from}\" not found")))?;

    let next = source.set_role_grants(name, &grants)?;
    apply_auth(&state, &viewer, &source, &next, "ui/auth/role/add").await?;
    Ok(redirect_with("/access", "ok", &format!("Created role {name} from {from}")).into_response())
}

pub async fn delete_role(
    State(state): State<Arc<UiState>>,
    CurrentViewer(viewer): CurrentViewer,
    Path(name): Path<String>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> UiResult<Response> {
    require_admin(&viewer)?;
    data::csrf_ok(&state, &form)?;
    let source = ConfigSource::load()?;
    data::ensure_writable(&state, &source, &viewer)?;
    ensure_rbac(&source)?;

    let (_, cfg) = data::load_source()?;
    ensure_role_removable(&source, &cfg.server_auth.admin_roles, &name)?;

    // Belt and braces: the generic guard below is what actually decides.
    let next = source.remove_role(&name)?;
    apply_auth(&state, &viewer, &source, &next, "ui/auth/role/delete").await?;
    Ok(redirect_with("/access", "ok", &format!("Removed role {name}")).into_response())
}

// --- helpers ---------------------------------------------------------------

/// Newest audit entry per identity, for the "last used" columns.
fn last_used_by_subject(state: &UiState) -> HashMap<String, String> {
    let entries = state
        .audit
        .query_filtered(&crate::audit::AuditFilter {
            limit: 2_000,
            ..Default::default()
        })
        .unwrap_or_default();
    let mut map: HashMap<String, String> = HashMap::new();
    for entry in entries {
        map.entry(entry.identity.clone())
            .or_insert_with(|| data::short_time(&entry.timestamp));
    }
    map
}

fn token_rows_view(
    source: &ConfigSource,
    last_used: &HashMap<String, String>,
) -> UiResult<Vec<Value>> {
    Ok(bearer_tokens(source)?
        .into_iter()
        .map(|t| {
            json!({
                "fingerprint": t.fingerprint,
                "subject": t.subject,
                "roles": t.roles,
                "legacy": t.legacy,
                "last_used": last_used.get(&t.subject).cloned().unwrap_or_else(|| "never".into()),
            })
        })
        .collect())
}

struct TokenRow {
    fingerprint: String,
    token: String,
    subject: String,
    roles: Vec<String>,
    legacy: bool,
}

fn bearer_tokens(source: &ConfigSource) -> UiResult<Vec<TokenRow>> {
    let raw = source.parsed()?;
    let Some(map) = raw
        .pointer("/serverAuth/bearer/tokens")
        .and_then(|v| v.as_object())
    else {
        return Ok(Vec::new());
    };
    let mut rows: Vec<TokenRow> = map
        .iter()
        .map(|(token, entry)| {
            let (subject, roles, legacy) = match entry {
                Value::String(subject) => (subject.clone(), Vec::new(), true),
                obj => (
                    obj.get("subject")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    obj.get("roles")
                        .and_then(|r| r.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                    false,
                ),
            };
            TokenRow {
                fingerprint: fingerprint_of(token),
                token: token.clone(),
                subject,
                roles,
                legacy,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.subject.cmp(&b.subject));
    Ok(rows)
}

fn fingerprint_of(token: &str) -> String {
    crate::config_source::sha256_hex(token)
        .chars()
        .take(12)
        .collect()
}

fn current_request_token(headers: &HeaderMap) -> Option<String> {
    crate::serve::team::cookie_token(headers).or_else(|| {
        headers
            .get(axum::http::header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")
            .map(str::to_string)
    })
}

fn split_list(value: Option<&String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn role_names(source: &ConfigSource) -> UiResult<std::collections::BTreeSet<String>> {
    let raw = source.parsed()?;
    Ok(raw
        .pointer("/serverAuth/acl/roles")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default())
}

fn role_grants(source: &ConfigSource, role: &str) -> UiResult<Option<Value>> {
    let raw = source.parsed()?;
    Ok(raw
        .pointer(&format!(
            "/serverAuth/acl/roles/{}",
            role.replace('/', "~1")
        ))
        .cloned())
}

/// A role can go only when nothing points at it.
///
/// The previous version compared each *subject name* against the role name, so
/// it only ever refused a deletion when a subject happened to be called like
/// the role — which is to say it never refused one.
fn ensure_role_removable(
    source: &ConfigSource,
    admin_roles: &[String],
    name: &str,
) -> UiResult<()> {
    if admin_roles.iter().any(|r| r == name) {
        return Err(UiError::BadRequest(format!(
            "\"{name}\" is in serverAuth.adminRoles — remove it there first"
        )));
    }
    let assigned = subjects_using(source, name)?;
    if !assigned.is_empty() {
        return Err(UiError::BadRequest(format!(
            "role \"{name}\" is still assigned to {} — reassign those subjects first",
            assigned.join(", ")
        )));
    }
    Ok(())
}

fn subjects_using(source: &ConfigSource, role: &str) -> UiResult<Vec<String>> {
    let raw = source.parsed()?;
    let Some(subjects) = raw
        .pointer("/serverAuth/acl/subjects")
        .and_then(|v| v.as_object())
    else {
        return Ok(Vec::new());
    };
    Ok(subjects
        .iter()
        .filter(|(_, v)| {
            v.get("roles")
                .and_then(|r| r.as_array())
                .map(|roles| roles.iter().any(|r| r.as_str() == Some(role)))
                .unwrap_or(false)
        })
        .map(|(k, _)| k.clone())
        .collect())
}

fn ensure_rbac(source: &ConfigSource) -> UiResult<()> {
    let raw = source.parsed()?;
    if raw.pointer("/serverAuth/acl/rules").is_some() {
        return Err(UiError::BadRequest(
            "this ACL uses the legacy rules schema — edit the file to change it".into(),
        ));
    }
    Ok(())
}

/// Refuses a change that would leave nobody able to sign in as admin.
///
/// A role on a *subject* is not a credential: if no token maps to that
/// subject, nobody can present it. So the check walks the bearer tokens, adds
/// the roles the subject map gives each subject, and requires at least one
/// resulting identity to hold an admin role. When identities arrive from
/// somewhere else (`forwarded`, `oauth_as`) they cannot be enumerated here, so
/// the guard steps aside rather than blocking a legitimate change.
fn ensure_admin_survives(cfg: &crate::config::Config) -> UiResult<()> {
    let admin = &cfg.server_auth.admin_roles;
    if admin.is_empty() {
        return Ok(());
    }
    let uses_bearer = cfg.server_auth.providers.iter().any(|p| p == "bearer");
    if !uses_bearer {
        return Ok(());
    }

    let subject_roles = |subject: &str| -> Vec<String> {
        match &cfg.server_auth.acl {
            Some(AclConfig::RoleBased(rbac)) => rbac
                .subjects
                .get(subject)
                .map(|s| s.roles.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    };

    let mut admin_credential = false;
    if let Some(bearer) = &cfg.server_auth.bearer {
        for token in bearer.tokens.values() {
            let (subject, token_roles) = match token {
                BearerToken::Subject(subject) => (subject, &[][..]),
                BearerToken::Extended { subject, roles } => (subject, roles.as_slice()),
            };
            let subject_roles = subject_roles(subject);
            if token_roles
                .iter()
                .chain(subject_roles.iter())
                .any(|role| admin.contains(role))
            {
                admin_credential = true;
                break;
            }
        }
    }

    if admin_credential {
        Ok(())
    } else {
        Err(UiError::BadRequest(
            "this change would leave no admin credential: keep at least one bearer token whose subject or token roles include a role from serverAuth.adminRoles"
                .into(),
        ))
    }
}

/// Validates, checks the lockout guard, writes atomically and reloads.
async fn apply_auth(
    state: &UiState,
    viewer: &Viewer,
    source: &ConfigSource,
    text: &str,
    method: &str,
) -> UiResult<String> {
    let cfg = source
        .validate(text)
        .map_err(|e| UiError::BadRequest(format!("{e:#}")))?;
    ensure_admin_survives(&cfg)?;

    match source.apply(text) {
        Ok(_) => {
            data::audit_ui(
                state,
                viewer,
                data::UiAction {
                    method,
                    tool: None,
                    server: None,
                    ok: true,
                    duration_ms: 0,
                    error: None,
                },
            );
            Ok(publish(state).await)
        }
        Err(e) if crate::config_source::is_conflict(&e) => Err(UiError::Conflict(format!(
            "{e} — reload the page and try again"
        ))),
        Err(e) => Err(UiError::Internal(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(json_text: &str) -> crate::config::Config {
        crate::config::validate_config_text(json_text, std::path::PathBuf::from("<t>"))
            .expect("test config")
    }

    const BASE: &str = r#"{
      "mcpServers": {},
      "serverAuth": {
        "providers": ["bearer"],
        "adminRoles": ["admin"],
        "bearer": { "tokens": {
          "tok-admin": { "subject": "alice", "roles": ["admin"] },
          "tok-dev": { "subject": "bob", "roles": ["dev"] }
        } },
        "acl": {
          "default": "deny",
          "roles": { "admin": [{ "server": "*", "access": "*" }], "dev": [] },
          "subjects": { "alice": { "roles": ["admin"] }, "bob": { "roles": ["dev"] } }
        }
      }
    }"#;

    const RBAC_DOC: &str = r#"{
      "mcpServers": {},
      "serverAuth": {
        "providers": ["bearer"],
        "adminRoles": ["admin"],
        "bearer": { "tokens": {} },
        "acl": {
          "default": "deny",
          "roles": {
            "admin": [{ "server": "*", "access": "*" }],
            "dev": [{ "server": "sentry", "access": "read" }],
            "unused": [{ "server": "jira", "access": "read" }]
          },
          "subjects": {
            "alice": { "roles": ["admin"] },
            "bob": { "roles": ["dev"] }
          }
        }
      }
    }"#;

    fn source(doc: &str) -> ConfigSource {
        ConfigSource::from_text(doc, crate::config_source::Origin::File("/tmp/x".into()))
    }

    #[test]
    fn a_role_in_use_is_not_removable_and_the_error_names_the_subjects() {
        let err = ensure_role_removable(&source(RBAC_DOC), &["admin".into()], "dev").unwrap_err();
        let message = format!("{err}");
        assert!(
            message.contains("bob"),
            "should name the subject: {message}"
        );
        assert!(!message.contains("dev —"), "{message}");
    }

    #[test]
    fn an_unused_role_can_be_removed() {
        assert!(ensure_role_removable(&source(RBAC_DOC), &["admin".into()], "unused").is_ok());
    }

    #[test]
    fn a_role_in_admin_roles_cannot_be_removed() {
        let err = ensure_role_removable(&source(RBAC_DOC), &["admin".into()], "admin").unwrap_err();
        assert!(format!("{err}").contains("adminRoles"));
    }

    #[test]
    fn role_rows_carry_a_numeric_subject_count() {
        let raw: Value = serde_json::from_str(RBAC_DOC).unwrap();
        let view = acl_view(raw.get("serverAuth").and_then(|s| s.get("acl")));
        let roles = view["roles"].as_array().expect("roles");
        let dev = roles.iter().find(|r| r["name"] == "dev").expect("dev");
        assert_eq!(
            dev["subjects"], 1,
            "the template's disable check reads this"
        );
        assert_eq!(dev["subject_count"], "1 subject");
        let unused = roles
            .iter()
            .find(|r| r["name"] == "unused")
            .expect("unused");
        assert_eq!(unused["subjects"], 0);
    }

    #[test]
    fn removing_the_last_admin_token_is_refused() {
        let without_admin_token = BASE.replace(
            r#""tok-admin": { "subject": "alice", "roles": ["admin"] },"#,
            "",
        );
        let err = ensure_admin_survives(&cfg(&without_admin_token)).unwrap_err();
        assert!(format!("{err}").contains("no admin credential"), "{err}");
    }

    #[test]
    fn a_dev_token_plus_admin_subject_is_not_enough() {
        // The subject map alone proves nothing: nobody can authenticate as it.
        let only_dev_token = BASE.replace(
            r#""tok-admin": { "subject": "alice", "roles": ["admin"] },"#,
            "",
        );
        assert!(ensure_admin_survives(&cfg(&only_dev_token)).is_err());
    }

    #[test]
    fn an_admin_role_on_the_subject_counts_when_a_token_points_at_it() {
        let legacy_shaped = BASE.replace(
            r#""tok-admin": { "subject": "alice", "roles": ["admin"] }"#,
            r#""tok-admin": "alice""#,
        );
        // Legacy token + subject role admin => still an admin credential.
        assert!(ensure_admin_survives(&cfg(&legacy_shaped)).is_ok());
    }

    #[test]
    fn external_providers_are_not_second_guessed() {
        let forwarded = BASE
            .replace(
                r#""providers": ["bearer"]"#,
                r#""providers": ["forwarded"]"#,
            )
            .replace(
                r#""tok-admin": { "subject": "alice", "roles": ["admin"] },"#,
                "",
            );
        assert!(ensure_admin_survives(&cfg(&forwarded)).is_ok());
    }
}
