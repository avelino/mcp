//! View models: everything a template needs, computed from the same modules the
//! CLI uses. No business logic lives here — classification, ACL evaluation and
//! config parsing are called, never reimplemented.

use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::audit::{AuditEntry, AuditFilter};
use crate::classifier;
use crate::config::{Config, IdleTimeoutPolicy, ServerConfig, ToolOverrides};
use crate::config_source::ConfigSource;
use crate::protocol::Tool;

use super::viewer::Viewer;
use super::{UiResult, UiState};

/// Snapshot of the audit log used by the overview and activity pages.
#[derive(Default)]
pub struct AuditSnapshot {
    pub calls: usize,
    pub errors: usize,
    pub denied: usize,
    pub per_server: HashMap<String, usize>,
    pub denials: Vec<Value>,
    pub rows: Vec<AuditEntry>,
}

pub fn audit_snapshot(
    state: &UiState,
    since_hours: i64,
    limit: usize,
    identity: Option<&str>,
) -> AuditSnapshot {
    let filter = AuditFilter {
        limit,
        since: Some(chrono::Duration::hours(since_hours)),
        identity: identity.map(str::to_string),
        ..Default::default()
    };
    let entries = state.audit.query_filtered(&filter).unwrap_or_default();
    let mut snap = AuditSnapshot {
        calls: entries.len(),
        ..Default::default()
    };
    for entry in &entries {
        if !entry.success {
            snap.errors += 1;
        }
        if entry.acl_decision.as_deref() == Some("deny") {
            snap.denied += 1;
            if snap.denials.len() < 5 {
                snap.denials.push(json!({
                    "tool": entry.tool_name.clone().unwrap_or_else(|| entry.method.clone()),
                    "identity": entry.identity,
                    "rule": entry.acl_matched_rule.clone().unwrap_or_else(|| "default".into()),
                    "at": short_time(&entry.timestamp),
                }));
            }
        }
        if let Some(server) = &entry.server_name {
            *snap.per_server.entry(server.clone()).or_insert(0) += 1;
        }
    }
    snap.rows = entries;
    snap
}

pub fn short_time(timestamp: &str) -> String {
    // RFC 3339 -> HH:MM:SS, without pulling a date formatter into the view.
    timestamp
        .split('T')
        .nth(1)
        .map(|t| t.chars().take(8).collect())
        .unwrap_or_else(|| timestamp.chars().take(19).collect())
}

/// The same preflight `mcp --list` runs: can this backend's command start
/// here at all? HTTP backends always answer `None` — reachability needs a
/// request, and this is a config view.
pub fn unavailable_reason(config: &ServerConfig) -> Option<String> {
    crate::output::server_unavailable_reason(config)
}

pub fn kind_of(config: &ServerConfig) -> &'static str {
    match config {
        ServerConfig::Http { .. } => "http",
        ServerConfig::Cli { .. } => "cli",
        ServerConfig::Stdio { .. } => "stdio",
    }
}

pub fn endpoint_of(config: &ServerConfig) -> String {
    match config {
        ServerConfig::Http { url, .. } => url.clone(),
        ServerConfig::Stdio { command, args, .. } | ServerConfig::Cli { command, args, .. } => {
            if args.is_empty() {
                command.clone()
            } else {
                format!("{command} {}", args.join(" "))
            }
        }
    }
}

pub fn idle_label(config: &ServerConfig) -> String {
    match config.idle_timeout_policy() {
        IdleTimeoutPolicy::Adaptive => "adaptive".to_string(),
        IdleTimeoutPolicy::Never => "never".to_string(),
        IdleTimeoutPolicy::Fixed(value) => value.clone(),
    }
}

/// One row per configured server, joined with its cache and 24h call count.
pub fn server_rows(
    cfg: &Config,
    state: &UiState,
    viewer: &Viewer,
    calls: &HashMap<String, usize>,
) -> Vec<Value> {
    let mut names: Vec<&String> = cfg.servers.keys().collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let config = &cfg.servers[name];
            let cached = state.cached(name);
            let visible = cached
                .as_ref()
                .map(|c| visible_tools(viewer, cfg, name, &c.tools))
                .unwrap_or_default();
            let (tools, read, write) = classify_tools(config, &visible);
            let stale = match (&cached, cfg.config_hashes.get(name)) {
                (Some(c), Some(hash)) => &c.config_hash != hash,
                (None, _) => false,
                _ => true,
            };
            json!({
                "name": name,
                "kind": kind_of(config),
                "endpoint": endpoint_of(config),
                "idle": idle_label(config),
                "tools": tools,
                "read": read,
                "write": write,
                "cached_at": cached
                    .as_ref()
                    .map(|c| short_time(&c.cached_at))
                    .unwrap_or_else(|| "—".to_string()),
                "stale": stale,
                "dot": if cached.is_some() && !stale { "ok" } else if cached.is_some() { "warn" } else { "" },
                "calls": calls.get(name).copied().unwrap_or(0),
                "available": unavailable_reason(config).is_none(),
                "unavailable_reason": unavailable_reason(config),
                // A reader only sees backends whose catalog they can use; the
                // endpoint itself is metadata they have no claim to.
                "visible": viewer.is_local()
                    || viewer.admin
                    || !visible.is_empty(),
            })
        })
        .collect()
}

pub fn classify_tools(config: &ServerConfig, tools: &[Tool]) -> (usize, usize, usize) {
    let overrides: Option<&ToolOverrides> = config.tool_acl();
    let mut read = 0;
    let mut write = 0;
    for tool in tools {
        match classifier::classify(tool, overrides).kind {
            classifier::Kind::Read => read += 1,
            _ => write += 1,
        }
    }
    (tools.len(), read, write)
}

/// The tools this viewer may call.
///
/// In the local UI every tool is visible: the person running it is the person
/// whose config it is. In team mode the catalog is filtered by the same ACL
/// the proxy applies to `tools/list`, so the UI cannot show a tool the viewer
/// would be denied when calling it.
pub fn visible_tools(viewer: &Viewer, cfg: &Config, server: &str, tools: &[Tool]) -> Vec<Tool> {
    if viewer.is_local() {
        return tools.to_vec();
    }
    let Some(identity) = &viewer.identity else {
        return tools.to_vec();
    };
    let overrides = cfg.servers.get(server).and_then(|c| c.tool_acl());
    tools
        .iter()
        .filter(|tool| {
            let classification = classifier::classify(tool, overrides);
            let ctx = crate::server_auth::ToolContext {
                server_alias: server,
                tool_name: &tool.name,
                classification: Some(&classification),
            };
            crate::server_auth::is_tool_allowed(
                identity,
                &format!("{server}__{}", tool.name),
                &cfg.server_auth.acl,
                Some(&ctx),
            )
            .allowed
        })
        .cloned()
        .collect()
}

/// Tool table rows, classified the same way the proxy does.
pub fn tool_rows(
    tools: &[Tool],
    overrides: Option<&ToolOverrides>,
) -> (Vec<Value>, usize, usize, usize) {
    let mut rows = Vec::with_capacity(tools.len());
    let (mut read, mut write, mut ambiguous) = (0, 0, 0);
    for tool in tools {
        let class = classifier::classify(tool, overrides);
        match class.kind {
            classifier::Kind::Read => read += 1,
            classifier::Kind::Write => write += 1,
            classifier::Kind::Ambiguous => ambiguous += 1,
        }
        rows.push(json!({
            "name": tool.name,
            "description": tool.description.clone().unwrap_or_default(),
            "kind": class.kind.as_str(),
            "source": class.source.as_str(),
            "confidence": format!("{:.2}", class.confidence),
        }));
    }
    (rows, read, write, ambiguous)
}

/// Shown instead of a literal secret. One string, used by the config view, the
/// edit form and the diff, so a value can round-trip through the form without
/// the browser ever holding it.
pub const REDACTED: &str = "•••• (redacted)";

/// A `${VAR}` reference is safe to show; anything else in a header or env value
/// may be a secret.
pub fn redact_secret(value: &str) -> String {
    if value.contains("${") {
        value.to_string()
    } else if value.is_empty() {
        String::new()
    } else {
        REDACTED.to_string()
    }
}

/// Literal (non-placeholder) values from a server's `headers` and `env`.
///
/// Used to seal a diff: the diff is computed on the raw bytes, then these
/// substrings are replaced before the HTML is rendered.
pub fn literal_secrets(value: &Value) -> Vec<String> {
    let mut secrets = Vec::new();
    for key in ["headers", "env"] {
        let Some(map) = value.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        for value in map.values() {
            let Some(text) = value.as_str() else { continue };
            if !text.contains("${") {
                secrets.push(text.to_string());
            }
        }
    }
    secrets
}

/// Replaces literal secret values inside a rendered diff.
///
/// Matching the *quoted* JSON form rather than the bare value: it cannot
/// mistake a short value for something else in the line, and it handles the
/// escaping the raw file uses (a secret containing a quote or a backslash).
/// JSON parsing and re-rendering would be worse: it drops the comments the diff
/// exists to show.
pub fn seal_diff(diff: &str, secrets: &[String]) -> String {
    let mut sealed = diff.to_string();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        // A value embedded in something longer ("Bearer sk-…") only matches as
        // a bare substring. Short values match the quoted JSON form instead:
        // replacing "1" everywhere would shred the diff for nothing.
        if secret.len() >= 4 {
            sealed = sealed.replace(secret, REDACTED);
        } else {
            let quoted = serde_json::to_string(secret).unwrap_or_default();
            if !quoted.is_empty() {
                sealed = sealed.replace(&quoted, &format!("\"{REDACTED}\""));
            }
        }
    }
    sealed
}

/// Literal secrets from every server in the document.
///
/// The diff is computed on the whole file and carries context lines, so
/// sealing only the entry being edited would leave a neighbouring entry's
/// token visible (SEC-20).
pub fn literal_secrets_document(document: &Value) -> Vec<String> {
    let mut secrets = Vec::new();
    if let Some(servers) = document.get("mcpServers").and_then(|v| v.as_object()) {
        for server in servers.values() {
            secrets.extend(literal_secrets(server));
        }
    }
    secrets
}

/// Redacts values that look like credentials while keeping `${VAR}`
/// placeholders readable — they are references, not secrets.
pub fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, val)| {
                    let lowered = key.to_ascii_lowercase();
                    let secretish = lowered.contains("token")
                        || lowered.contains("secret")
                        || lowered.contains("password")
                        || lowered.contains("authorization")
                        || lowered.contains("api_key")
                        || lowered.contains("apikey");
                    let value = if secretish {
                        Value::String(redacted_value(val))
                    } else if lowered.contains("url") {
                        match val.as_str() {
                            Some(url) => Value::String(redact_url(url)),
                            None => redact_deep(val, false),
                        }
                    } else if lowered == "args" {
                        Value::Array(redact_args(val))
                    } else {
                        redact_deep(val, lowered == "env" || lowered == "headers")
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Query parameters whose value is a credential, whatever the header says.
fn sensitive_param(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "sig",
        "signature",
        "auth",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

/// Redacts credential-looking query values while keeping the URL usable.
fn redact_url(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let (query, fragment) = match query.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (query, None),
    };
    let mut parts = Vec::new();
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some((name, _value)) if sensitive_param(name) => {
                parts.push(format!("{name}={REDACTED}"))
            }
            Some((name, value)) => parts.push(format!("{name}={value}")),
            None => parts.push(pair.to_string()),
        }
    }
    let mut out = format!("{base}?{}", parts.join("&"));
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// `args` can carry a credential (`--token abc`). Values that follow a
/// credential-ish flag, and `--flag=value` pairs, are redacted.
fn redact_args(value: &Value) -> Vec<Value> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    let mut redact_next = false;
    for item in items {
        let Some(text) = item.as_str() else {
            out.push(item.clone());
            continue;
        };
        if redact_next {
            redact_next = false;
            out.push(Value::String(REDACTED.to_string()));
            continue;
        }
        if let Some((flag, _)) = text.split_once('=') {
            if flag.starts_with('-') && sensitive_param(flag) {
                out.push(Value::String(format!("{flag}={REDACTED}")));
                continue;
            }
        }
        if text.starts_with('-') && sensitive_param(text) {
            redact_next = true;
        }
        out.push(item.clone());
    }
    out
}

/// Inside `env` and `headers` every literal value may be a secret; only
/// placeholders are safe to show.
fn redact_deep(value: &Value, in_secret_map: bool) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_deep(v, in_secret_map)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_deep(v, in_secret_map))
                .collect(),
        ),
        Value::String(s) if in_secret_map => Value::String(redact_secret(s)),
        other => other.clone(),
    }
}

fn redacted_value(value: &Value) -> String {
    match value {
        Value::String(s) => redact_secret(s),
        _ => REDACTED.to_string(),
    }
}

/// The edit form's values, built from the **raw** entry and never from the
/// loaded config.
///
/// Two reasons. `load_config` expands `${VAR}` before parsing, so using the
/// typed value here would show "Bearer " instead of "Bearer ${SENTRY_TOKEN}"
/// and applying the form would write that empty value back. And a literal
/// secret must not reach the browser at all: `redact_secret` replaces it with
/// the sentinel, which `EditForm::apply_to` turns back into the stored value
/// when the field is submitted untouched.
pub fn form_view(name: &str, raw: &Value) -> Value {
    let kind = if raw.get("url").is_some() {
        "http"
    } else if raw.get("cli").and_then(Value::as_bool).unwrap_or(false) {
        "cli"
    } else {
        "stdio"
    };

    let url = raw.get("url").and_then(Value::as_str).unwrap_or("");
    let command = raw.get("command").and_then(Value::as_str).unwrap_or("");
    let args: Vec<String> = raw
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let acl = raw.get("tool_acl");

    json!({
        "name": name,
        "kind": kind,
        "url": url,
        "command": command,
        // Quoted, so an argument containing spaces survives the round-trip.
        "args": shell_words::join(&args),
        "headers_text": pairs_text(raw.get("headers"), ": "),
        "env_text": pairs_text(raw.get("env"), "="),
        "idle": raw.get("idle_timeout").and_then(Value::as_str).unwrap_or("adaptive"),
        "tool_acl_read": globs(acl, "read"),
        "tool_acl_write": globs(acl, "write"),
    })
}

fn pairs_text(value: Option<&Value>, separator: &str) -> String {
    let Some(map) = value.and_then(Value::as_object) else {
        return String::new();
    };
    let mut lines: Vec<String> = map
        .iter()
        .map(|(k, v)| {
            let value = v.as_str().map(redact_secret).unwrap_or_default();
            format!("{k}{separator}{value}")
        })
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

/// Parses the tool schema into form fields the playground can render without
/// knowing MCP.
pub fn schema_fields(schema: Option<&Value>) -> Vec<Value> {
    let Some(schema) = schema else {
        return Vec::new();
    };
    let Some(props) = schema.get("properties").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut fields = Vec::new();
    for (key, prop) in props {
        let ty = prop
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("any")
            .to_string();
        let description = prop
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let placeholder = prop
            .get("examples")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .map(|v| v.to_string())
            .unwrap_or_default();

        let (kind, options) = if let Some(values) = prop.get("enum").and_then(|e| e.as_array()) {
            (
                "select",
                values
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string())
                    })
                    .collect::<Vec<_>>(),
            )
        } else if ty == "boolean" {
            ("bool", Vec::new())
        } else if ty == "number" || ty == "integer" {
            ("number", Vec::new())
        } else if ty == "string" {
            if is_long_text(key, &description) {
                ("textarea", Vec::new())
            } else {
                ("text", Vec::new())
            }
        } else {
            ("raw", Vec::new())
        };

        let value = prop
            .get("default")
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();

        fields.push(json!({
            "key": key,
            "type": ty,
            "kind": kind,
            "options": options,
            "required": required.contains(&key.as_str()),
            "description": description,
            "placeholder": placeholder,
            "value": value,
        }));
    }
    // Required fields first, then alphabetical: the thing you must fill should
    // not be below the fold.
    fields.sort_by(|a, b| {
        let ra = a["required"].as_bool().unwrap_or(false);
        let rb = b["required"].as_bool().unwrap_or(false);
        rb.cmp(&ra).then_with(|| {
            a["key"]
                .as_str()
                .unwrap_or("")
                .cmp(b["key"].as_str().unwrap_or(""))
        })
    });
    fields
}

fn is_long_text(key: &str, description: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "query", "text", "body", "prompt", "sql", "code", "content", "message",
    ]
    .iter()
    .any(|k| key.contains(k))
        || description.len() > 120
}

/// Turns submitted form values into the JSON arguments object the tool expects,
/// coercing by the schema's declared types.
pub fn form_arguments(
    fields: &[Value],
    form: &HashMap<String, String>,
    raw_override: &str,
) -> Result<Value, String> {
    if !raw_override.trim().is_empty() {
        let parsed: Value = serde_json::from_str(raw_override)
            .map_err(|e| format!("arguments are not valid JSON: {e}"))?;
        if !parsed.is_object() {
            return Err("arguments must be a JSON object".to_string());
        }
        return Ok(parsed);
    }

    let mut args = Map::new();
    for field in fields {
        let key = field["key"].as_str().unwrap_or_default();
        let Some(raw) = form.get(&format!("arg_{key}")) else {
            continue;
        };
        if raw.is_empty() {
            if field["required"].as_bool().unwrap_or(false) {
                return Err(format!("{key} is required"));
            }
            continue;
        }
        let type_name = field["type"].as_str().unwrap_or("any");
        let kind = field["kind"].as_str().unwrap_or("text");
        let value = match kind {
            "number" => {
                let n: f64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("{key} must be a number"))?;
                if type_name == "integer" && n.fract() != 0.0 {
                    return Err(format!("{key} must be an integer"));
                }
                if type_name == "integer" {
                    json!(n as i64)
                } else {
                    json!(n)
                }
            }
            "bool" => json!(raw == "true"),
            "raw" => {
                serde_json::from_str(raw).map_err(|e| format!("{key} must be valid JSON: {e}"))?
            }
            _ => json!(raw),
        };
        args.insert(key.to_string(), value);
    }
    Ok(Value::Object(args))
}

/// Client-side shape of a server edit form.
pub struct EditForm<'a> {
    pub form: &'a HashMap<String, String>,
}

impl EditForm<'_> {
    pub fn get(&self, key: &str) -> &str {
        self.form.get(key).map(String::as_str).unwrap_or("")
    }

    /// Applies the form to the server's raw JSON, returning the new object.
    ///
    /// Only the fields present in the form are touched; everything else in the
    /// entry (unknown keys, `forward_identity`, `tools`) survives untouched.
    /// Values submitted as the redaction sentinel are read back from `current`,
    /// which is the only place the real secret exists.
    pub fn apply_to(&self, current: &Value) -> Result<Value, String> {
        let mut next = current.as_object().cloned().unwrap_or_default();
        let kind = if next.contains_key("url") {
            "http"
        } else if next.get("cli").and_then(Value::as_bool).unwrap_or(false) {
            "cli"
        } else {
            "stdio"
        };

        if kind == "http" {
            next.insert("url".into(), json!(self.get("url").trim()));
            let headers = restore_redacted(
                parse_pairs(self.get("headers"), ':'),
                current.get("headers"),
            )?;
            if headers.is_empty() {
                next.remove("headers");
            } else {
                next.insert("headers".into(), json!(headers));
            }
        } else {
            next.insert("command".into(), json!(self.get("command").trim()));
            let args = self.get("args").trim();
            let current_args: Vec<String> = current
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if args.is_empty() {
                next.remove("args");
            } else if args == shell_words::join(&current_args) {
                // Untouched: keep the array byte-for-byte, so quitting the form
                // cannot reinterpret an argument that was already correct.
                if !current_args.is_empty() {
                    next.insert("args".into(), json!(current_args));
                }
            } else {
                let parsed = shell_words::split(args).map_err(|e| format!("args: {e}"))?;
                next.insert("args".into(), json!(parsed));
            }
            let env = restore_redacted(parse_pairs(self.get("env"), '='), current.get("env"))?;
            if env.is_empty() {
                next.remove("env");
            } else {
                next.insert("env".into(), json!(env));
            }
        }

        // "adaptive" is the default, so an entry that never declared it stays
        // that way; one that declared it keeps an explicit value. Editing a
        // field should not silently delete the line the operator wrote.
        let had_idle = next.contains_key("idle_timeout");
        let idle = self.get("idle_timeout").trim();
        if idle.is_empty() || (idle == "adaptive" && !had_idle) {
            next.remove("idle_timeout");
        } else {
            next.insert("idle_timeout".into(), json!(idle));
        }

        let read = split_globs(self.get("tool_acl_read"));
        let write = split_globs(self.get("tool_acl_write"));
        if read.is_empty() && write.is_empty() {
            next.remove("tool_acl");
        } else {
            next.insert("tool_acl".into(), json!({ "read": read, "write": write }));
        }

        Ok(Value::Object(next))
    }
}

/// Puts the stored value back where the form shows the redaction sentinel.
///
/// A sentinel for a key the entry does not have is dropped: there is no secret
/// to restore, and writing the sentinel itself would corrupt the config.
fn restore_redacted(
    pairs: std::collections::BTreeMap<String, String>,
    current: Option<&Value>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut out = std::collections::BTreeMap::new();
    for (key, value) in pairs {
        if value == REDACTED {
            if let Some(existing) = current.and_then(|c| c.get(&key)).and_then(Value::as_str) {
                out.insert(key, existing.to_string());
            }
        } else if value.contains(REDACTED) {
            // The placeholder mixed with typed text: there is no way to know
            // which part is the secret, and writing the placeholder into the
            // config is worse than refusing.
            return Err(format!(
                "{key}: the redacted placeholder cannot be edited — clear the field and type the value, or leave it untouched"
            ));
        } else {
            out.insert(key, value);
        }
    }
    Ok(out)
}

fn split_globs(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parses `Key: Value` or `KEY=value` lines into a map. Blank lines and lines
/// starting with `#` are ignored so operators can leave comments in the field.
fn parse_pairs(raw: &str, separator: char) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(separator) {
            let key = key.trim();
            if !key.is_empty() {
                out.insert(key.to_string(), value.trim().to_string());
            }
        }
    }
    out
}

pub fn load_source() -> UiResult<(ConfigSource, Config)> {
    let source = ConfigSource::load().map_err(super::UiError::Internal)?;
    let cfg = crate::config::load_config().map_err(super::UiError::Internal)?;
    Ok((source, cfg))
}

/// Validates that the UI may write, returning the read-only reason otherwise.
pub fn ensure_writable(state: &UiState, source: &ConfigSource, viewer: &Viewer) -> UiResult<()> {
    if !viewer.can_write() {
        return Err(super::UiError::Forbidden(
            "this action needs an admin role (serverAuth.adminRoles)".to_string(),
        ));
    }
    if state.read_only {
        return Err(super::UiError::BadRequest(
            "this UI was started with --read-only".to_string(),
        ));
    }
    if !source.is_writable() {
        return Err(super::UiError::BadRequest(
            source
                .read_only_reason()
                .unwrap_or("config is read-only")
                .to_string(),
        ));
    }
    Ok(())
}

pub fn csrf_ok(state: &UiState, form: &HashMap<String, String>) -> UiResult<()> {
    match form.get("csrf") {
        Some(token) if super::session::ct_eq(token, &state.token) => Ok(()),
        _ => Err(super::UiError::BadRequest(
            "invalid or missing form token".to_string(),
        )),
    }
}

/// Records a UI action in the same audit trail as everything else.
pub fn audit_ui(state: &UiState, viewer: &Viewer, action: UiAction<'_>) {
    state.audit.log(AuditEntry {
        timestamp: chrono::Local::now().to_rfc3339(),
        source: "ui".to_string(),
        method: action.method.to_string(),
        tool_name: action.tool.map(str::to_string),
        server_name: action.server.map(str::to_string),
        identity: viewer.subject().to_string(),
        duration_ms: action.duration_ms,
        success: action.ok,
        error_message: action.error,
        arguments: None,
        acl_decision: None,
        acl_matched_rule: None,
        acl_access_kind: None,
        classification_kind: None,
        classification_source: None,
        classification_confidence: None,
    });
}

/// One UI action, as it should appear in the audit trail.
pub struct UiAction<'a> {
    pub method: &'a str,
    pub tool: Option<&'a str>,
    pub server: Option<&'a str>,
    pub ok: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

pub fn instances_view() -> Vec<Value> {
    let now = chrono::Local::now();
    let mut out = Vec::new();
    for record in crate::instances::list_live().unwrap_or_default() {
        let started = chrono::DateTime::parse_from_rfc3339(&record.started_at)
            .map(|t| t.with_timezone(&chrono::Local))
            .ok();
        let uptime = started
            .map(|t| {
                let secs = (now - t).num_seconds().max(0);
                if secs < 3600 {
                    format!("{}m", secs / 60)
                } else {
                    format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
                }
            })
            .unwrap_or_else(|| "?".to_string());
        out.push(json!({
            "pid": record.pid,
            "transport": record.transport,
            "addr": record.addr.clone().unwrap_or_else(|| "stdio".to_string()),
            "version": record.version,
            "started_at": short_time(&record.started_at),
            "uptime": uptime,
            "filter": match (record.only.as_deref(), record.exclude.as_deref()) {
                (Some(only), _) => format!("--only {only}"),
                (None, Some(exclude)) => format!("--exclude {exclude}"),
                _ => "—".to_string(),
            },
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_auth::AuthIdentity;
    use serde_json::json;

    fn form(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn schema_fields_put_required_first_and_pick_the_right_control() {
        let schema = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "the search query" },
                "sort": { "enum": ["date", "freq"] },
                "limit": { "type": "integer" },
                "dry": { "type": "boolean" },
                "extra": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["query"]
        });
        let fields = schema_fields(Some(&schema));
        assert_eq!(fields[0]["key"], "query");
        assert_eq!(fields[0]["kind"], "textarea");
        assert_eq!(fields[0]["required"], true);

        let by_key = |key: &str| {
            fields
                .iter()
                .find(|f| f["key"] == key)
                .unwrap_or_else(|| panic!("{key} missing"))
                .clone()
        };
        assert_eq!(by_key("sort")["kind"], "select");
        assert_eq!(by_key("sort")["options"], json!(["date", "freq"]));
        assert_eq!(by_key("limit")["kind"], "number");
        assert_eq!(by_key("dry")["kind"], "bool");
        assert_eq!(by_key("extra")["kind"], "raw");
    }

    #[test]
    fn arguments_are_coerced_by_schema_type() {
        let fields = schema_fields(Some(&json!({
            "type": "object",
            "properties": {
                "n": { "type": "integer" },
                "flag": { "type": "boolean" },
                "q": { "type": "string" }
            }
        })));
        let args = form_arguments(
            &fields,
            &form(&[("arg_n", "42"), ("arg_flag", "true"), ("arg_q", "hello")]),
            "",
        )
        .unwrap();
        assert_eq!(args, json!({ "n": 42, "flag": true, "q": "hello" }));
    }

    #[test]
    fn missing_required_argument_is_an_error() {
        let fields = schema_fields(Some(&json!({
            "type": "object",
            "properties": { "query": { "type": "string" } },
            "required": ["query"]
        })));
        let err = form_arguments(&fields, &form(&[("arg_query", "")]), "").unwrap_err();
        assert!(err.contains("query"), "error should name the field: {err}");
    }

    #[test]
    fn raw_override_wins_over_fields() {
        let fields = schema_fields(Some(&json!({
            "type": "object",
            "properties": { "q": { "type": "string" } }
        })));
        let args = form_arguments(
            &fields,
            &form(&[("arg_q", "ignored")]),
            r#"{"q":"from json","n":1}"#,
        )
        .unwrap();
        assert_eq!(args, json!({ "q": "from json", "n": 1 }));

        let err = form_arguments(&fields, &HashMap::new(), "[1,2]").unwrap_err();
        assert!(err.contains("object"), "{err}");
    }

    #[test]
    fn editing_keeps_unknown_keys_and_preserves_the_idle_line() {
        let current = json!({
            "url": "https://example.com/mcp",
            "idle_timeout": "never",
            "forward_identity": { "header": "X-MCP-Subject" },
            "future_key": 7
        });
        let next = EditForm {
            form: &form(&[
                ("url", "https://example.com/mcp"),
                ("headers", "Authorization: Bearer ${TOKEN}"),
                ("idle_timeout", "adaptive"),
            ]),
        }
        .apply_to(&current)
        .expect("the form is valid");
        assert_eq!(next["idle_timeout"], "adaptive");
        assert_eq!(next["forward_identity"]["header"], "X-MCP-Subject");
        assert_eq!(next["future_key"], 7);
        assert_eq!(next["headers"]["Authorization"], "Bearer ${TOKEN}");
    }

    #[test]
    fn adding_an_idle_timeout_to_an_entry_that_had_none_stays_implicit() {
        let current = json!({ "url": "https://example.com/mcp" });
        let next = EditForm {
            form: &form(&[
                ("url", "https://example.com/mcp"),
                ("idle_timeout", "adaptive"),
            ]),
        }
        .apply_to(&current)
        .expect("the form is valid");
        assert!(next.get("idle_timeout").is_none(), "default stays implicit");
    }

    #[test]
    fn stdio_editing_splits_args_and_parses_env() {
        let current = json!({ "command": "npx", "args": ["-y", "a"] });
        let next = EditForm {
            form: &form(&[
                ("command", "npx"),
                ("args", "-y a --flag b"),
                ("env", "TOKEN=${T}\n# comment\nB=2"),
            ]),
        }
        .apply_to(&current)
        .expect("the form is valid");
        assert_eq!(next["args"], json!(["-y", "a", "--flag", "b"]));
        assert_eq!(next["env"]["TOKEN"], "${T}");
        assert_eq!(next["env"]["B"], "2");
        assert!(next["env"].get("# comment").is_none());
    }

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: None,
            input_schema: None,
            annotations: None,
        }
    }

    /// A tool the classifier is sure about, without depending on how it scores
    /// descriptions: the proxy honours `readOnlyHint` before heuristics.
    fn read_tool(name: &str) -> Tool {
        Tool {
            annotations: Some(crate::protocol::ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: None,
                idempotent_hint: None,
                open_world_hint: None,
            }),
            ..tool(name)
        }
    }

    fn team_config() -> Config {
        crate::config::validate_config_text(
            r#"{
              "mcpServers": { "sentry": { "url": "https://example.com/mcp" } },
              "serverAuth": {
                "acl": {
                  "default": "deny",
                  "roles": {
                    "admin": [{ "server": "*", "access": "*" }],
                    "dev": [{ "server": "sentry", "access": "read" }],
                    "nothing": []
                  },
                  "subjects": {}
                }
              }
            }"#,
            std::path::PathBuf::from("<test>"),
        )
        .expect("test config")
    }

    #[test]
    fn a_backend_whose_command_is_missing_is_flagged_before_spawning() {
        let cfg = crate::config::validate_config_text(
            r#"{
              "mcpServers": {
                "ghost": { "command": "mcp-not-a-real-binary-xyz", "args": [] },
                "remote": { "url": "https://example.com/mcp" }
              }
            }"#,
            std::path::PathBuf::from("<test>"),
        )
        .expect("test config");

        let reason = unavailable_reason(&cfg.servers["ghost"]).expect("must be unavailable");
        assert!(
            reason.contains("mcp-not-a-real-binary-xyz"),
            "reason should name the command: {reason}"
        );
        assert!(
            unavailable_reason(&cfg.servers["remote"]).is_none(),
            "HTTP is never preflighted"
        );
    }

    #[test]
    fn the_catalog_is_filtered_by_the_viewers_acl() {
        let cfg = team_config();
        let tools = vec![read_tool("search_issues"), tool("resolve_issue")];

        let local = Viewer::local();
        assert_eq!(visible_tools(&local, &cfg, "sentry", &tools).len(), 2);

        let dev = Viewer::team(AuthIdentity::new("bob", vec!["dev".into()]), false);
        let visible = visible_tools(&dev, &cfg, "sentry", &tools);
        assert_eq!(visible.len(), 1);
        assert_eq!(
            visible[0].name, "search_issues",
            "write tool is filtered out"
        );

        let admin = Viewer::team(AuthIdentity::new("alice", vec!["admin".into()]), true);
        assert_eq!(visible_tools(&admin, &cfg, "sentry", &tools).len(), 2);

        let nobody = Viewer::team(AuthIdentity::new("eve", vec!["nothing".into()]), false);
        assert!(visible_tools(&nobody, &cfg, "sentry", &tools).is_empty());
    }

    #[test]
    fn a_local_viewer_is_never_filtered_even_with_an_acl_configured() {
        let cfg = team_config();
        let tools = vec![tool("resolve_issue")];
        assert_eq!(
            visible_tools(&Viewer::local(), &cfg, "sentry", &tools).len(),
            1
        );
    }

    #[test]
    fn the_edit_form_never_contains_a_literal_secret() {
        let raw = json!({
            "url": "https://example.com/mcp",
            "headers": {
                "Authorization": "Bearer sk-live-123456",
                "X-Team": "platform"
            },
            "env": { "TOKEN": "${GITHUB_TOKEN}", "MODE": "strict" }
        });
        let view = form_view("sentry", &raw);
        let text = view.to_string();
        assert!(
            !text.contains("sk-live-123456"),
            "header secret leaked: {text}"
        );
        assert!(!text.contains("platform"), "header value leaked: {text}");
        assert!(!text.contains("strict"), "env value leaked: {text}");
        assert!(
            text.contains("${GITHUB_TOKEN}"),
            "placeholder must stay readable"
        );
        assert_eq!(
            view["headers_text"],
            "Authorization: •••• (redacted)\nX-Team: •••• (redacted)"
        );
        assert_eq!(
            view["env_text"],
            "MODE=•••• (redacted)\nTOKEN=${GITHUB_TOKEN}"
        );
    }

    #[test]
    fn an_untouched_redacted_field_keeps_the_stored_secret() {
        let current = json!({
            "url": "https://example.com/mcp",
            "headers": { "Authorization": "Bearer sk-live-123456" },
            "env": { "MODE": "strict" }
        });
        let mut form = form(&[("url", "https://example.com/mcp")]);
        form.insert("headers".into(), format!("Authorization: {REDACTED}"));
        form.insert("env".into(), format!("MODE={REDACTED}"));
        let next = EditForm { form: &form }
            .apply_to(&current)
            .expect("valid form");
        assert_eq!(next["headers"]["Authorization"], "Bearer sk-live-123456");
        assert_eq!(next["env"]["MODE"], "strict");
    }

    #[test]
    fn text_mixed_with_the_placeholder_is_refused() {
        let current = json!({
            "url": "https://example.com/mcp",
            "headers": { "Authorization": "Bearer sk-live-123456" }
        });
        let form = form(&[
            ("url", "https://example.com/mcp"),
            ("headers", &format!("Authorization: Bearer {REDACTED}")),
        ]);
        let err = EditForm { form: &form }.apply_to(&current).unwrap_err();
        assert!(err.contains("placeholder"), "{err}");
    }

    #[test]
    fn a_sentinel_for_an_unknown_key_is_dropped() {
        let current = json!({ "url": "https://example.com/mcp" });
        let form = form(&[
            ("url", "https://example.com/mcp"),
            ("headers", &format!("X-New: {REDACTED}")),
        ]);
        let next = EditForm { form: &form }
            .apply_to(&current)
            .expect("valid form");
        assert!(
            next.get("headers").is_none(),
            "nothing to restore, and the sentinel must not be written"
        );
    }

    #[test]
    fn arguments_with_spaces_survive_the_edit_form() {
        let current = json!({
            "command": "npx",
            "args": ["-y", "pkg", "--header", "Authorization: Bearer abc"]
        });
        let view = form_view("tool", &current);
        let rendered = view["args"].as_str().unwrap().to_string();
        assert!(rendered.contains("Authorization: Bearer abc"), "{rendered}");
        assert!(
            rendered.contains('\''),
            "the argument must be quoted: {rendered}"
        );

        // Submitting the same text keeps the array byte-for-byte.
        let same = form(&[("command", "npx"), ("args", &rendered)]);
        let next = EditForm { form: &same }
            .apply_to(&current)
            .expect("valid form");
        assert_eq!(next["args"], current["args"]);

        // Changing it splits with shell rules, not on whitespace.
        let changed = form(&[
            ("command", "npx"),
            ("args", "-y pkg --header \"X-A: 1 2 3\""),
        ]);
        let next = EditForm { form: &changed }
            .apply_to(&current)
            .expect("valid form");
        assert_eq!(next["args"], json!(["-y", "pkg", "--header", "X-A: 1 2 3"]));
    }

    #[test]
    fn an_unbalanced_argument_string_is_rejected_not_guessed() {
        let current = json!({ "command": "npx", "args": [] });
        let form = form(&[("command", "npx"), ("args", "pkg \"unterminated")]);
        let err = EditForm { form: &form }.apply_to(&current).unwrap_err();
        assert!(err.contains("args"), "{err}");
    }

    #[test]
    fn the_plan_diff_does_not_show_a_secret() {
        let secrets = vec!["sk-live-123456".to_string()];
        let diff = "@@ -1,2 +1,2 @@\n-  \"Authorization\": \"Bearer sk-live-123456\"\n+  \"Authorization\": \"Bearer sk-live-999\"\n";
        let sealed = seal_diff(diff, &secrets);
        assert!(!sealed.contains("sk-live-123456"));
        assert!(sealed.contains(REDACTED));
        assert!(
            sealed.contains("@@ -1,2 +1,2 @@"),
            "diff structure survives"
        );
    }

    #[test]
    fn literal_secrets_only_collects_real_values() {
        let raw = json!({
            "headers": { "A": "${TOKEN}", "B": "literal-value" },
            "env": { "C": "123", "D": "long-enough" },
            "url": "https://example.com"
        });
        let secrets = literal_secrets(&raw);
        assert!(secrets.contains(&"literal-value".to_string()));
        assert!(secrets.contains(&"long-enough".to_string()));
        assert!(!secrets.contains(&"${TOKEN}".to_string()));
        assert!(
            secrets.contains(&"123".to_string()),
            "short values are sealed too"
        );
    }

    #[test]
    fn query_strings_and_arguments_are_redacted_too() {
        let raw = json!({
            "url": "https://example.com/mcp?api_key=secret-value&team=platform",
            "args": ["--token", "abc123", "--header", "X: y", "--api-key=zzz"]
        });
        let redacted = redact(&raw);
        let url = redacted["url"].as_str().unwrap();
        assert!(!url.contains("secret-value"), "{url}");
        assert!(url.contains("api_key=•••• (redacted)"), "{url}");
        assert!(url.contains("team=platform"), "harmless params stay: {url}");

        let args = redacted["args"].to_string();
        assert!(!args.contains("abc123"), "{args}");
        assert!(!args.contains("zzz"), "{args}");
        assert!(args.contains("X: y"), "unrelated args stay: {args}");
    }

    #[test]
    fn a_short_secret_is_sealed_when_it_is_a_whole_value() {
        let sealed = seal_diff("+  \"MODE\": \"1\"", &["1".to_string()]);
        assert!(!sealed.contains("\"1\""), "{sealed}");
        assert!(sealed.contains(REDACTED));
    }

    #[test]
    fn redaction_hides_literal_secrets_and_keeps_placeholders() {
        let raw = json!({
            "url": "https://example.com",
            "headers": { "Authorization": "Bearer ${TOKEN}", "X-Api-Key": "sk-live-123" },
            "env": { "TEAM": "platform", "SECRET_TOKEN": "${S}" }
        });
        let redacted = redact(&raw);
        assert_eq!(redacted["headers"]["Authorization"], "Bearer ${TOKEN}");
        assert_eq!(redacted["headers"]["X-Api-Key"], "•••• (redacted)");
        assert_eq!(redacted["env"]["TEAM"], "•••• (redacted)");
        assert_eq!(redacted["env"]["SECRET_TOKEN"], "${S}");
        assert_eq!(redacted["url"], "https://example.com");
    }
}
