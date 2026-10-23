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
        Value::String(s) if in_secret_map => {
            if s.contains("${") {
                Value::String(s.clone())
            } else {
                Value::String(redacted_value(&Value::String(s.clone())))
            }
        }
        other => other.clone(),
    }
}

fn redacted_value(value: &Value) -> String {
    match value {
        Value::String(s) if s.contains("${") => s.clone(),
        _ => "•••• (redacted)".to_string(),
    }
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
    pub fn apply_to(&self, current: &Value) -> Value {
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
            match parse_pairs(self.get("headers"), ':') {
                pairs if pairs.is_empty() => {
                    next.remove("headers");
                }
                pairs => {
                    next.insert("headers".into(), json!(pairs));
                }
            }
        } else {
            next.insert("command".into(), json!(self.get("command").trim()));
            let args = self.get("args").trim();
            if args.is_empty() {
                next.remove("args");
            } else {
                next.insert(
                    "args".into(),
                    json!(args.split_whitespace().collect::<Vec<_>>()),
                );
            }
            match parse_pairs(self.get("env"), '=') {
                pairs if pairs.is_empty() => {
                    next.remove("env");
                }
                pairs => {
                    next.insert("env".into(), json!(pairs));
                }
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

        Value::Object(next)
    }
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
        Some(token) if token == &state.token => Ok(()),
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
        .apply_to(&current);
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
        .apply_to(&current);
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
        .apply_to(&current);
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
