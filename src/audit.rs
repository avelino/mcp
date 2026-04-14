use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

use crate::db::DbPool;

fn default_true() -> bool {
    true
}

fn default_output() -> AuditOutput {
    AuditOutput::File
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutput {
    File,
    Stdout,
    Stderr,
    None,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: Option<String>,
    pub index_path: Option<String>,
    #[serde(default)]
    pub log_arguments: bool,
    #[serde(default = "default_output")]
    pub output: AuditOutput,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            index_path: None,
            log_arguments: false,
            output: AuditOutput::File,
        }
    }
}

impl AuditConfig {
    /// Returns the data path override, if configured.
    pub fn data_path_override(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the index path override, if configured.
    pub fn index_path_override(&self) -> Option<&str> {
        self.index_path.as_deref()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub source: String,
    pub method: String,
    pub tool_name: Option<String>,
    pub server_name: Option<String>,
    pub identity: String,
    pub duration_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    // -- ACL decision fields (added by issue #56) --
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_access_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_confidence: Option<f32>,
}

impl AuditEntry {
    /// Human-readable summary from arguments for the Detail column.
    pub fn detail(&self) -> String {
        if let Some(ref args) = self.arguments {
            // Pick the most relevant field to show
            if let Some(q) = args.get("query").and_then(|v| v.as_str()) {
                return format!("query={q}");
            }
            if let Some(u) = args.get("url").and_then(|v| v.as_str()) {
                return format!("url={u}");
            }
            if let Some(f) = args.get("from").and_then(|v| v.as_str()) {
                return format!("from={f}");
            }
            // Fallback: compact JSON if small enough
            let s = args.to_string();
            if s.len() <= 60 {
                return s;
            }
        }
        if let Some(ref msg) = self.error_message {
            if !self.success {
                return truncate_error(msg);
            }
        }
        "-".to_string()
    }
}

/// Extract first meaningful line from error message and truncate to fit table.
fn truncate_error(msg: &str) -> String {
    // Take first line (before any newline or JSON blob)
    let first_line = msg.split('\n').next().unwrap_or(msg).trim();
    // Strip trailing JSON array/object markers
    let clean = first_line.trim_end_matches(|c: char| c == '[' || c == '{' || c.is_whitespace());
    if clean.len() <= 80 {
        clean.to_string()
    } else {
        format!("{}…", &clean[..77])
    }
}

pub struct AuditFilter {
    pub limit: usize,
    pub server: Option<String>,
    pub tool: Option<String>,
    pub method: Option<String>,
    pub identity: Option<String>,
    pub errors_only: bool,
    pub since: Option<chrono::Duration>,
    pub follow: bool,
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self {
            limit: 50,
            server: None,
            tool: None,
            method: None,
            identity: None,
            errors_only: false,
            since: None,
            follow: false,
        }
    }
}

impl AuditFilter {
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        if self.errors_only && entry.success {
            return false;
        }
        if let Some(ref s) = self.server {
            match &entry.server_name {
                Some(name) if name.starts_with(s) => {}
                _ => return false,
            }
        }
        if let Some(ref t) = self.tool {
            match &entry.tool_name {
                Some(name) if name.starts_with(t) => {}
                _ => return false,
            }
        }
        if let Some(ref m) = self.method {
            if &entry.method != m {
                return false;
            }
        }
        if let Some(ref id) = self.identity {
            if &entry.identity != id {
                return false;
            }
        }
        if let Some(ref since) = self.since {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&entry.timestamp) {
                let cutoff = Utc::now() - *since;
                if ts < cutoff {
                    return false;
                }
            }
        }
        true
    }
}

pub enum AuditLogger {
    Active {
        sender: tokio::sync::mpsc::UnboundedSender<AuditEntry>,
        pool: Arc<DbPool>,
    },
    Stream {
        sender: tokio::sync::mpsc::UnboundedSender<AuditEntry>,
    },
    Disabled,
}

impl AuditLogger {
    pub fn open(config: &AuditConfig, pool: Arc<DbPool>) -> Result<Self> {
        if !config.enabled {
            return Ok(AuditLogger::Disabled);
        }

        // Check effective output mode (env var overrides config)
        let output = match std::env::var("MCP_AUDIT_OUTPUT") {
            Ok(v) => match v.trim().to_lowercase().as_str() {
                "stdout" => AuditOutput::Stdout,
                "stderr" => AuditOutput::Stderr,
                "none" => AuditOutput::None,
                "file" => AuditOutput::File,
                _ => config.output.clone(),
            },
            Err(_) => config.output.clone(),
        };

        match output {
            AuditOutput::None => Ok(AuditLogger::Disabled),
            AuditOutput::Stdout | AuditOutput::Stderr => {
                let use_stderr = output == AuditOutput::Stderr;
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AuditEntry>();
                tokio::task::spawn_blocking(move || {
                    while let Some(entry) = rx.blocking_recv() {
                        if let Ok(line) = serde_json::to_string(&entry) {
                            if use_stderr {
                                eprintln!("{line}");
                            } else {
                                println!("{line}");
                            }
                        }
                    }
                });
                Ok(AuditLogger::Stream { sender: tx })
            }
            AuditOutput::File => {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AuditEntry>();
                let writer_pool = pool.clone();
                tokio::task::spawn_blocking(move || {
                    while let Some(entry) = rx.blocking_recv() {
                        let key = format!(
                            "audit:{}-{}",
                            Utc::now().timestamp_millis(),
                            uuid::Uuid::new_v4()
                        );
                        match serde_json::to_value(&entry) {
                            Ok(doc) => match writer_pool.acquire() {
                                Ok(db) => {
                                    if let Err(e) = db.put(&key, &doc, None) {
                                        tracing::warn!(error = ?e, "failed to write audit entry");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = format!("{e:#}"),
                                        "failed to acquire db for audit"
                                    );
                                }
                            },
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to serialize audit entry");
                            }
                        }
                    }
                });
                Ok(AuditLogger::Active { sender: tx, pool })
            }
        }
    }

    pub fn log(&self, entry: AuditEntry) {
        match self {
            AuditLogger::Active { sender, .. } | AuditLogger::Stream { sender } => {
                let _ = sender.send(entry);
            }
            AuditLogger::Disabled => {}
        }
    }

    pub fn query_recent(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        match self {
            AuditLogger::Disabled | AuditLogger::Stream { .. } => Ok(vec![]),
            AuditLogger::Active { pool, .. } => {
                let db = pool.acquire()?;
                let raw = db
                    .list_by_prefix("audit:", None)
                    .map_err(|e| anyhow::anyhow!("failed to query audit logs: {e:?}"))?;
                parse_entries_from_list(&raw, limit)
            }
        }
    }

    pub fn query_filtered(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        match self {
            AuditLogger::Disabled | AuditLogger::Stream { .. } => Ok(vec![]),
            AuditLogger::Active { pool, .. } => {
                let db = pool.acquire()?;
                let raw = db
                    .list_by_prefix("audit:", None)
                    .map_err(|e| anyhow::anyhow!("failed to query audit logs: {e:?}"))?;
                let all_entries = parse_entries_from_list(&raw, usize::MAX)?;

                let filtered: Vec<AuditEntry> = all_entries
                    .into_iter()
                    .rev() // most recent first
                    .filter(|e| filter.matches(e))
                    .take(filter.limit)
                    .collect();

                Ok(filtered)
            }
        }
    }
}

fn parse_entries_from_list(raw: &Value, limit: usize) -> Result<Vec<AuditEntry>> {
    let mut entries = Vec::new();

    match raw {
        Value::Array(arr) => {
            for item in arr.iter().take(limit) {
                if let Ok(entry) = serde_json::from_value::<AuditEntry>(item.clone()) {
                    entries.push(entry);
                }
            }
        }
        Value::Object(map) => {
            for (_key, val) in map.iter().take(limit) {
                if let Ok(entry) = serde_json::from_value::<AuditEntry>(val.clone()) {
                    entries.push(entry);
                }
            }
        }
        _ => {}
    }

    Ok(entries)
}

pub fn parse_duration(s: &str) -> Result<chrono::Duration> {
    let s = s.trim();
    if s.len() < 2 {
        bail!("invalid duration: {s}");
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .with_context(|| format!("invalid duration number: {num_str}"))?;

    match unit {
        "m" => Ok(chrono::Duration::minutes(num)),
        "h" => Ok(chrono::Duration::hours(num)),
        "d" => Ok(chrono::Duration::days(num)),
        _ => bail!("unknown duration unit: {unit} (use m, h, or d)"),
    }
}

pub fn parse_filter_args(args: &[String]) -> Result<AuditFilter> {
    let mut filter = AuditFilter::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                if i + 1 >= args.len() {
                    bail!("--limit requires a value");
                }
                filter.limit = args[i + 1].parse().context("invalid --limit value")?;
                i += 2;
            }
            "--server" => {
                if i + 1 >= args.len() {
                    bail!("--server requires a value");
                }
                filter.server = Some(args[i + 1].clone());
                i += 2;
            }
            "--tool" => {
                if i + 1 >= args.len() {
                    bail!("--tool requires a value");
                }
                filter.tool = Some(args[i + 1].clone());
                i += 2;
            }
            "--method" => {
                if i + 1 >= args.len() {
                    bail!("--method requires a value");
                }
                filter.method = Some(args[i + 1].clone());
                i += 2;
            }
            "--identity" => {
                if i + 1 >= args.len() {
                    bail!("--identity requires a value");
                }
                filter.identity = Some(args[i + 1].clone());
                i += 2;
            }
            "--errors" => {
                filter.errors_only = true;
                i += 1;
            }
            "--since" => {
                if i + 1 >= args.len() {
                    bail!("--since requires a value");
                }
                filter.since = Some(parse_duration(&args[i + 1])?);
                i += 2;
            }
            "-f" => {
                filter.follow = true;
                i += 1;
            }
            other => bail!("unknown flag: {other}"),
        }
    }
    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_entry() -> AuditEntry {
        AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "serve:http".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("sentry__search_issues".to_string()),
            server_name: Some("sentry".to_string()),
            identity: "alice".to_string(),
            duration_ms: 142,
            success: true,
            error_message: None,
            arguments: None,
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        }
    }

    fn sample_error_entry() -> AuditEntry {
        AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("github__search_repos".to_string()),
            server_name: Some("github".to_string()),
            identity: "local".to_string(),
            duration_ms: 234,
            success: false,
            error_message: Some("connection timeout".to_string()),
            arguments: None,
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        }
    }

    // --- AuditEntry serialization ---

    #[test]
    fn test_audit_entry_serialization() {
        let entry = sample_entry();
        let json = serde_json::to_value(&entry).unwrap();
        let back: AuditEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.source, "serve:http");
        assert_eq!(back.method, "tools/call");
        assert_eq!(back.tool_name, Some("sentry__search_issues".to_string()));
        assert!(back.success);
    }

    #[test]
    fn test_audit_entry_key_format() {
        let ts = Utc::now().timestamp_millis();
        let id = uuid::Uuid::new_v4();
        let key = format!("audit:{ts}-{id}");
        assert!(key.starts_with("audit:"));
        assert!(key.contains('-'));
    }

    // --- AuditEntry::detail ---

    #[test]
    fn test_detail_with_query() {
        let mut entry = sample_entry();
        entry.arguments = Some(json!({"query": "filesystem"}));
        assert_eq!(entry.detail(), "query=filesystem");
    }

    #[test]
    fn test_detail_with_url() {
        let mut entry = sample_entry();
        entry.arguments = Some(json!({"url": "https://example.com/mcp"}));
        assert_eq!(entry.detail(), "url=https://example.com/mcp");
    }

    #[test]
    fn test_detail_with_from() {
        let mut entry = sample_entry();
        entry.arguments = Some(json!({"from": "registry"}));
        assert_eq!(entry.detail(), "from=registry");
    }

    #[test]
    fn test_detail_no_arguments() {
        let entry = sample_entry();
        assert_eq!(entry.detail(), "-");
    }

    #[test]
    fn test_detail_error_entry_no_arguments() {
        let entry = sample_error_entry();
        assert_eq!(entry.detail(), "connection timeout");
    }

    #[test]
    fn test_detail_error_long_message_truncated() {
        let mut entry = sample_error_entry();
        entry.error_message = Some(
            "MCP error -32602: Invalid arguments for tool search_issues: [\n  {\n    \"code\": \"invalid_type\"\n  }\n]".to_string()
        );
        let detail = entry.detail();
        assert!(!detail.contains('\n'));
        assert!(detail.starts_with("MCP error -32602:"));
    }

    #[test]
    fn test_truncate_error_first_line() {
        assert_eq!(
            super::truncate_error("first line\nsecond line\nthird"),
            "first line"
        );
    }

    #[test]
    fn test_truncate_error_strips_trailing_bracket() {
        assert_eq!(
            super::truncate_error("Invalid arguments: ["),
            "Invalid arguments:"
        );
    }

    #[test]
    fn test_truncate_error_short_message() {
        assert_eq!(
            super::truncate_error("connection timeout"),
            "connection timeout"
        );
    }

    // --- AuditConfig ---

    #[test]
    fn test_audit_config_defaults() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert!(config.path.is_none());
        assert!(config.index_path.is_none());
        assert!(!config.log_arguments);
        assert_eq!(config.output, AuditOutput::File);
    }

    #[test]
    fn test_audit_config_deserialize() {
        let json = json!({
            "enabled": false,
            "path": "/tmp/audit/data",
            "index_path": "/tmp/audit/index",
            "log_arguments": true
        });
        let config: AuditConfig = serde_json::from_value(json).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.path.unwrap(), "/tmp/audit/data");
        assert_eq!(config.index_path.unwrap(), "/tmp/audit/index");
        assert!(config.log_arguments);
        // Backward compat: missing output field defaults to File
        assert_eq!(config.output, AuditOutput::File);
    }

    #[test]
    fn test_audit_config_output_stdout() {
        let json = json!({
            "enabled": true,
            "output": "stdout"
        });
        let config: AuditConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.output, AuditOutput::Stdout);
    }

    #[test]
    fn test_audit_config_output_none() {
        let json = json!({
            "enabled": true,
            "output": "none"
        });
        let config: AuditConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.output, AuditOutput::None);
    }

    #[test]
    fn test_audit_output_serialization() {
        assert_eq!(
            serde_json::to_string(&AuditOutput::Stdout).unwrap(),
            "\"stdout\""
        );
        assert_eq!(
            serde_json::to_string(&AuditOutput::File).unwrap(),
            "\"file\""
        );
    }

    // --- Disabled logger ---

    #[test]
    fn test_disabled_logger_noop() {
        let logger = AuditLogger::Disabled;
        // Should not panic
        logger.log(sample_entry());
        let entries = logger.query_recent(10).unwrap();
        assert!(entries.is_empty());
    }

    // --- AuditFilter ---

    #[test]
    fn test_audit_filter_defaults() {
        let filter = AuditFilter::default();
        assert_eq!(filter.limit, 50);
        assert!(filter.server.is_none());
        assert!(filter.tool.is_none());
        assert!(filter.method.is_none());
        assert!(filter.identity.is_none());
        assert!(!filter.errors_only);
        assert!(filter.since.is_none());
        assert!(!filter.follow);
    }

    #[test]
    fn test_audit_filter_matches_errors_only() {
        let filter = AuditFilter {
            errors_only: true,
            ..AuditFilter::default()
        };
        assert!(!filter.matches(&sample_entry())); // success=true → filtered out
        assert!(filter.matches(&sample_error_entry())); // success=false → passes
    }

    #[test]
    fn test_audit_filter_matches_server() {
        let filter = AuditFilter {
            server: Some("sentry".to_string()),
            ..AuditFilter::default()
        };
        assert!(filter.matches(&sample_entry())); // server_name="sentry" → prefix match
        assert!(!filter.matches(&sample_error_entry())); // server_name="github" → no match
    }

    #[test]
    fn test_audit_filter_matches_tool() {
        let filter = AuditFilter {
            tool: Some("sentry__".to_string()),
            ..AuditFilter::default()
        };
        assert!(filter.matches(&sample_entry())); // tool starts with "sentry__"
        assert!(!filter.matches(&sample_error_entry())); // tool starts with "github__"
    }

    #[test]
    fn test_audit_filter_matches_method() {
        let filter = AuditFilter {
            method: Some("tools/call".to_string()),
            ..AuditFilter::default()
        };
        assert!(filter.matches(&sample_entry()));

        let filter_list = AuditFilter {
            method: Some("tools/list".to_string()),
            ..AuditFilter::default()
        };
        assert!(!filter_list.matches(&sample_entry()));
    }

    #[test]
    fn test_audit_filter_matches_identity() {
        let filter = AuditFilter {
            identity: Some("alice".to_string()),
            ..AuditFilter::default()
        };
        assert!(filter.matches(&sample_entry())); // identity="alice"
        assert!(!filter.matches(&sample_error_entry())); // identity="local"
    }

    #[test]
    fn test_audit_filter_matches_all_pass() {
        let filter = AuditFilter {
            server: Some("sentry".to_string()),
            tool: Some("sentry__search".to_string()),
            method: Some("tools/call".to_string()),
            identity: Some("alice".to_string()),
            ..AuditFilter::default()
        };
        assert!(filter.matches(&sample_entry()));
    }

    // --- parse_filter_args ---

    #[test]
    fn test_parse_filter_args_empty() {
        let args: Vec<String> = vec![];
        let filter = parse_filter_args(&args).unwrap();
        assert_eq!(filter.limit, 50);
        assert!(!filter.errors_only);
        assert!(!filter.follow);
    }

    #[test]
    fn test_parse_filter_args_limit() {
        let args: Vec<String> = vec!["--limit".into(), "100".into()];
        let filter = parse_filter_args(&args).unwrap();
        assert_eq!(filter.limit, 100);
    }

    #[test]
    fn test_parse_filter_args_errors() {
        let args: Vec<String> = vec!["--errors".into()];
        let filter = parse_filter_args(&args).unwrap();
        assert!(filter.errors_only);
    }

    #[test]
    fn test_parse_filter_args_combined() {
        let args: Vec<String> = vec![
            "--server".into(),
            "sentry".into(),
            "--errors".into(),
            "--limit".into(),
            "10".into(),
        ];
        let filter = parse_filter_args(&args).unwrap();
        assert_eq!(filter.server, Some("sentry".to_string()));
        assert!(filter.errors_only);
        assert_eq!(filter.limit, 10);
    }

    #[test]
    fn test_parse_filter_args_unknown_flag() {
        let args: Vec<String> = vec!["--bogus".into()];
        assert!(parse_filter_args(&args).is_err());
    }

    #[test]
    fn test_parse_filter_args_follow() {
        let args: Vec<String> = vec!["-f".into()];
        let filter = parse_filter_args(&args).unwrap();
        assert!(filter.follow);
    }

    // --- parse_duration ---

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("5m").unwrap();
        assert_eq!(d, chrono::Duration::minutes(5));
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("1h").unwrap();
        assert_eq!(d, chrono::Duration::hours(1));
    }

    #[test]
    fn test_parse_duration_days() {
        let d = parse_duration("7d").unwrap();
        assert_eq!(d, chrono::Duration::days(7));
    }

    // --- parse_entries_from_list ---

    #[test]
    fn test_parse_entries_from_array() {
        let entry = sample_entry();
        let val = serde_json::to_value(&entry).unwrap();
        let arr = Value::Array(vec![val]);
        let entries = parse_entries_from_list(&arr, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, "serve:http");
    }

    #[test]
    fn test_parse_entries_from_object() {
        let entry = sample_entry();
        let val = serde_json::to_value(&entry).unwrap();
        let mut map = serde_json::Map::new();
        map.insert("audit:123-uuid".to_string(), val);
        let obj = Value::Object(map);
        let entries = parse_entries_from_list(&obj, 10).unwrap();
        assert_eq!(entries.len(), 1);
    }

    // --- ACL enrichment tests (issue #56) ---

    #[test]
    fn test_audit_acl_fields_serialized_when_set() {
        let mut entry = sample_entry();
        entry.acl_decision = Some("deny".to_string());
        entry.acl_matched_rule = Some("dev[1]".to_string());
        entry.acl_access_kind = Some("write".to_string());
        entry.classification_kind = Some("write".to_string());
        entry.classification_source = Some("classifier".to_string());
        entry.classification_confidence = Some(0.81);

        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["acl_decision"], "deny");
        assert_eq!(json["acl_matched_rule"], "dev[1]");
        assert_eq!(json["acl_access_kind"], "write");
        assert_eq!(json["classification_kind"], "write");
        assert_eq!(json["classification_source"], "classifier");
        assert!((json["classification_confidence"].as_f64().unwrap() - 0.81).abs() < 0.01);
    }

    #[test]
    fn test_audit_acl_fields_omitted_when_none() {
        let entry = sample_entry();
        let json = serde_json::to_value(&entry).unwrap();
        let obj = json.as_object().unwrap();
        // ACL fields should be absent (not null) when None
        assert!(!obj.contains_key("acl_decision"));
        assert!(!obj.contains_key("acl_matched_rule"));
        assert!(!obj.contains_key("acl_access_kind"));
        assert!(!obj.contains_key("classification_kind"));
        assert!(!obj.contains_key("classification_source"));
        assert!(!obj.contains_key("classification_confidence"));
    }

    #[test]
    fn test_audit_backwards_compat_deser() {
        // Old JSON without ACL fields should deserialize with None values
        let old_json = json!({
            "timestamp": "2026-03-16T18:30:00Z",
            "source": "serve:http",
            "method": "tools/call",
            "tool_name": "sentry__search_issues",
            "server_name": "sentry",
            "identity": "alice",
            "duration_ms": 142,
            "success": true,
            "error_message": null
        });
        let entry: AuditEntry = serde_json::from_value(old_json).unwrap();
        assert!(entry.acl_decision.is_none());
        assert!(entry.acl_matched_rule.is_none());
        assert!(entry.acl_access_kind.is_none());
        assert!(entry.classification_kind.is_none());
        assert!(entry.classification_source.is_none());
        assert!(entry.classification_confidence.is_none());
    }
}
