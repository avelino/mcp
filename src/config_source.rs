//! Source-preserving view of `servers.json`.
//!
//! Why this exists at all: the two existing ways to touch the config are both
//! lossy for a UI.
//!
//! `config::load_config` expands `${VAR}` **before** parsing (`src/config.rs`),
//! so the value it hands back has already replaced the placeholders with the
//! secrets they pointed at. Writing that value back would either bake the
//! secrets into the file or blank them out when the variable is unset.
//!
//! `manager::add/remove/update` re-serialise the whole document with
//! `to_string_pretty`, which drops every comment and reorders keys.
//!
//! So this module keeps the raw text, edits it through a concrete syntax tree
//! that preserves comments and formatting, and writes it back atomically with
//! a backup and an optimistic-concurrency check.

use anyhow::{bail, Context, Result};
use jsonc_parser::cst::{CstInputValue, CstObject, CstRootNode};
use jsonc_parser::ParseOptions;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::config;

/// Pseudo-source reported when the config comes from `MCP_SERVERS_CONFIG`.
pub const INLINE_SOURCE: &str = "<env:MCP_SERVERS_CONFIG>";

/// Where the document came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A real file on disk. It may not exist yet; the first write creates it.
    File(PathBuf),
    /// Loaded from `MCP_SERVERS_CONFIG`. There is no canonical file to write.
    Inline,
}

/// A config document as it sits on disk: raw text, no `${VAR}` expansion.
#[derive(Debug, Clone)]
pub struct ConfigSource {
    origin: Origin,
    text: String,
}

impl ConfigSource {
    /// Resolves the source the same way `config::load_config` does, but keeps
    /// the bytes untouched.
    pub fn load() -> Result<Self> {
        if let Ok(raw) = std::env::var("MCP_SERVERS_CONFIG") {
            return Ok(Self::from_text(raw, Origin::Inline));
        }
        let path = config::config_path()?;
        Self::from_path(path)
    }

    pub fn from_path(path: PathBuf) -> Result<Self> {
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(e).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        Ok(Self {
            origin: Origin::File(path),
            text,
        })
    }

    pub fn from_text(text: impl Into<String>, origin: Origin) -> Self {
        Self {
            origin,
            text: text.into(),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn path(&self) -> Option<&Path> {
        match &self.origin {
            Origin::File(p) => Some(p),
            Origin::Inline => None,
        }
    }

    /// Whether `apply` may write this document at all.
    pub fn is_writable(&self) -> bool {
        matches!(self.origin, Origin::File(_))
    }

    /// Human-readable reason the document is read-only, for the UI to show
    /// instead of silently disabling buttons.
    pub fn read_only_reason(&self) -> Option<&'static str> {
        match self.origin {
            Origin::Inline => Some(
                "config is inline in MCP_SERVERS_CONFIG — there is no file to write. \
                 Edit the manifest that sets it and restart.",
            ),
            Origin::File(_) => None,
        }
    }

    /// SHA-256 of the exact bytes, used as the ETag for optimistic concurrency.
    pub fn hash(&self) -> String {
        sha256_hex(&self.text)
    }

    /// The document parsed as JSON (comments skipped). Missing or empty files
    /// read as an empty object.
    pub fn parsed(&self) -> Result<Value> {
        parse_jsonc(&self.text)
    }

    /// Configured servers with `${VAR}` still literal.
    pub fn servers(&self) -> Result<Vec<(String, Value)>> {
        let value = self.parsed()?;
        let servers = match value.get("mcpServers") {
            Some(Value::Object(map)) => map,
            Some(_) => bail!("\"mcpServers\" is not an object"),
            None => return Ok(Vec::new()),
        };
        Ok(servers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    pub fn server(&self, name: &str) -> Result<Option<Value>> {
        Ok(self
            .servers()?
            .into_iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value))
    }

    /// Replaces a whole server entry, or appends it when absent.
    pub fn set_server(&self, name: &str, server: &Value) -> Result<String> {
        check_name(name)?;
        let root = self.parse_cst()?;
        let servers = servers_object(&root);
        let value = to_input(server);
        match servers.get(name) {
            Some(prop) => prop.set_value(value),
            None => {
                servers.append(name, value);
            }
        }
        Ok(root.to_string())
    }

    pub fn remove_server(&self, name: &str) -> Result<String> {
        let root = self.parse_cst()?;
        if let Some(servers) = existing_servers(&root) {
            if let Some(prop) = servers.get(name) {
                prop.remove();
            }
        }
        Ok(root.to_string())
    }

    /// Sets one field inside a server, leaving every other byte untouched.
    pub fn set_server_field(&self, name: &str, key: &str, value: &Value) -> Result<String> {
        check_name(key)?;
        let root = self.parse_cst()?;
        let servers = existing_servers(&root).context("config has no \"mcpServers\" object")?;
        let server = servers
            .object_value(name)
            .or_else(|| servers.get(name).map(|p| p.object_value_or_set()))
            .context(format!("server \"{name}\" not found or not an object"))?;
        let value = to_input(value);
        match server.get(key) {
            Some(prop) => prop.set_value(value),
            None => {
                server.append(key, value);
            }
        }
        Ok(root.to_string())
    }

    pub fn remove_server_field(&self, name: &str, key: &str) -> Result<String> {
        let root = self.parse_cst()?;
        let servers = existing_servers(&root).context("config has no \"mcpServers\" object")?;
        if let Some(server) = servers.get(name).and_then(|p| p.object_value()) {
            if let Some(prop) = server.get(key) {
                prop.remove();
            }
        }
        Ok(root.to_string())
    }

    /// Applies field-level edits one key at a time.
    ///
    /// Field-level edits are what keep comments inside the untouched parts of
    /// the entry alive: only the changed lines are rewritten.
    pub fn patch_server(&self, name: &str, ops: &[(String, Option<Value>)]) -> Result<String> {
        let mut text = self.text().to_string();
        for (key, value) in ops {
            let view = ConfigSource {
                origin: self.origin.clone(),
                text,
            };
            text = match value {
                Some(value) => view.set_server_field(name, key, value)?,
                None => view.remove_server_field(name, key)?,
            };
        }
        Ok(text)
    }

    /// Validates the document against the real config schema.
    pub fn validate(&self, text: &str) -> Result<config::Config> {
        let source = self
            .path()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(INLINE_SOURCE));
        config::validate_config_text(text, source)
    }

    /// Writes `text` back, refusing if the file changed since this view was
    /// produced. Returns the backup path when a previous file existed.
    pub fn apply(&self, text: &str) -> Result<Applied> {
        let path = match &self.origin {
            Origin::File(path) => path.clone(),
            Origin::Inline => bail!("{}", self.read_only_reason().unwrap_or("read-only")),
        };
        self.validate(text)?;
        write_atomic(&path, text, Some(&self.hash()))
    }

    fn parse_cst(&self) -> Result<CstRootNode> {
        if self.text.trim().is_empty() {
            return CstRootNode::parse("{}", &ParseOptions::default())
                .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"));
        }
        CstRootNode::parse(&self.text, &ParseOptions::default())
            .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))
    }
}

/// Result of a successful `apply`.
#[derive(Debug, Clone)]
pub struct Applied {
    pub backup: Option<PathBuf>,
}

/// Writes `text` to `path` atomically, replacing the file only if its current
/// content hashes to `expected` (when given).
///
/// The sequence matters: a temp file in the same directory, flushed and
/// fsynced, renamed over the target, then the directory fsynced. A crash
/// leaves either the old file or the new one — never a truncated config.
pub fn write_atomic(path: &Path, text: &str, expected: Option<&str>) -> Result<Applied> {
    use std::io::Write;

    if let Some(expected) = expected {
        let current = std::fs::read_to_string(path).unwrap_or_default();
        let current_hash = sha256_hex(&current);
        if current_hash != expected {
            bail!(Conflict {
                expected: expected.to_string(),
                current: current_hash,
            });
        }
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }

    let backup = if path.exists() {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let backup = path.with_extension(format!("json.bak.{stamp}"));
        std::fs::copy(path, &backup)
            .with_context(|| format!("failed to write backup {}", backup.display()))?;
        Some(backup)
    } else {
        None
    };

    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("failed to create {}", tmp.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush {}", tmp.display()))?;
    drop(file);

    std::fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))?;

    // Durability of the rename itself. Best effort: a filesystem that refuses
    // directory fsync (or a platform without it) must not fail the write.
    if let Some(dir) = path.parent() {
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }

    Ok(Applied { backup })
}

/// The file changed underneath us: the caller must re-read and re-diff.
#[derive(Debug)]
pub struct Conflict {
    pub expected: String,
    pub current: String,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "config changed on disk (expected {}, found {})",
            &self.expected[..8.min(self.expected.len())],
            &self.current[..8.min(self.current.len())]
        )
    }
}

impl std::error::Error for Conflict {}

/// True when the error is a concurrency conflict (mapped to HTTP 409 upstream).
pub fn is_conflict(err: &anyhow::Error) -> bool {
    err.is::<Conflict>()
}

pub fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_jsonc(text: &str) -> Result<Value> {
    if text.trim().is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    let parsed = jsonc_parser::parse_to_ast(
        text,
        &jsonc_parser::CollectOptions::default(),
        &ParseOptions::default(),
    )
    .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
    parsed.value.map(Value::from).context("config is empty")
}

fn servers_object(root: &CstRootNode) -> CstObject {
    root.object_value_or_set().object_value_or_set("mcpServers")
}

fn existing_servers(root: &CstRootNode) -> Option<CstObject> {
    root.object_value()
        .and_then(|o| o.object_value("mcpServers"))
}

/// A key that is safe to emit as a JSON object property.
///
/// The CST writer quotes names itself, but rejecting control characters and an
/// empty name early keeps an invalid entry from ever being written.
fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("server name must not be empty");
    }
    if name.chars().any(|c| c.is_control()) {
        bail!("server name must not contain control characters");
    }
    Ok(())
}

fn to_input(value: &Value) -> CstInputValue {
    match value {
        Value::Null => CstInputValue::Null,
        Value::Bool(b) => CstInputValue::Bool(*b),
        Value::Number(n) => CstInputValue::Number(n.to_string()),
        Value::String(s) => CstInputValue::String(s.clone()),
        Value::Array(items) => CstInputValue::Array(items.iter().map(to_input).collect()),
        Value::Object(map) => {
            CstInputValue::Object(map.iter().map(|(k, v)| (k.clone(), to_input(v))).collect())
        }
    }
}

/// Line-by-line unified diff with `context` lines around each change.
///
/// Config files are small (a few hundred lines at most) and edits are
/// surgical, so the quadratic LCS below is the right trade: no dependency, and
/// the output is what `git diff` would show for the same change.
pub fn unified_diff(old: &str, new: &str, context: usize) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    // LCS table over line indices.
    let n = old_lines.len();
    let m = new_lines.len();
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old_lines[i] == new_lines[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    #[derive(PartialEq)]
    enum Op<'a> {
        Same(&'a str),
        Del(&'a str),
        Add(&'a str),
    }
    let mut ops: Vec<Op> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old_lines[i] == new_lines[j] {
            ops.push(Op::Same(old_lines[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            ops.push(Op::Del(old_lines[i]));
            i += 1;
        } else {
            ops.push(Op::Add(new_lines[j]));
            j += 1;
        }
    }
    while i < n {
        ops.push(Op::Del(old_lines[i]));
        i += 1;
    }
    while j < m {
        ops.push(Op::Add(new_lines[j]));
        j += 1;
    }

    // Mark which ops are near a change.
    let changed: Vec<bool> = ops.iter().map(|o| !matches!(o, Op::Same(_))).collect();
    let mut keep = vec![false; ops.len()];
    for (idx, is_change) in changed.iter().enumerate() {
        if *is_change {
            let start = idx.saturating_sub(context);
            let end = (idx + context).min(ops.len().saturating_sub(1));
            for slot in &mut keep[start..=end] {
                *slot = true;
            }
        }
    }

    if !keep.iter().any(|k| *k) {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("--- a\n+++ b\n");

    let mut idx = 0;
    while idx < ops.len() {
        if !keep[idx] {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < ops.len() && keep[idx] {
            idx += 1;
        }
        let hunk = &ops[start..idx];
        let old_start = ops[..start]
            .iter()
            .filter(|o| !matches!(o, Op::Add(_)))
            .count()
            + 1;
        let new_start = ops[..start]
            .iter()
            .filter(|o| !matches!(o, Op::Del(_)))
            .count()
            + 1;
        let old_len = hunk.iter().filter(|o| !matches!(o, Op::Add(_))).count();
        let new_len = hunk.iter().filter(|o| !matches!(o, Op::Del(_))).count();
        out.push_str(&format!(
            "@@ -{old_start},{old_len} +{new_start},{new_len} @@\n"
        ));
        for op in hunk {
            match op {
                Op::Same(line) => out.push_str(&format!(" {line}\n")),
                Op::Del(line) => out.push_str(&format!("-{line}\n")),
                Op::Add(line) => out.push_str(&format!("+{line}\n")),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE: &str = r#"{
  // Sentry is the busiest backend; keep it warm.
  "mcpServers": {
    "sentry": {
      "url": "https://mcp.sentry.dev/sse",
      "headers": { "Authorization": "Bearer ${SENTRY_TOKEN}" },
      "idle_timeout": "never"
    },
    "slack": {
      /* stale comment that must survive */
      "command": "npx",
      "args": ["-y", "slack-mcp-server@latest"],
      "env": { "SLACK_MCP_XOXP_TOKEN": "${SLACK_TOKEN}" }
    }
  },
  "audit": { "enabled": true }
}
"#;

    fn source(text: &str) -> ConfigSource {
        ConfigSource::from_text(text, Origin::File(PathBuf::from("/tmp/test-servers.json")))
    }

    #[test]
    fn reads_servers_with_placeholders_intact() {
        let src = source(SAMPLE);
        let servers = src.servers().unwrap();
        assert_eq!(servers.len(), 2);
        let sentry = src.server("sentry").unwrap().unwrap();
        assert_eq!(
            sentry["headers"]["Authorization"],
            json!("Bearer ${SENTRY_TOKEN}")
        );
    }

    #[test]
    fn changing_a_field_keeps_comments_and_bytes_around_it() {
        let src = source(SAMPLE);
        let out = src
            .set_server_field("sentry", "idle_timeout", &json!("adaptive"))
            .unwrap();

        assert!(out.contains("// Sentry is the busiest backend"));
        assert!(out.contains("/* stale comment that must survive */"));
        assert!(out.contains("${SENTRY_TOKEN}"));
        assert!(out.contains("\"idle_timeout\": \"adaptive\""));
        assert!(!out.contains("\"never\""));

        // Everything except the changed literal is byte-identical.
        let before: Vec<&str> = SAMPLE.lines().collect();
        let after: Vec<&str> = out.lines().collect();
        assert_eq!(before.len(), after.len());
        let differing: Vec<usize> = (0..before.len())
            .filter(|i| before[*i] != after[*i])
            .collect();
        assert_eq!(differing.len(), 1, "only the edited line changed");
    }

    #[test]
    fn adding_a_field_inserts_inside_the_server_object() {
        let src = source(SAMPLE);
        let out = src
            .set_server_field("sentry", "idle_timeout", &json!("never"))
            .unwrap();
        assert!(out.contains("\"idle_timeout\": \"never\""));

        let out = src
            .set_server_field("sentry", "min_idle_timeout", &json!("30s"))
            .unwrap();
        assert!(out.contains("\"min_idle_timeout\": \"30s\""));
        assert!(out.contains("// Sentry is the busiest backend"));
    }

    #[test]
    fn removing_a_field_keeps_the_document_valid() {
        let src = source(SAMPLE);
        let out = src.remove_server_field("sentry", "idle_timeout").unwrap();
        assert!(!out.contains("idle_timeout"));
        let parsed = parse_jsonc(&out).unwrap();
        assert!(parsed["mcpServers"]["sentry"]["url"].is_string());
    }

    #[test]
    fn adding_a_server_appends_it() {
        let src = source(SAMPLE);
        let out = src
            .set_server(
                "github",
                &json!({ "url": "https://api.githubcopilot.com/mcp/" }),
            )
            .unwrap();
        let parsed = parse_jsonc(&out).unwrap();
        assert_eq!(
            parsed["mcpServers"]["github"]["url"],
            json!("https://api.githubcopilot.com/mcp/")
        );
        assert!(out.contains("// Sentry is the busiest backend"));
    }

    #[test]
    fn removing_a_server_drops_only_that_entry() {
        let src = source(SAMPLE);
        let out = src.remove_server("slack").unwrap();
        let parsed = parse_jsonc(&out).unwrap();
        assert!(parsed["mcpServers"].get("slack").is_none());
        assert!(parsed["mcpServers"].get("sentry").is_some());
        assert!(!out.contains("stale comment"));
    }

    #[test]
    fn empty_file_yields_an_empty_server_map() {
        let src = source("");
        assert!(src.servers().unwrap().is_empty());
        let out = src
            .set_server("sentry", &json!({ "url": "https://example.com" }))
            .unwrap();
        let parsed = parse_jsonc(&out).unwrap();
        assert_eq!(
            parsed["mcpServers"]["sentry"]["url"],
            json!("https://example.com")
        );
    }

    #[test]
    fn inline_config_is_not_writable() {
        let src = ConfigSource::from_text("{}", Origin::Inline);
        assert!(!src.is_writable());
        assert!(src.read_only_reason().is_some());
        assert!(src.apply("{}").is_err());
    }

    #[test]
    fn rejects_pathological_names() {
        let src = source(SAMPLE);
        assert!(src.set_server("", &json!({})).is_err());
        assert!(src.set_server("bad\nname", &json!({})).is_err());
    }

    #[test]
    fn validation_accepts_comments_and_rejects_broken_schema() {
        let src = source(SAMPLE);
        let cfg = src.validate(SAMPLE).unwrap();
        assert_eq!(cfg.servers.len(), 2);

        let broken = SAMPLE.replace("\"url\": \"https://mcp.sentry.dev/sse\"", "\"nope\": 1");
        assert!(src.validate(&broken).is_err());
    }

    #[test]
    fn write_is_atomic_and_detects_concurrency_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers.json");
        std::fs::write(&path, "{\"mcpServers\":{}}\n").unwrap();

        let src = ConfigSource::from_path(path.clone()).unwrap();
        let next = src
            .set_server("sentry", &json!({ "url": "https://example.com" }))
            .unwrap();
        let applied = src.apply(&next).unwrap();
        assert!(applied.backup.is_some());
        assert!(std::fs::read_to_string(&path).unwrap().contains("sentry"));

        // A second apply from the stale view must not clobber the first.
        let err = src.apply(&next).unwrap_err();
        assert!(is_conflict(&err), "expected conflict, got {err}");
    }

    #[test]
    fn write_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers.json");
        let src = ConfigSource::from_path(path.clone()).unwrap();
        src.apply("{\"mcpServers\":{}}\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn diff_reports_only_the_changed_region() {
        let old = "{\n  \"a\": 1,\n  \"b\": 2\n}\n";
        let new = "{\n  \"a\": 1,\n  \"b\": 3\n}\n";
        let diff = unified_diff(old, new, 1);
        assert!(diff.contains("-  \"b\": 2"));
        assert!(diff.contains("+  \"b\": 3"));
        assert!(diff.contains("   \"a\": 1"));
        assert!(!diff.contains("+  \"a\": 1"));
    }

    #[test]
    fn diff_is_empty_when_nothing_changed() {
        assert!(unified_diff("{\"a\":1}\n", "{\"a\":1}\n", 3).is_empty());
    }
}
