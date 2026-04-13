use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::audit::AuditConfig;
use crate::server_auth::ServerAuthConfig;

const RESERVED_NAMES: &[&str] = &[
    "search", "add", "remove", "list", "help", "version", "serve", "logs",
];

#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdleTimeoutPolicy {
    #[default]
    Adaptive,
    Never,
    #[serde(untagged)]
    Fixed(String),
}

pub fn parse_duration_str(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>().ok().map(|n| Duration::from_secs(n * 3600))
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>().ok().map(|n| Duration::from_secs(n * 60))
    } else if let Some(n) = s.strip_suffix('s') {
        n.parse::<u64>().ok().map(Duration::from_secs)
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

pub const DEFAULT_MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Per-server manual classification overrides for tools.
/// Glob patterns follow the same syntax as `server_auth::acl::glob_match`.
/// Both fields are optional; if a tool name matches an override glob, the
/// classifier is bypassed for it. A tool name matching **both** `read` and
/// `write` is a configuration error and is rejected at load time.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ToolOverrides {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CliToolConfig {
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ServerConfig {
    // Cli must come before Stdio: both have `command`, but Cli requires `cli: true`.
    // With untagged enums serde tries variants in order; Cli fails when `cli` is absent,
    // falling through to Stdio.
    Cli {
        command: String,
        cli: bool,
        #[serde(default = "default_cli_help")]
        cli_help: String,
        #[serde(default = "default_cli_depth")]
        cli_depth: u8,
        #[serde(default)]
        cli_only: Vec<String>,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        tools: Vec<CliToolConfig>,
        #[serde(default)]
        tool_acl: Option<ToolOverrides>,
        #[serde(default)]
        idle_timeout: IdleTimeoutPolicy,
        #[serde(default)]
        min_idle_timeout: Option<String>,
        #[serde(default)]
        max_idle_timeout: Option<String>,
    },
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        tool_acl: Option<ToolOverrides>,
        #[serde(default)]
        idle_timeout: IdleTimeoutPolicy,
        #[serde(default)]
        min_idle_timeout: Option<String>,
        #[serde(default)]
        max_idle_timeout: Option<String>,
    },
    Http {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        tool_acl: Option<ToolOverrides>,
        #[serde(default)]
        idle_timeout: IdleTimeoutPolicy,
        #[serde(default)]
        min_idle_timeout: Option<String>,
        #[serde(default)]
        max_idle_timeout: Option<String>,
    },
}

fn default_cli_help() -> String {
    "--help".to_string()
}

fn default_cli_depth() -> u8 {
    2
}

impl ServerConfig {
    pub fn idle_timeout_policy(&self) -> &IdleTimeoutPolicy {
        match self {
            ServerConfig::Cli { idle_timeout, .. } => idle_timeout,
            ServerConfig::Stdio { idle_timeout, .. } => idle_timeout,
            ServerConfig::Http { idle_timeout, .. } => idle_timeout,
        }
    }

    pub fn min_idle_timeout(&self) -> Duration {
        let raw = match self {
            ServerConfig::Cli {
                min_idle_timeout, ..
            } => min_idle_timeout.as_deref(),
            ServerConfig::Stdio {
                min_idle_timeout, ..
            } => min_idle_timeout.as_deref(),
            ServerConfig::Http {
                min_idle_timeout, ..
            } => min_idle_timeout.as_deref(),
        };
        raw.and_then(parse_duration_str)
            .unwrap_or(DEFAULT_MIN_IDLE_TIMEOUT)
    }

    pub fn tool_acl(&self) -> Option<&ToolOverrides> {
        match self {
            ServerConfig::Cli { tool_acl, .. } => tool_acl.as_ref(),
            ServerConfig::Stdio { tool_acl, .. } => tool_acl.as_ref(),
            ServerConfig::Http { tool_acl, .. } => tool_acl.as_ref(),
        }
    }

    pub fn max_idle_timeout(&self) -> Duration {
        let raw = match self {
            ServerConfig::Cli {
                max_idle_timeout, ..
            } => max_idle_timeout.as_deref(),
            ServerConfig::Stdio {
                max_idle_timeout, ..
            } => max_idle_timeout.as_deref(),
            ServerConfig::Http {
                max_idle_timeout, ..
            } => max_idle_timeout.as_deref(),
        };
        raw.and_then(parse_duration_str)
            .unwrap_or(DEFAULT_MAX_IDLE_TIMEOUT)
    }
}

#[derive(Debug)]
pub struct Config {
    pub servers: HashMap<String, ServerConfig>,
    pub server_auth: ServerAuthConfig,
    pub audit: AuditConfig,
    pub path: PathBuf,
    /// SHA-256 hex digest of each backend's raw config JSON, for cache invalidation.
    pub config_hashes: HashMap<String, String>,
}

/// Returns the MCP configuration directory.
/// Uses `MCP_CONFIG_DIR` if set, then `$HOME/.config/mcp`, then `/tmp/mcp` as
/// a last-resort fallback for containers without a home directory.
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("MCP_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join(".config").join("mcp"));
    }
    eprintln!("warning: HOME not set, using /tmp/mcp as config directory");
    Ok(PathBuf::from("/tmp/mcp"))
}

/// Returns the data path for the shared ChronDB database.
/// Falls back to legacy `audit/data` path for backward compatibility.
pub fn db_data_path() -> Result<String> {
    let dir = config_dir()?;
    let new_path = dir.join("db").join("data");
    if new_path.exists() {
        return Ok(new_path.to_string_lossy().to_string());
    }
    let legacy_path = dir.join("audit").join("data");
    if legacy_path.exists() {
        return Ok(legacy_path.to_string_lossy().to_string());
    }
    Ok(new_path.to_string_lossy().to_string())
}

/// Returns the index path for the shared ChronDB database.
/// Falls back to legacy `audit/index` path for backward compatibility.
pub fn db_index_path() -> Result<String> {
    let dir = config_dir()?;
    let new_path = dir.join("db").join("index");
    if new_path.exists() {
        return Ok(new_path.to_string_lossy().to_string());
    }
    let legacy_path = dir.join("audit").join("index");
    if legacy_path.exists() {
        return Ok(legacy_path.to_string_lossy().to_string());
    }
    Ok(new_path.to_string_lossy().to_string())
}

pub fn config_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("MCP_CONFIG_PATH") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("servers.json"))
}

/// Strip single-line (`//`) and multi-line (`/* */`) comments from JSON,
/// respecting string literals so that `"http://example.com"` is preserved.
fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'"' => {
                out.push('"');
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' && i + 1 < len {
                        out.push(bytes[i] as char);
                        out.push(bytes[i + 1] as char);
                        i += 2;
                    } else if bytes[i] == b'"' {
                        out.push('"');
                        i += 1;
                        break;
                    } else {
                        out.push(bytes[i] as char);
                        i += 1;
                    }
                }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'/' => {
                // Single-line comment: skip until end of line
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                // Multi-line comment: skip until */
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < len {
                    i += 2; // skip */
                }
            }
            _ => {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }

    out
}

pub fn load_config() -> Result<Config> {
    // Priority 1: inline config via MCP_SERVERS_CONFIG (no file mount needed)
    if let Ok(raw) = std::env::var("MCP_SERVERS_CONFIG") {
        return parse_config_content(&raw, PathBuf::from("<env:MCP_SERVERS_CONFIG>"));
    }
    // Priority 2: file path (existing behavior)
    let path = config_path()?;
    load_config_from_path(&path)
}

pub fn load_config_from_path(path: &PathBuf) -> Result<Config> {
    if !path.exists() {
        return Ok(Config {
            servers: HashMap::new(),
            server_auth: ServerAuthConfig::default(),
            audit: apply_audit_env_overrides(AuditConfig::default()),
            path: path.clone(),
            config_hashes: HashMap::new(),
        });
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    parse_config_content(&content, path.clone())
}

fn parse_config_content(content: &str, source: PathBuf) -> Result<Config> {
    let content = substitute_env_vars(content);
    let content = strip_json_comments(&content);

    let raw: Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse config from: {}", source.display()))?;

    let servers_value = raw
        .get("mcpServers")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    // Compute per-backend config hashes for cache invalidation
    let config_hashes: HashMap<String, String> = match servers_value.as_object() {
        Some(map) => {
            use sha2::{Digest, Sha256};
            map.iter()
                .map(|(name, val)| {
                    let json = serde_json::to_string(val).unwrap_or_default();
                    let hash = format!("{:x}", Sha256::digest(json.as_bytes()));
                    (name.clone(), hash)
                })
                .collect()
        }
        None => HashMap::new(),
    };

    let servers: HashMap<String, ServerConfig> =
        serde_json::from_value(servers_value).context("failed to parse mcpServers from config")?;

    for (name, config) in &servers {
        if let ServerConfig::Cli { cli, .. } = config {
            if !cli {
                anyhow::bail!(
                    "server '{name}': \"cli\" must be true (use a Stdio config without \"cli\" for MCP servers)"
                );
            }
        }
        if let Some(overrides) = config.tool_acl() {
            validate_tool_overrides(name, overrides)?;
        }
    }

    let server_auth: ServerAuthConfig = raw
        .get("serverAuth")
        .cloned()
        .map(|v| serde_json::from_value(v).context("failed to parse serverAuth from config"))
        .transpose()?
        .unwrap_or_default();

    let audit: AuditConfig = raw
        .get("audit")
        .cloned()
        .map(|v| serde_json::from_value(v).context("failed to parse audit from config"))
        .transpose()?
        .unwrap_or_default();

    // Apply environment variable overrides for container-friendly deployment
    let audit = apply_audit_env_overrides(audit);

    Ok(Config {
        servers,
        server_auth,
        audit,
        path: source,
        config_hashes,
    })
}

/// Returns the trimmed value of an env var, or `None` if unset or empty/whitespace.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// Applies environment variable overrides to `AuditConfig`.
/// Container deployments can use these to disable audit or redirect paths
/// without modifying the config JSON.
fn apply_audit_env_overrides(mut audit: AuditConfig) -> AuditConfig {
    if let Ok(v) = std::env::var("MCP_AUDIT_ENABLED") {
        match v.trim() {
            s if s.eq_ignore_ascii_case("false") || s == "0" => audit.enabled = false,
            s if s.eq_ignore_ascii_case("true") || s == "1" => audit.enabled = true,
            _ => {}
        }
    }
    if let Some(v) = non_empty_env("MCP_AUDIT_PATH") {
        audit.path = Some(v);
    }
    if let Some(v) = non_empty_env("MCP_AUDIT_INDEX_PATH") {
        audit.index_path = Some(v);
    }
    audit
}

fn substitute_env_vars(input: &str) -> String {
    let re = Regex::new(r"\$\{([^}]+)\}").unwrap();
    re.replace_all(input, |caps: &regex::Captures| {
        let var_name = &caps[1];
        std::env::var(var_name).unwrap_or_default()
    })
    .to_string()
}

/// Reject `tool_acl` configs where a single pattern (or one exactly equal
/// pattern) appears in both `read` and `write`. This catches the obvious
/// typo-class footgun at load time. Full cross-glob intersection analysis
/// isn't worth the complexity — the classifier runtime check below still
/// fires if a real tool name happens to match both lists.
fn validate_tool_overrides(
    server_name: &str,
    overrides: &crate::config::ToolOverrides,
) -> Result<()> {
    for r in &overrides.read {
        if overrides.write.iter().any(|w| w == r) {
            anyhow::bail!(
                "server '{server_name}': tool_acl pattern '{r}' appears in both 'read' and 'write'"
            );
        }
    }
    Ok(())
}

pub fn validate_server_names(config: &Config) -> Vec<String> {
    config
        .servers
        .keys()
        .filter(|name| RESERVED_NAMES.contains(&name.as_str()))
        .cloned()
        .collect()
}

pub fn is_reserved_name(name: &str) -> bool {
    RESERVED_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn config_from_json(json: &str) -> Result<Config> {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", json).unwrap();
        let path = file.path().to_path_buf();
        load_config_from_path(&path)
    }

    #[test]
    fn test_parse_stdio_server() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_TOKEN": "test123"}
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(config.servers.len(), 1);
        match &config.servers["github"] {
            ServerConfig::Stdio {
                command, args, env, ..
            } => {
                assert_eq!(command, "npx");
                assert_eq!(args.len(), 2);
                assert_eq!(env["GITHUB_TOKEN"], "test123");
            }
            _ => panic!("expected Stdio config"),
        }
    }

    #[test]
    fn test_parse_http_server() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "remote": {
                        "url": "https://example.com/mcp",
                        "headers": {"Authorization": "Bearer tok"}
                    }
                }
            }"#,
        )
        .unwrap();

        match &config.servers["remote"] {
            ServerConfig::Http { url, headers, .. } => {
                assert_eq!(url, "https://example.com/mcp");
                assert_eq!(headers["Authorization"], "Bearer tok");
            }
            _ => panic!("expected Http config"),
        }
    }

    #[test]
    fn test_env_var_substitution() {
        std::env::set_var("MCP_TEST_TOKEN", "secret123");
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": [],
                        "env": {"TOKEN": "${MCP_TEST_TOKEN}"}
                    }
                }
            }"#,
        )
        .unwrap();

        match &config.servers["github"] {
            ServerConfig::Stdio { env, .. } => {
                assert_eq!(env["TOKEN"], "secret123");
            }
            _ => panic!("expected Stdio config"),
        }
        std::env::remove_var("MCP_TEST_TOKEN");
    }

    #[test]
    fn test_missing_env_var_becomes_empty() {
        std::env::remove_var("MCP_NONEXISTENT_VAR");
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "test": {
                        "command": "echo",
                        "args": [],
                        "env": {"TOKEN": "${MCP_NONEXISTENT_VAR}"}
                    }
                }
            }"#,
        )
        .unwrap();

        match &config.servers["test"] {
            ServerConfig::Stdio { env, .. } => {
                assert_eq!(env["TOKEN"], "");
            }
            _ => panic!("expected Stdio config"),
        }
    }

    #[test]
    fn test_file_not_found_returns_empty() {
        let path = PathBuf::from("/tmp/mcp_nonexistent_config.json");
        let config = load_config_from_path(&path).unwrap();
        assert!(config.servers.is_empty());
    }

    #[test]
    fn test_empty_mcp_servers() {
        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert!(config.servers.is_empty());
    }

    #[test]
    fn test_missing_mcp_servers_key() {
        let config = config_from_json(r#"{}"#).unwrap();
        assert!(config.servers.is_empty());
    }

    #[test]
    fn test_multiple_servers() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "github": {"command": "npx", "args": []},
                    "remote": {"url": "https://example.com/mcp"}
                }
            }"#,
        )
        .unwrap();
        assert_eq!(config.servers.len(), 2);
    }

    #[test]
    fn test_validate_reserved_names() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "search": {"command": "echo", "args": []},
                    "github": {"command": "npx", "args": []},
                    "help": {"command": "echo", "args": []}
                }
            }"#,
        )
        .unwrap();

        let conflicts = validate_server_names(&config);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.contains(&"search".to_string()));
        assert!(conflicts.contains(&"help".to_string()));
    }

    #[test]
    fn test_no_reserved_names() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "github": {"command": "npx", "args": []}
                }
            }"#,
        )
        .unwrap();
        assert!(validate_server_names(&config).is_empty());
    }

    #[test]
    fn test_is_reserved_name() {
        assert!(is_reserved_name("search"));
        assert!(is_reserved_name("add"));
        assert!(is_reserved_name("remove"));
        assert!(is_reserved_name("logs"));
        assert!(!is_reserved_name("github"));
        assert!(!is_reserved_name("filesystem"));
    }

    #[test]
    fn test_parse_duration_str() {
        assert_eq!(parse_duration_str("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration_str("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration_str("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration_str("60"), Some(Duration::from_secs(60)));
        assert_eq!(parse_duration_str(" 10m "), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration_str("abc"), None);
        assert_eq!(parse_duration_str(""), None);
    }

    #[test]
    fn test_idle_timeout_defaults() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "test": {"command": "echo", "args": []}
                }
            }"#,
        )
        .unwrap();

        let server = &config.servers["test"];
        assert_eq!(*server.idle_timeout_policy(), IdleTimeoutPolicy::Adaptive);
        assert_eq!(server.min_idle_timeout(), DEFAULT_MIN_IDLE_TIMEOUT);
        assert_eq!(server.max_idle_timeout(), DEFAULT_MAX_IDLE_TIMEOUT);
    }

    #[test]
    fn test_idle_timeout_fixed() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "test": {
                        "command": "echo",
                        "args": [],
                        "idle_timeout": "10m"
                    }
                }
            }"#,
        )
        .unwrap();

        let server = &config.servers["test"];
        assert_eq!(
            *server.idle_timeout_policy(),
            IdleTimeoutPolicy::Fixed("10m".to_string())
        );
    }

    #[test]
    fn test_idle_timeout_never() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "test": {
                        "command": "echo",
                        "args": [],
                        "idle_timeout": "never"
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            *config.servers["test"].idle_timeout_policy(),
            IdleTimeoutPolicy::Never
        );
    }

    #[test]
    fn test_idle_timeout_custom_bounds() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "test": {
                        "command": "echo",
                        "args": [],
                        "min_idle_timeout": "30s",
                        "max_idle_timeout": "1h"
                    }
                }
            }"#,
        )
        .unwrap();

        let server = &config.servers["test"];
        assert_eq!(server.min_idle_timeout(), Duration::from_secs(30));
        assert_eq!(server.max_idle_timeout(), Duration::from_secs(3600));
    }

    #[test]
    fn test_idle_timeout_http_server() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    "remote": {
                        "url": "https://example.com/mcp",
                        "idle_timeout": "never"
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            *config.servers["remote"].idle_timeout_policy(),
            IdleTimeoutPolicy::Never
        );
    }

    #[test]
    fn test_parse_audit_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = config_from_json(
            r#"{
                "mcpServers": {},
                "audit": {
                    "enabled": true,
                    "log_arguments": true,
                    "path": "/tmp/audit/data",
                    "index_path": "/tmp/audit/index"
                }
            }"#,
        )
        .unwrap();
        assert!(config.audit.enabled);
        assert!(config.audit.log_arguments);
        assert_eq!(config.audit.path.unwrap(), "/tmp/audit/data");
    }

    #[test]
    fn test_parse_config_without_audit() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert!(config.audit.enabled); // default
        assert!(!config.audit.log_arguments); // default
        assert!(config.audit.path.is_none());
    }

    #[test]
    fn test_strip_single_line_comments() {
        let input = r#"{
            // this is a comment
            "mcpServers": {}
        }"#;
        let stripped = strip_json_comments(input);
        let _: serde_json::Value = serde_json::from_str(&stripped).unwrap();
    }

    #[test]
    fn test_strip_block_comments() {
        let input = r#"{
            /* block comment */
            "mcpServers": {}
        }"#;
        let stripped = strip_json_comments(input);
        let _: serde_json::Value = serde_json::from_str(&stripped).unwrap();
    }

    #[test]
    fn test_strip_comments_preserves_urls() {
        let input = r#"{
            "mcpServers": {
                "sentry": {
                    "url": "https://mcp.sentry.dev/mcp"
                }
            }
        }"#;
        let stripped = strip_json_comments(input);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(
            v["mcpServers"]["sentry"]["url"],
            "https://mcp.sentry.dev/mcp"
        );
    }

    #[test]
    fn test_strip_comments_commented_out_server() {
        let input = r#"{
            "mcpServers": {
                // "disabled": {
                //   "url": "https://example.com"
                // },
                "enabled": {
                    "url": "https://active.example.com"
                }
            }
        }"#;
        let stripped = strip_json_comments(input);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert!(v["mcpServers"]["disabled"].is_null());
        assert_eq!(
            v["mcpServers"]["enabled"]["url"],
            "https://active.example.com"
        );
    }

    #[test]
    fn test_config_with_comments() {
        let config = config_from_json(
            r#"{
                "mcpServers": {
                    // "disabled": { "url": "https://example.com" },
                    "active": {
                        "url": "https://active.example.com"
                    }
                }
            }"#,
        )
        .unwrap();
        assert!(config.servers.contains_key("active"));
        assert!(!config.servers.contains_key("disabled"));
    }

    // --- Container-friendly config tests (issue #67) ---

    /// Serialize env var access for tests that set/remove env vars.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_inline_config_via_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let json = r#"{"mcpServers":{"demo":{"url":"https://example.com/mcp"}}}"#;
        std::env::set_var("MCP_SERVERS_CONFIG", json);
        // Ensure MCP_CONFIG_PATH doesn't interfere
        std::env::remove_var("MCP_CONFIG_PATH");
        // Clear audit overrides
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = load_config().unwrap();
        assert_eq!(config.servers.len(), 1);
        assert!(config.servers.contains_key("demo"));
        assert_eq!(config.path, PathBuf::from("<env:MCP_SERVERS_CONFIG>"));

        std::env::remove_var("MCP_SERVERS_CONFIG");
    }

    #[test]
    fn test_inline_config_env_var_substitution() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_INLINE_TEST_TOKEN", "tok_abc");
        let json = r#"{"mcpServers":{"s":{"url":"https://ex.com","headers":{"Authorization":"Bearer ${MCP_INLINE_TEST_TOKEN}"}}}}"#;
        std::env::set_var("MCP_SERVERS_CONFIG", json);
        std::env::remove_var("MCP_CONFIG_PATH");
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = load_config().unwrap();
        match &config.servers["s"] {
            ServerConfig::Http { headers, .. } => {
                assert_eq!(headers["Authorization"], "Bearer tok_abc");
            }
            _ => panic!("expected Http config"),
        }

        std::env::remove_var("MCP_SERVERS_CONFIG");
        std::env::remove_var("MCP_INLINE_TEST_TOKEN");
    }

    #[test]
    fn test_inline_config_invalid_json_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_SERVERS_CONFIG", "not json {{{");
        std::env::remove_var("MCP_CONFIG_PATH");
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let result = load_config();
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("MCP_SERVERS_CONFIG"),
            "error should reference source: {err_msg}"
        );

        std::env::remove_var("MCP_SERVERS_CONFIG");
    }

    #[test]
    fn test_inline_config_takes_precedence_over_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Point MCP_CONFIG_PATH to a file with different content
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"{{"mcpServers":{{"file_server":{{"url":"https://file.com"}}}}}}"#
        )
        .unwrap();
        std::env::set_var("MCP_CONFIG_PATH", file.path().to_str().unwrap());

        // Inline config should win
        std::env::set_var(
            "MCP_SERVERS_CONFIG",
            r#"{"mcpServers":{"inline_server":{"url":"https://inline.com"}}}"#,
        );
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = load_config().unwrap();
        assert!(config.servers.contains_key("inline_server"));
        assert!(!config.servers.contains_key("file_server"));

        std::env::remove_var("MCP_SERVERS_CONFIG");
        std::env::remove_var("MCP_CONFIG_PATH");
    }

    #[test]
    fn test_audit_disabled_via_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_AUDIT_ENABLED", "false");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        // Config JSON has audit enabled, but env override disables it
        let config = config_from_json(
            r#"{
                "mcpServers": {},
                "audit": {"enabled": true}
            }"#,
        )
        .unwrap();
        assert!(!config.audit.enabled);

        std::env::remove_var("MCP_AUDIT_ENABLED");
    }

    #[test]
    fn test_audit_disabled_via_env_zero() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_AUDIT_ENABLED", "0");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert!(!config.audit.enabled);

        std::env::remove_var("MCP_AUDIT_ENABLED");
    }

    #[test]
    fn test_audit_enabled_not_overridden_when_env_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert!(config.audit.enabled); // default is true
    }

    #[test]
    fn test_audit_path_overrides_via_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::set_var("MCP_AUDIT_PATH", "/data/audit/data");
        std::env::set_var("MCP_AUDIT_INDEX_PATH", "/data/audit/index");

        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert_eq!(config.audit.path.as_deref(), Some("/data/audit/data"));
        assert_eq!(
            config.audit.index_path.as_deref(),
            Some("/data/audit/index")
        );

        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");
    }

    #[test]
    fn test_audit_env_overrides_json_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::set_var("MCP_AUDIT_PATH", "/env/data");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        // JSON sets one path, env overrides it
        let config = config_from_json(
            r#"{
                "mcpServers": {},
                "audit": {"path": "/json/data"}
            }"#,
        )
        .unwrap();
        assert_eq!(config.audit.path.as_deref(), Some("/env/data"));

        std::env::remove_var("MCP_AUDIT_PATH");
    }

    #[test]
    fn test_audit_force_enabled_via_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_AUDIT_ENABLED", "true");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        // JSON disables audit, but env override force-enables it
        let config = config_from_json(
            r#"{
                "mcpServers": {},
                "audit": {"enabled": false}
            }"#,
        )
        .unwrap();
        assert!(config.audit.enabled);

        std::env::remove_var("MCP_AUDIT_ENABLED");
    }

    #[test]
    fn test_audit_force_enabled_via_env_one() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_AUDIT_ENABLED", "1");
        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");

        let config = config_from_json(
            r#"{
                "mcpServers": {},
                "audit": {"enabled": false}
            }"#,
        )
        .unwrap();
        assert!(config.audit.enabled);

        std::env::remove_var("MCP_AUDIT_ENABLED");
    }

    #[test]
    fn test_empty_audit_path_env_ignored() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MCP_AUDIT_ENABLED");
        std::env::set_var("MCP_AUDIT_PATH", "");
        std::env::set_var("MCP_AUDIT_INDEX_PATH", "  ");

        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert!(config.audit.path.is_none());
        assert!(config.audit.index_path.is_none());

        std::env::remove_var("MCP_AUDIT_PATH");
        std::env::remove_var("MCP_AUDIT_INDEX_PATH");
    }
}
