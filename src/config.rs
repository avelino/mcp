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

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdleTimeoutPolicy {
    Adaptive,
    Never,
    #[serde(untagged)]
    Fixed(String),
}

impl Default for IdleTimeoutPolicy {
    fn default() -> Self {
        IdleTimeoutPolicy::Adaptive
    }
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

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ServerConfig {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
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
        idle_timeout: IdleTimeoutPolicy,
        #[serde(default)]
        min_idle_timeout: Option<String>,
        #[serde(default)]
        max_idle_timeout: Option<String>,
    },
}

impl ServerConfig {
    pub fn idle_timeout_policy(&self) -> &IdleTimeoutPolicy {
        match self {
            ServerConfig::Stdio { idle_timeout, .. } => idle_timeout,
            ServerConfig::Http { idle_timeout, .. } => idle_timeout,
        }
    }

    pub fn min_idle_timeout(&self) -> Duration {
        let raw = match self {
            ServerConfig::Stdio { min_idle_timeout, .. } => min_idle_timeout.as_deref(),
            ServerConfig::Http { min_idle_timeout, .. } => min_idle_timeout.as_deref(),
        };
        raw.and_then(parse_duration_str).unwrap_or(DEFAULT_MIN_IDLE_TIMEOUT)
    }

    pub fn max_idle_timeout(&self) -> Duration {
        let raw = match self {
            ServerConfig::Stdio { max_idle_timeout, .. } => max_idle_timeout.as_deref(),
            ServerConfig::Http { max_idle_timeout, .. } => max_idle_timeout.as_deref(),
        };
        raw.and_then(parse_duration_str).unwrap_or(DEFAULT_MAX_IDLE_TIMEOUT)
    }
}

#[derive(Debug)]
pub struct Config {
    pub servers: HashMap<String, ServerConfig>,
    pub server_auth: ServerAuthConfig,
    pub audit: AuditConfig,
    pub path: PathBuf,
}

pub fn config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".config").join("mcp"))
}

pub fn config_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("MCP_CONFIG_PATH") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("servers.json"))
}

pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    load_config_from_path(&path)
}

pub fn load_config_from_path(path: &PathBuf) -> Result<Config> {
    if !path.exists() {
        return Ok(Config {
            servers: HashMap::new(),
            server_auth: ServerAuthConfig::default(),
            audit: AuditConfig::default(),
            path: path.clone(),
        });
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let content = substitute_env_vars(&content);

    let raw: Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;

    let servers_value = raw
        .get("mcpServers")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let servers: HashMap<String, ServerConfig> =
        serde_json::from_value(servers_value).context("failed to parse mcpServers from config")?;

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

    Ok(Config {
        servers,
        server_auth,
        audit,
        path: path.clone(),
    })
}

fn substitute_env_vars(input: &str) -> String {
    let re = Regex::new(r"\$\{([^}]+)\}").unwrap();
    re.replace_all(input, |caps: &regex::Captures| {
        let var_name = &caps[1];
        std::env::var(var_name).unwrap_or_default()
    })
    .to_string()
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
            ServerConfig::Stdio { command, args, env, .. } => {
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
        let config = config_from_json(r#"{"mcpServers": {}}"#).unwrap();
        assert!(config.audit.enabled); // default
        assert!(!config.audit.log_arguments); // default
        assert!(config.audit.path.is_none());
    }
}
