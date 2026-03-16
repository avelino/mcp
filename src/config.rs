use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

const RESERVED_NAMES: &[&str] = &["search", "add", "remove", "list", "help", "version"];

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ServerConfig {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    Http {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

#[derive(Debug)]
pub struct Config {
    pub servers: HashMap<String, ServerConfig>,
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

    Ok(Config {
        servers,
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
            ServerConfig::Stdio { command, args, env } => {
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
            ServerConfig::Http { url, headers } => {
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
        assert!(!is_reserved_name("github"));
        assert!(!is_reserved_name("filesystem"));
    }
}
