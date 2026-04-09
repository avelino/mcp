use crate::config::{self, is_reserved_name};
use crate::registry;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

pub async fn add_from_registry(name: &str) -> Result<()> {
    if is_reserved_name(name) {
        bail!(
            "\"{}\" is a reserved command name and cannot be used as a server name",
            name
        );
    }

    let server = registry::find_server(name)
        .await?
        .with_context(|| format!("server \"{name}\" not found in registry"))?;

    let path = config::config_path()?;
    let mut root = load_or_create_config(&path)?;

    let servers = get_servers_mut(&mut root)?;

    if servers.get(name).is_some() {
        bail!("server \"{name}\" already exists in config");
    }

    // Build server config from registry data
    let entry = build_config_entry(&server)?;

    servers
        .as_object_mut()
        .context("\"mcpServers\" must be a JSON object")?
        .insert(name.to_string(), entry);

    save_config(&path, &root)?;

    // Print guidance
    eprintln!("✓ Server \"{}\" added to {}", name, path.display());

    let env_vars = collect_env_vars(&server);
    if !env_vars.is_empty() {
        eprintln!("\nConfigure the following environment variables:");
        for (var_name, description) in &env_vars {
            let desc = description.as_deref().unwrap_or("(no description)");
            eprintln!("  {var_name}  — {desc}");
        }
    }

    eprintln!("\nRun to test:");
    eprintln!("  mcp {name} --list");

    Ok(())
}

pub fn add_http(name: &str, url: &str) -> Result<()> {
    if is_reserved_name(name) {
        bail!(
            "\"{}\" is a reserved command name and cannot be used as a server name",
            name
        );
    }

    validate_http_url(url)?;

    let path = config::config_path()?;
    let mut root = load_or_create_config(&path)?;

    let servers = get_servers_mut(&mut root)?;

    if servers.get(name).is_some() {
        bail!("server \"{name}\" already exists in config");
    }

    servers
        .as_object_mut()
        .context("\"mcpServers\" must be a JSON object")?
        .insert(
            name.to_string(),
            json!({
                "url": url
            }),
        );

    save_config(&path, &root)?;

    eprintln!("✓ Server \"{}\" added to {}", name, path.display());
    eprintln!("\nRun to test:");
    eprintln!("  mcp {name} --list");

    Ok(())
}

pub async fn update_from_registry(name: &str) -> Result<()> {
    if is_reserved_name(name) {
        bail!(
            "\"{}\" is a reserved command name and cannot be used as a server name",
            name
        );
    }

    let server = registry::find_server(name)
        .await?
        .with_context(|| format!("server \"{name}\" not found in registry"))?;

    let path = config::config_path()?;
    if !path.exists() {
        bail!("config file not found: {}", path.display());
    }

    let mut root = load_or_create_config(&path)?;
    let servers = get_servers_mut(&mut root)?;
    let servers_obj = servers
        .as_object_mut()
        .context("\"mcpServers\" must be a JSON object")?;

    let existing = servers_obj.get(name).cloned().with_context(|| {
        format!("server \"{name}\" not found in config (use `mcp add {name}` to add it)")
    })?;

    let fresh = build_config_entry(&server)?;

    // Detect type transition (stdio <-> http)
    let was_http = existing.get("url").is_some();
    let now_http = fresh.get("url").is_some();
    if was_http != now_http {
        eprintln!(
            "warning: server \"{}\" changed type ({} -> {}); type-specific fields will not be carried over",
            name,
            if was_http { "http" } else { "stdio" },
            if now_http { "http" } else { "stdio" },
        );
    }

    let merged = merge_entry(&fresh, &existing);

    if merged == existing {
        eprintln!("✓ Server \"{name}\" already up to date");
        return Ok(());
    }

    // Compute newly added env vars (present in fresh, absent in existing)
    let new_env_vars: Vec<(String, Option<String>)> = if !now_http {
        let existing_env = existing.get("env").and_then(|v| v.as_object());
        collect_env_vars(&server)
            .into_iter()
            .filter(|(k, _)| existing_env.is_none_or(|m| !m.contains_key(k)))
            .collect()
    } else {
        Vec::new()
    };

    servers_obj.insert(name.to_string(), merged);
    save_config(&path, &root)?;

    eprintln!("✓ Server \"{}\" updated in {}", name, path.display());

    if !new_env_vars.is_empty() {
        eprintln!("\nNew environment variables to configure:");
        for (var_name, description) in &new_env_vars {
            let desc = description.as_deref().unwrap_or("(no description)");
            eprintln!("  {var_name}  — {desc}");
        }
    }

    Ok(())
}

/// Checks if a string is a placeholder of form `${VAR_NAME}` (uppercase letters, digits, underscore).
fn is_env_placeholder(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'$' || bytes[1] != b'{' || bytes[bytes.len() - 1] != b'}' {
        return false;
    }
    bytes[2..bytes.len() - 1]
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

/// Merge a freshly-built registry entry with an existing config entry,
/// preserving user customizations (filled env values, headers, idle_timeout, cli*, tools).
fn merge_entry(fresh: &Value, existing: &Value) -> Value {
    let mut merged = fresh.clone();
    let merged_obj = match merged.as_object_mut() {
        Some(o) => o,
        None => return merged,
    };
    let existing_obj = match existing.as_object() {
        Some(o) => o,
        None => return merged,
    };

    let was_http = existing.get("url").is_some();
    let now_http = fresh.get("url").is_some();
    let same_type = was_http == now_http;

    // Merge env: preserve filled-in values, drop env vars removed from registry,
    // keep new ones as placeholders.
    if !now_http {
        if let (Some(fresh_env), Some(existing_env)) = (
            merged_obj.get("env").and_then(|v| v.as_object()).cloned(),
            existing_obj.get("env").and_then(|v| v.as_object()),
        ) {
            let mut new_env = fresh_env.clone();
            for (key, fresh_val) in fresh_env.iter() {
                if let Some(existing_val) = existing_env.get(key) {
                    if let Some(s) = existing_val.as_str() {
                        if !is_env_placeholder(s) {
                            new_env.insert(key.clone(), existing_val.clone());
                            continue;
                        }
                    }
                    // Non-string user override (rare): preserve.
                    if !existing_val.is_string() {
                        new_env.insert(key.clone(), existing_val.clone());
                        continue;
                    }
                    // Otherwise keep fresh (placeholder).
                    let _ = fresh_val;
                }
            }
            merged_obj.insert("env".to_string(), Value::Object(new_env));
        }
    }

    // Type-agnostic user fields preserved across updates.
    const ALWAYS_PRESERVE: &[&str] = &[
        "idle_timeout",
        "min_idle_timeout",
        "max_idle_timeout",
        "cli",
        "cli_help",
        "cli_depth",
        "cli_only",
        "tools",
    ];
    for key in ALWAYS_PRESERVE {
        if let Some(v) = existing_obj.get(*key) {
            merged_obj.insert((*key).to_string(), v.clone());
        }
    }

    // headers only carry over if both sides are http.
    if same_type && now_http {
        if let Some(v) = existing_obj.get("headers") {
            merged_obj.insert("headers".to_string(), v.clone());
        }
    }

    merged
}

pub fn remove_server(name: &str) -> Result<()> {
    let path = config::config_path()?;

    if !path.exists() {
        bail!("config file not found: {}", path.display());
    }

    let mut root = load_or_create_config(&path)?;

    let servers = get_servers_mut(&mut root)?;

    let removed = servers
        .as_object_mut()
        .context("\"mcpServers\" must be a JSON object")?
        .remove(name);

    if removed.is_none() {
        bail!("server \"{name}\" not found in config");
    }

    save_config(&path, &root)?;

    eprintln!("✓ Server \"{}\" removed from {}", name, path.display());

    Ok(())
}

fn validate_http_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid URL: \"{url}\""))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => bail!("unsupported URL scheme \"{scheme}\": only http and https are allowed"),
    }
}

fn get_servers_mut(root: &mut Value) -> Result<&mut Value> {
    let obj = root
        .as_object_mut()
        .context("config file must contain a JSON object at the top level")?;
    Ok(obj.entry("mcpServers").or_insert_with(|| json!({})))
}

fn load_or_create_config(path: &std::path::Path) -> Result<Value> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))
    } else {
        // Create parent dirs
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        Ok(json!({"mcpServers": {}}))
    }
}

fn save_config(path: &std::path::Path, root: &Value) -> Result<()> {
    let content = serde_json::to_string_pretty(root)?;
    std::fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn build_config_entry(server: &registry::RegistryServer) -> Result<Value> {
    // Prefer packages (stdio) over remotes (http)
    if let Some(pkg) = server.packages.first() {
        let (command, args) = match pkg.registry_type.as_str() {
            "npm" => (
                "npx".to_string(),
                vec!["-y".to_string(), pkg.identifier.clone()],
            ),
            "pip" | "pypi" => ("uvx".to_string(), vec![pkg.identifier.clone()]),
            "oci" | "docker" => (
                "docker".to_string(),
                vec![
                    "run".to_string(),
                    "-i".to_string(),
                    "--rm".to_string(),
                    pkg.identifier.clone(),
                ],
            ),
            _ => (pkg.identifier.clone(), vec![]),
        };

        let mut env = serde_json::Map::new();
        for ev in &pkg.environment_variables {
            env.insert(ev.name.clone(), Value::String(format!("${{{}}}", ev.name)));
        }

        let mut entry = json!({
            "command": command,
            "args": args,
        });

        if !env.is_empty() {
            entry["env"] = Value::Object(env);
        }

        Ok(entry)
    } else if let Some(remote) = server.remotes.first() {
        Ok(json!({
            "url": remote.url
        }))
    } else {
        bail!(
            "server \"{}\" has no packages or remotes — cannot determine how to run it",
            server.name
        );
    }
}

fn collect_env_vars(server: &registry::RegistryServer) -> Vec<(String, Option<String>)> {
    let mut vars = Vec::new();
    for pkg in &server.packages {
        for ev in &pkg.environment_variables {
            vars.push((ev.name.clone(), ev.description.clone()));
        }
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{EnvVar, Package, RegistryServer, Remote};

    #[test]
    fn test_build_config_entry_from_npm_package() {
        let server = RegistryServer {
            name: "github".to_string(),
            description: Some("GitHub server".to_string()),
            repository: None,
            packages: vec![Package {
                registry_type: "npm".to_string(),
                identifier: "@modelcontextprotocol/server-github".to_string(),
                environment_variables: vec![EnvVar {
                    name: "GITHUB_TOKEN".to_string(),
                    description: Some("GitHub personal access token".to_string()),
                }],
            }],
            remotes: vec![],
        };

        let entry = build_config_entry(&server).unwrap();
        assert_eq!(entry["command"], "npx");
        assert_eq!(entry["args"][0], "-y");
        assert_eq!(entry["args"][1], "@modelcontextprotocol/server-github");
        assert_eq!(entry["env"]["GITHUB_TOKEN"], "${GITHUB_TOKEN}");
    }

    #[test]
    fn test_build_config_entry_from_remote() {
        let server = RegistryServer {
            name: "remote".to_string(),
            description: None,
            repository: None,
            packages: vec![],
            remotes: vec![Remote {
                url: "https://example.com/mcp".to_string(),
            }],
        };

        let entry = build_config_entry(&server).unwrap();
        assert_eq!(entry["url"], "https://example.com/mcp");
    }

    #[test]
    fn test_build_config_entry_no_packages_or_remotes() {
        let server = RegistryServer {
            name: "empty".to_string(),
            description: None,
            repository: None,
            packages: vec![],
            remotes: vec![],
        };

        let result = build_config_entry(&server);
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_env_vars() {
        let server = RegistryServer {
            name: "test".to_string(),
            description: None,
            repository: None,
            packages: vec![Package {
                registry_type: "npm".to_string(),
                identifier: "test-pkg".to_string(),
                environment_variables: vec![
                    EnvVar {
                        name: "TOKEN".to_string(),
                        description: Some("Auth token".to_string()),
                    },
                    EnvVar {
                        name: "API_KEY".to_string(),
                        description: None,
                    },
                ],
            }],
            remotes: vec![],
        };

        let vars = collect_env_vars(&server);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, "TOKEN");
        assert_eq!(vars[0].1.as_deref(), Some("Auth token"));
        assert_eq!(vars[1].0, "API_KEY");
        assert!(vars[1].1.is_none());
    }

    #[test]
    fn test_load_or_create_config_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir").join("servers.json");
        let root = load_or_create_config(&path).unwrap();
        assert!(root.get("mcpServers").is_some());
    }

    #[test]
    fn test_load_or_create_config_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"existing": {"command": "echo", "args": []}}}"#,
        )
        .unwrap();

        let root = load_or_create_config(&path).unwrap();
        assert!(root["mcpServers"]["existing"].is_object());
    }

    #[test]
    fn test_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers.json");

        let root = json!({
            "mcpServers": {
                "test": {"command": "echo", "args": []}
            }
        });

        save_config(&path, &root).unwrap();

        let loaded = load_or_create_config(&path).unwrap();
        assert_eq!(loaded["mcpServers"]["test"]["command"], "echo");
    }

    #[test]
    fn test_reserved_name_rejected() {
        // Test that is_reserved_name works correctly
        assert!(is_reserved_name("search"));
        assert!(is_reserved_name("add"));
        assert!(!is_reserved_name("github"));
    }

    #[test]
    fn test_get_servers_mut_valid_object() {
        let mut root = json!({"mcpServers": {"a": {"command": "echo"}}});
        let servers = get_servers_mut(&mut root).unwrap();
        assert!(servers.is_object());
    }

    #[test]
    fn test_get_servers_mut_creates_missing_key() {
        let mut root = json!({});
        let servers = get_servers_mut(&mut root).unwrap();
        assert!(servers.is_object());
        assert_eq!(servers, &json!({}));
    }

    #[test]
    fn test_get_servers_mut_rejects_non_object_root() {
        let mut root = json!([1, 2, 3]);
        let result = get_servers_mut(&mut root);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("JSON object at the top level"));
    }

    #[test]
    fn test_load_malformed_json_string_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers.json");
        std::fs::write(&path, r#""just a string""#).unwrap();

        let mut root = load_or_create_config(&path).unwrap();
        let result = get_servers_mut(&mut root);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_http_url_accepts_http() {
        assert!(validate_http_url("http://example.com/mcp").is_ok());
    }

    #[test]
    fn test_validate_http_url_accepts_https() {
        assert!(validate_http_url("https://example.com/mcp").is_ok());
    }

    #[test]
    fn test_validate_http_url_rejects_invalid() {
        let result = validate_http_url("not-a-url");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid URL"));
    }

    #[test]
    fn test_validate_http_url_rejects_non_http_scheme() {
        let result = validate_http_url("ftp://example.com/mcp");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported URL scheme"));
    }

    #[test]
    fn test_is_env_placeholder() {
        assert!(is_env_placeholder("${GITHUB_TOKEN}"));
        assert!(is_env_placeholder("${API_KEY_2}"));
        assert!(!is_env_placeholder("ghp_xxx"));
        assert!(!is_env_placeholder("${lowercase}"));
        assert!(!is_env_placeholder("${}"));
        assert!(!is_env_placeholder(""));
        assert!(!is_env_placeholder("$GITHUB_TOKEN"));
    }

    #[test]
    fn test_merge_entry_preserves_filled_env_value() {
        let fresh = json!({
            "command": "npx",
            "args": ["-y", "@scope/pkg"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}
        });
        let existing = json!({
            "command": "npx",
            "args": ["-y", "@scope/pkg"],
            "env": {"GITHUB_TOKEN": "ghp_secret"}
        });
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged["env"]["GITHUB_TOKEN"], "ghp_secret");
    }

    #[test]
    fn test_merge_entry_keeps_placeholder_when_not_filled() {
        let fresh = json!({
            "command": "npx", "args": [],
            "env": {"TOKEN": "${TOKEN}"}
        });
        let existing = json!({
            "command": "npx", "args": [],
            "env": {"TOKEN": "${TOKEN}"}
        });
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged["env"]["TOKEN"], "${TOKEN}");
    }

    #[test]
    fn test_merge_entry_adds_new_registry_env_var() {
        let fresh = json!({
            "command": "npx", "args": [],
            "env": {"OLD": "${OLD}", "NEW_VAR": "${NEW_VAR}"}
        });
        let existing = json!({
            "command": "npx", "args": [],
            "env": {"OLD": "old_value"}
        });
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged["env"]["OLD"], "old_value");
        assert_eq!(merged["env"]["NEW_VAR"], "${NEW_VAR}");
    }

    #[test]
    fn test_merge_entry_drops_removed_env_var() {
        let fresh = json!({
            "command": "npx", "args": [],
            "env": {"KEEP": "${KEEP}"}
        });
        let existing = json!({
            "command": "npx", "args": [],
            "env": {"KEEP": "kept", "GONE": "stale"}
        });
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged["env"]["KEEP"], "kept");
        assert!(merged["env"].get("GONE").is_none());
    }

    #[test]
    fn test_merge_entry_preserves_user_customizations() {
        let fresh = json!({
            "command": "npx",
            "args": ["-y", "@scope/pkg@2.0.0"],
        });
        let existing = json!({
            "command": "npx",
            "args": ["-y", "@scope/pkg@1.0.0"],
            "idle_timeout": "adaptive",
            "min_idle_timeout": "30s",
            "cli_only": true,
            "tools": ["foo", "bar"],
        });
        let merged = merge_entry(&fresh, &existing);
        // Registry-derived fields are refreshed
        assert_eq!(merged["args"][1], "@scope/pkg@2.0.0");
        // User fields preserved
        assert_eq!(merged["idle_timeout"], "adaptive");
        assert_eq!(merged["min_idle_timeout"], "30s");
        assert_eq!(merged["cli_only"], true);
        assert_eq!(merged["tools"][0], "foo");
    }

    #[test]
    fn test_merge_entry_preserves_http_headers() {
        let fresh = json!({"url": "https://example.com/v2"});
        let existing = json!({
            "url": "https://example.com/v1",
            "headers": {"Authorization": "Bearer xyz"},
            "idle_timeout": "120s",
        });
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged["url"], "https://example.com/v2");
        assert_eq!(merged["headers"]["Authorization"], "Bearer xyz");
        assert_eq!(merged["idle_timeout"], "120s");
    }

    #[test]
    fn test_merge_entry_type_transition_drops_headers() {
        // stdio -> http: existing was stdio, no headers to carry. Just sanity-check no panic.
        let fresh = json!({"url": "https://example.com/mcp"});
        let existing = json!({
            "command": "npx",
            "args": ["-y", "old"],
            "env": {"X": "filled"},
            "idle_timeout": "60s",
        });
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged["url"], "https://example.com/mcp");
        assert!(merged.get("command").is_none());
        assert!(merged.get("env").is_none());
        // type-agnostic preserved
        assert_eq!(merged["idle_timeout"], "60s");

        // http -> stdio: headers must NOT be carried over.
        let fresh = json!({"command": "npx", "args": []});
        let existing = json!({
            "url": "https://example.com/mcp",
            "headers": {"Authorization": "Bearer xyz"},
        });
        let merged = merge_entry(&fresh, &existing);
        assert!(merged.get("headers").is_none());
        assert!(merged.get("url").is_none());
    }

    #[test]
    fn test_merge_entry_noop_when_identical() {
        let fresh = json!({
            "command": "npx",
            "args": ["-y", "@scope/pkg"],
            "env": {"TOKEN": "${TOKEN}"}
        });
        let existing = fresh.clone();
        let merged = merge_entry(&fresh, &existing);
        assert_eq!(merged, existing);
    }

    #[test]
    fn test_load_malformed_json_array_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers.json");
        std::fs::write(&path, r#"[1, 2, 3]"#).unwrap();

        let mut root = load_or_create_config(&path).unwrap();
        let result = get_servers_mut(&mut root);
        assert!(result.is_err());
    }
}
