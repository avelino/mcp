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

    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));

    if servers.get(name).is_some() {
        bail!("server \"{name}\" already exists in config");
    }

    // Build server config from registry data
    let entry = build_config_entry(&server)?;

    servers
        .as_object_mut()
        .unwrap()
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

    let path = config::config_path()?;
    let mut root = load_or_create_config(&path)?;

    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));

    if servers.get(name).is_some() {
        bail!("server \"{name}\" already exists in config");
    }

    servers.as_object_mut().unwrap().insert(
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

pub fn remove_server(name: &str) -> Result<()> {
    let path = config::config_path()?;

    if !path.exists() {
        bail!("config file not found: {}", path.display());
    }

    let mut root = load_or_create_config(&path)?;

    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));

    let removed = servers.as_object_mut().unwrap().remove(name);

    if removed.is_none() {
        bail!("server \"{name}\" not found in config");
    }

    save_config(&path, &root)?;

    eprintln!("✓ Server \"{}\" removed from {}", name, path.display());

    Ok(())
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
        let command = pkg.runtime.as_deref().unwrap_or(&pkg.name);

        let mut args: Vec<String> = pkg.runtime_args.clone();
        args.push(pkg.name.clone());
        args.extend(pkg.package_args.clone());

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
    fn test_build_config_entry_from_package() {
        let server = RegistryServer {
            name: "github".to_string(),
            description: Some("GitHub server".to_string()),
            repository: None,
            packages: vec![Package {
                name: "@modelcontextprotocol/server-github".to_string(),
                runtime: Some("npx".to_string()),
                runtime_args: vec!["-y".to_string()],
                package_args: vec![],
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
                name: "test-pkg".to_string(),
                runtime: None,
                runtime_args: vec![],
                package_args: vec![],
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
}
