use anyhow::Result;
use crate::config::ServerConfig;
use crate::protocol::{Tool, ToolCallResult};
use crate::registry::RegistryServer;
use serde_json::json;
use std::collections::HashMap;

pub fn print_servers(servers: &HashMap<String, ServerConfig>) -> Result<()> {
    let list: Vec<serde_json::Value> = servers
        .iter()
        .map(|(name, config)| match config {
            ServerConfig::Stdio { command, args, .. } => json!({
                "name": name,
                "type": "stdio",
                "command": command,
                "args": args,
            }),
            ServerConfig::Http { url, .. } => json!({
                "name": name,
                "type": "http",
                "url": url,
            }),
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

pub fn print_tools(tools: &[Tool]) -> Result<()> {
    let list: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

pub fn print_tools_info(tools: &[Tool]) -> Result<()> {
    let list: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

pub fn print_tool_result(result: &ToolCallResult) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}

pub fn print_search_results(servers: &[RegistryServer]) -> Result<()> {
    let list: Vec<serde_json::Value> = servers
        .iter()
        .map(|s| {
            let mut entry = json!({
                "name": s.name,
                "description": s.description,
            });

            if let Some(ref repo) = s.repository {
                entry["repository"] = json!(repo.url);
            }

            if !s.packages.is_empty() {
                let install: Vec<String> = s
                    .packages
                    .iter()
                    .map(|p| {
                        if let Some(ref runtime) = p.runtime {
                            format!("{} {}", runtime, p.name)
                        } else {
                            p.name.clone()
                        }
                    })
                    .collect();
                entry["install"] = json!(install);
            }

            entry
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_servers_json_structure() {
        let mut servers = HashMap::new();
        servers.insert(
            "test".to_string(),
            ServerConfig::Stdio {
                command: "echo".to_string(),
                args: vec![],
                env: HashMap::new(),
            },
        );

        let list: Vec<serde_json::Value> = servers
            .iter()
            .map(|(name, _)| json!({"name": name}))
            .collect();
        let json = serde_json::to_string_pretty(&list).unwrap();
        assert!(json.contains("test"));
    }
}
