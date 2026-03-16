use anyhow::{Context, Result};
use serde::Deserialize;

const REGISTRY_BASE_URL: &str = "https://registry.modelcontextprotocol.io/v0.1/servers";

#[derive(Debug, Deserialize, Clone)]
pub struct RegistryServer {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub repository: Option<Repository>,
    #[serde(default)]
    pub packages: Vec<Package>,
    #[serde(default)]
    pub remotes: Vec<Remote>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Repository {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Package {
    pub name: String,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default, rename = "runtimeArgs")]
    pub runtime_args: Vec<String>,
    #[serde(default, rename = "packageArgs")]
    pub package_args: Vec<String>,
    #[serde(default, rename = "environmentVariables")]
    pub environment_variables: Vec<EnvVar>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EnvVar {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Remote {
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    servers: Vec<RegistryServer>,
}

pub async fn search_servers(query: &str) -> Result<Vec<RegistryServer>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(REGISTRY_BASE_URL)
        .query(&[("q", query), ("limit", "20")])
        .send()
        .await
        .context("failed to query MCP registry")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("registry returned {status}: {text}");
    }

    let search_resp: SearchResponse = resp
        .json()
        .await
        .context("failed to parse registry response")?;

    Ok(search_resp.servers)
}

pub async fn find_server(name: &str) -> Result<Option<RegistryServer>> {
    let results = search_servers(name).await?;
    Ok(results.into_iter().find(|s| s.name == name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_server_deserialization() {
        let json = serde_json::json!({
            "name": "github",
            "description": "GitHub MCP server",
            "repository": {
                "url": "https://github.com/modelcontextprotocol/servers"
            },
            "packages": [{
                "name": "@modelcontextprotocol/server-github",
                "runtime": "npx",
                "runtimeArgs": ["-y"],
                "packageArgs": [],
                "environmentVariables": [{
                    "name": "GITHUB_TOKEN",
                    "description": "GitHub personal access token"
                }]
            }],
            "remotes": []
        });

        let server: RegistryServer = serde_json::from_value(json).unwrap();
        assert_eq!(server.name, "github");
        assert_eq!(server.description.unwrap(), "GitHub MCP server");
        assert_eq!(server.packages.len(), 1);
        assert_eq!(
            server.packages[0].name,
            "@modelcontextprotocol/server-github"
        );
        assert_eq!(server.packages[0].environment_variables.len(), 1);
        assert_eq!(
            server.packages[0].environment_variables[0].name,
            "GITHUB_TOKEN"
        );
    }

    #[test]
    fn test_registry_server_minimal() {
        let json = serde_json::json!({
            "name": "test"
        });
        let server: RegistryServer = serde_json::from_value(json).unwrap();
        assert_eq!(server.name, "test");
        assert!(server.description.is_none());
        assert!(server.packages.is_empty());
        assert!(server.remotes.is_empty());
    }

    #[test]
    fn test_search_response_deserialization() {
        let json = serde_json::json!({
            "servers": [
                {"name": "github"},
                {"name": "filesystem"}
            ]
        });
        let resp: SearchResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.servers.len(), 2);
    }

    #[test]
    fn test_remote_deserialization() {
        let json = serde_json::json!({
            "url": "https://example.com/mcp/sse"
        });
        let remote: Remote = serde_json::from_value(json).unwrap();
        assert_eq!(remote.url, "https://example.com/mcp/sse");
    }
}
