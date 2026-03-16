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
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Package {
    #[serde(rename = "registryType")]
    pub registry_type: String,
    pub identifier: String,
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
struct SearchEntry {
    server: RegistryServer,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    servers: Vec<SearchEntry>,
}

pub async fn search_servers(query: &str) -> Result<Vec<RegistryServer>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(REGISTRY_BASE_URL)
        .query(&[("search", query), ("limit", "20")])
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

    let mut seen = std::collections::HashSet::new();
    let mut servers: Vec<RegistryServer> = search_resp
        .servers
        .into_iter()
        .map(|e| e.server)
        .filter(|s| seen.insert(s.name.clone()))
        .collect();

    let query_lower = query.to_lowercase();
    servers.sort_by_key(|s| relevance_score(s, &query_lower));
    Ok(servers)
}

/// Lower score = more relevant.
/// Prioritizes matches in the short name (after `/`) and description
/// over matches that only hit a namespace prefix like `io.github.`.
fn relevance_score(server: &RegistryServer, query: &str) -> u8 {
    // Short name is the part after the last `/`
    let short_name = server
        .name
        .rsplit('/')
        .next()
        .unwrap_or(&server.name)
        .to_lowercase();
    let desc = server.description.as_deref().unwrap_or("").to_lowercase();

    if short_name.contains(query) {
        return 0; // best: query in the actual server name
    }
    if desc.contains(query) {
        return 1; // good: query in description
    }
    2 // worst: match only in namespace prefix
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
                "registryType": "npm",
                "identifier": "@modelcontextprotocol/server-github",
                "version": "1.0.0",
                "transport": { "type": "stdio" },
                "environmentVariables": [{
                    "name": "GITHUB_TOKEN",
                    "description": "GitHub personal access token",
                    "isRequired": true,
                    "isSecret": true
                }]
            }],
            "remotes": []
        });

        let server: RegistryServer = serde_json::from_value(json).unwrap();
        assert_eq!(server.name, "github");
        assert_eq!(server.description.unwrap(), "GitHub MCP server");
        assert_eq!(server.packages.len(), 1);
        assert_eq!(
            server.packages[0].identifier,
            "@modelcontextprotocol/server-github"
        );
        assert_eq!(server.packages[0].registry_type, "npm");
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
                {"server": {"name": "github"}},
                {"server": {"name": "filesystem"}}
            ]
        });
        let resp: SearchResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.servers.len(), 2);
    }

    #[test]
    fn test_remote_deserialization() {
        let json = serde_json::json!({
            "url": "https://example.com/mcp/sse",
            "type": "streamable-http"
        });
        let remote: Remote = serde_json::from_value(json).unwrap();
        assert_eq!(remote.url, "https://example.com/mcp/sse");
    }
}
