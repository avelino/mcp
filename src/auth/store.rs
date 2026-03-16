use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthStore {
    #[serde(default)]
    pub clients: HashMap<String, ClientRegistration>,
    #[serde(default)]
    pub tokens: HashMap<String, StoredTokens>,
}

pub fn auth_store_path() -> Result<PathBuf> {
    Ok(config::config_dir()?.join("auth.json"))
}

pub fn load_auth_store() -> Result<AuthStore> {
    let path = auth_store_path()?;
    if !path.exists() {
        return Ok(AuthStore::default());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content).unwrap_or_default())
}

pub fn save_auth_store(store: &AuthStore) -> Result<()> {
    let path = auth_store_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(store)?;
    std::fs::write(&path, content)?;
    Ok(())
}

pub fn server_key(server_url: &str) -> String {
    server_url.trim_end_matches('/').to_string()
}

pub fn to_stored_tokens(resp: &super::oauth::TokenResponse) -> StoredTokens {
    let expires_at = resp.expires_in.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + secs
    });

    StoredTokens {
        access_token: resp.access_token.clone(),
        refresh_token: resp.refresh_token.clone(),
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_key_normalization() {
        assert_eq!(server_key("https://mcp.sentry.dev/"), "https://mcp.sentry.dev");
        assert_eq!(server_key("https://mcp.sentry.dev"), "https://mcp.sentry.dev");
    }

    #[test]
    fn test_to_stored_tokens() {
        let resp = super::super::oauth::TokenResponse {
            access_token: "abc".to_string(),
            refresh_token: Some("def".to_string()),
            expires_in: Some(3600),
        };
        let stored = to_stored_tokens(&resp);
        assert_eq!(stored.access_token, "abc");
        assert_eq!(stored.refresh_token.unwrap(), "def");
        assert!(stored.expires_at.unwrap() > 0);
    }

    #[test]
    fn test_to_stored_tokens_no_expiry() {
        let resp = super::super::oauth::TokenResponse {
            access_token: "abc".to_string(),
            refresh_token: None,
            expires_in: None,
        };
        let stored = to_stored_tokens(&resp);
        assert!(stored.expires_at.is_none());
        assert!(stored.refresh_token.is_none());
    }

    #[test]
    fn test_auth_store_roundtrip() {
        let mut store = AuthStore::default();
        store.clients.insert(
            "https://example.com".to_string(),
            ClientRegistration {
                client_id: "test123".to_string(),
                client_secret: None,
            },
        );
        store.tokens.insert(
            "https://example.com".to_string(),
            StoredTokens {
                access_token: "token".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: Some(9999999999),
            },
        );

        let json = serde_json::to_string(&store).unwrap();
        let loaded: AuthStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.clients["https://example.com"].client_id, "test123");
        assert_eq!(loaded.tokens["https://example.com"].access_token, "token");
    }
}
