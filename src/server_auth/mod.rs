mod acl;
mod providers;

pub use acl::{AclConfig, AclPolicy, AclRule};
pub use providers::{BearerTokenAuth, ForwardedUserAuth, NoAuth};

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Transport-agnostic credentials extracted by each transport layer.
pub type Credentials = HashMap<String, String>;

/// Authenticated identity flowing through the system.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub subject: String,
    pub roles: Vec<String>,
}

impl AuthIdentity {
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".to_string(),
            roles: vec![],
        }
    }

    pub fn new(subject: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            subject: subject.into(),
            roles,
        }
    }
}

/// Transport-independent authentication trait.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthIdentity>;
}

/// Configuration for server-side authentication.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerAuthConfig {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub bearer: Option<BearerConfig>,
    #[serde(default)]
    pub forwarded: Option<ForwardedConfig>,
    #[serde(default)]
    pub acl: Option<AclConfig>,
}

impl Default for ServerAuthConfig {
    fn default() -> Self {
        Self {
            provider: "none".to_string(),
            bearer: None,
            forwarded: None,
            acl: None,
        }
    }
}

fn default_provider() -> String {
    "none".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct BearerConfig {
    pub tokens: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForwardedConfig {
    #[serde(default = "default_header")]
    pub header: String,
}

fn default_header() -> String {
    "x-forwarded-user".to_string()
}

/// Build an AuthProvider from config.
pub fn build_auth_provider(config: &ServerAuthConfig) -> Result<Arc<dyn AuthProvider>> {
    match config.provider.as_str() {
        "none" => Ok(Arc::new(NoAuth)),
        "bearer" => {
            let bearer = config
                .bearer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("bearer provider requires 'bearer' config"))?;
            Ok(Arc::new(BearerTokenAuth::new(bearer.tokens.clone())))
        }
        "forwarded" => {
            let header = config
                .forwarded
                .as_ref()
                .map(|f| f.header.clone())
                .unwrap_or_else(default_header);
            Ok(Arc::new(ForwardedUserAuth::new(header)))
        }
        other => anyhow::bail!("unknown auth provider: {other}"),
    }
}

/// Check if a tool is allowed for the given identity.
pub fn is_tool_allowed(identity: &AuthIdentity, tool_name: &str, acl: &Option<AclConfig>) -> bool {
    match acl {
        Some(acl) => acl::is_tool_allowed(identity, tool_name, acl),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymous_identity() {
        let id = AuthIdentity::anonymous();
        assert_eq!(id.subject, "anonymous");
        assert!(id.roles.is_empty());
    }

    #[test]
    fn test_named_identity() {
        let id = AuthIdentity::new("alice", vec!["admin".to_string()]);
        assert_eq!(id.subject, "alice");
        assert_eq!(id.roles, vec!["admin"]);
    }

    #[tokio::test]
    async fn test_build_no_auth() {
        let config = ServerAuthConfig::default();
        let provider = build_auth_provider(&config).unwrap();
        let creds = Credentials::new();
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "anonymous");
    }

    #[tokio::test]
    async fn test_build_bearer_auth() {
        let mut tokens = HashMap::new();
        tokens.insert("secret-abc".to_string(), "alice".to_string());
        let config = ServerAuthConfig {
            provider: "bearer".to_string(),
            bearer: Some(BearerConfig { tokens }),
            ..Default::default()
        };
        let provider = build_auth_provider(&config).unwrap();

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer secret-abc".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
    }

    #[tokio::test]
    async fn test_build_bearer_missing_config() {
        let config = ServerAuthConfig {
            provider: "bearer".to_string(),
            bearer: None,
            ..Default::default()
        };
        assert!(build_auth_provider(&config).is_err());
    }

    #[tokio::test]
    async fn test_build_forwarded_auth() {
        let config = ServerAuthConfig {
            provider: "forwarded".to_string(),
            forwarded: Some(ForwardedConfig {
                header: "x-forwarded-user".to_string(),
            }),
            ..Default::default()
        };
        let provider = build_auth_provider(&config).unwrap();

        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "bob".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "bob");
    }

    #[test]
    fn test_build_unknown_provider() {
        let config = ServerAuthConfig {
            provider: "jwt".to_string(),
            ..Default::default()
        };
        assert!(build_auth_provider(&config).is_err());
    }

    #[test]
    fn test_default_config_deserialize() {
        let json = r#"{}"#;
        let config: ServerAuthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.provider, "none");
        assert!(config.bearer.is_none());
        assert!(config.acl.is_none());
    }

    #[test]
    fn test_full_config_deserialize() {
        let json = r#"{
            "provider": "bearer",
            "bearer": {
                "tokens": {
                    "tok-1": "alice",
                    "tok-2": "bob"
                }
            },
            "acl": {
                "default": "allow",
                "rules": [
                    {"subjects": ["bob"], "tools": ["sentry__*"], "policy": "deny"}
                ]
            }
        }"#;
        let config: ServerAuthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.provider, "bearer");
        assert_eq!(config.bearer.unwrap().tokens.len(), 2);
        let acl = config.acl.unwrap();
        assert_eq!(acl.rules.len(), 1);
    }
}
