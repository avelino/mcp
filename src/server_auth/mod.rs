mod acl;
mod providers;

pub(crate) use acl::glob_match;
pub use acl::{AclConfig, Decision, MatchedRule, ToolContext};
pub use providers::{BearerTokenAuth, ForwardedUserAuth, NoAuth};

// Re-exported for tests in other modules (serve.rs)
#[cfg(test)]
pub use acl::{AclPolicy, AclRule};

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

/// A single bearer token entry. Accepts two shapes for backwards compatibility:
/// - Legacy: `"tok-alice": "alice"` → subject only, no roles.
/// - Extended: `"tok-bob": { "subject": "bob", "roles": ["dev"] }`.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum BearerToken {
    Subject(String),
    Extended {
        subject: String,
        #[serde(default)]
        roles: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct BearerConfig {
    pub tokens: HashMap<String, BearerToken>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForwardedConfig {
    #[serde(default = "default_header")]
    pub header: String,
    #[serde(default = "default_groups_header")]
    pub groups_header: String,
}

fn default_header() -> String {
    "x-forwarded-user".to_string()
}

fn default_groups_header() -> String {
    "x-forwarded-groups".to_string()
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
            let (header, groups_header) = config
                .forwarded
                .as_ref()
                .map(|f| (f.header.clone(), f.groups_header.clone()))
                .unwrap_or_else(|| (default_header(), default_groups_header()));
            Ok(Arc::new(ForwardedUserAuth::new(header, groups_header)))
        }
        other => anyhow::bail!("unknown auth provider: {other}"),
    }
}

/// Check if a tool is allowed for the given identity.
pub fn is_tool_allowed(
    identity: &AuthIdentity,
    tool_name: &str,
    acl: &Option<AclConfig>,
    ctx: Option<&acl::ToolContext>,
) -> Decision {
    match acl {
        Some(acl) => acl::is_tool_allowed(identity, tool_name, acl, ctx),
        None => Decision {
            allowed: true,
            matched_rule: MatchedRule::NoAcl,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
            access_evaluated: None,
        },
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
        tokens.insert(
            "secret-abc".to_string(),
            BearerToken::Subject("alice".to_string()),
        );
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
                groups_header: "x-forwarded-groups".to_string(),
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
        match &acl {
            AclConfig::Legacy(legacy) => assert_eq!(legacy.rules.len(), 1),
            AclConfig::RoleBased(_) => panic!("expected legacy schema"),
        }
    }

    #[test]
    fn test_bearer_config_deserialize_mixed() {
        // Legacy string form and extended object form must coexist.
        let json = r#"{
            "tokens": {
                "tok-alice": "alice",
                "tok-bob": { "subject": "bob", "roles": ["dev", "oncall"] },
                "tok-carol": { "subject": "carol" }
            }
        }"#;
        let cfg: BearerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.tokens.len(), 3);
        match cfg.tokens.get("tok-alice").unwrap() {
            BearerToken::Subject(s) => assert_eq!(s, "alice"),
            _ => panic!("expected legacy subject form for tok-alice"),
        }
        match cfg.tokens.get("tok-bob").unwrap() {
            BearerToken::Extended { subject, roles } => {
                assert_eq!(subject, "bob");
                assert_eq!(roles, &vec!["dev".to_string(), "oncall".to_string()]);
            }
            _ => panic!("expected extended form for tok-bob"),
        }
        // Missing roles defaults to empty vec.
        match cfg.tokens.get("tok-carol").unwrap() {
            BearerToken::Extended { subject, roles } => {
                assert_eq!(subject, "carol");
                assert!(roles.is_empty());
            }
            _ => panic!("expected extended form for tok-carol"),
        }
    }

    #[test]
    fn test_bearer_config_deserialize_malformed_roles_type() {
        // roles must be an array — string should fail.
        let json = r#"{
            "tokens": {
                "tok-x": { "subject": "x", "roles": "admin" }
            }
        }"#;
        assert!(serde_json::from_str::<BearerConfig>(json).is_err());
    }

    #[test]
    fn test_bearer_config_deserialize_extended_missing_subject() {
        // Extended form without subject is invalid.
        let json = r#"{
            "tokens": {
                "tok-x": { "roles": ["dev"] }
            }
        }"#;
        assert!(serde_json::from_str::<BearerConfig>(json).is_err());
    }

    #[test]
    fn test_forwarded_config_default_groups_header() {
        let json = r#"{}"#;
        let cfg: ForwardedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.header, "x-forwarded-user");
        assert_eq!(cfg.groups_header, "x-forwarded-groups");
    }

    #[test]
    fn test_forwarded_config_custom_groups_header() {
        let json = r#"{"header":"x-user","groups_header":"x-groups"}"#;
        let cfg: ForwardedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.header, "x-user");
        assert_eq!(cfg.groups_header, "x-groups");
    }
}
