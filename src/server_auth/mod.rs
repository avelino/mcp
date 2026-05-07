mod acl;
pub mod oauth_as;
mod providers;

pub(crate) use acl::glob_match;
pub use acl::{AclConfig, Decision, MatchedRule, PromptContext, ResourceContext, ToolContext};
pub use oauth_as::OAuthAsConfig;
pub use providers::{BearerTokenAuth, ForwardedUserAuth, NoAuth, ProviderChain};

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
///
/// `providers` lists every provider that runs on `/mcp` requests, in
/// order. The composite [`ProviderChain`] tries each one until the
/// first acceptance. This shape is what makes the issue #90 use case
/// work: a single `mcp serve` instance accepts both static bearer
/// tokens (local dev) and OAuth-issued JWTs (Claude.ai web) at the
/// same endpoint.
///
/// Sub-configs are looked up by provider name:
/// - `"bearer"` → reads [`Self::bearer`].
/// - `"forwarded"` → reads [`Self::forwarded`].
/// - `"oauth_as"` → reads [`Self::oauth_as`].
/// - `"none"` is also accepted, yielding `NoAuth` (anonymous).
///
/// Empty `providers` is equivalent to `["none"]` — anonymous access,
/// useful for stdio mode and local dev with no auth at all.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct ServerAuthConfig {
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub bearer: Option<BearerConfig>,
    #[serde(default)]
    pub forwarded: Option<ForwardedConfig>,
    #[serde(default, rename = "oauthAs")]
    pub oauth_as: Option<OAuthAsConfig>,
    #[serde(default)]
    pub acl: Option<AclConfig>,
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

/// Build an AuthProvider chain from config.
///
/// Each name in `config.providers` is resolved to a concrete provider
/// and wrapped in a [`ProviderChain`] that tries them in order. Boot
/// fails fast if a name references a sub-config that is missing —
/// silent fallback would let a misconfigured deploy run with weaker
/// auth than the operator intended.
///
/// `as_state` is required iff `"oauth_as"` is in `providers`: the
/// JWT validator needs the registered-client store to enforce
/// audience checks against revocation. Callers (typically `run_http`)
/// load the state from disk and pass an `Arc` here.
///
/// Schema is intentionally not backwards-compatible with the legacy
/// `provider: String` field: configs that still carry it deserialize
/// into an empty `providers` vec, which boots as `NoAuth`. Operators
/// upgrading must rewrite their `serverAuth` block — the breaking
/// change is documented in `docs/howto/oauth-as.md`.
pub fn build_auth_provider(
    config: &ServerAuthConfig,
    as_state: Option<&Arc<oauth_as::AsState>>,
) -> Result<Arc<dyn AuthProvider>> {
    if config.providers.is_empty() {
        return Ok(Arc::new(NoAuth));
    }

    let mut providers: Vec<Arc<dyn AuthProvider>> = Vec::with_capacity(config.providers.len());
    for name in &config.providers {
        let p: Arc<dyn AuthProvider> = match name.as_str() {
            "none" => Arc::new(NoAuth),
            "bearer" => {
                let bearer = config.bearer.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "providers includes 'bearer' but 'bearer' sub-config is missing"
                    )
                })?;
                Arc::new(BearerTokenAuth::new(bearer.tokens.clone()))
            }
            "forwarded" => {
                let (header, groups_header) = config
                    .forwarded
                    .as_ref()
                    .map(|f| (f.header.clone(), f.groups_header.clone()))
                    .unwrap_or_else(|| (default_header(), default_groups_header()));
                Arc::new(ForwardedUserAuth::new(header, groups_header))
            }
            "oauth_as" => {
                let oauth = config.oauth_as.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "providers includes 'oauth_as' but 'oauthAs' sub-config is missing"
                    )
                })?;
                oauth.validate()?;
                let state = as_state.cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "providers includes 'oauth_as' but no AS state was provided to \
                         build_auth_provider — caller must load it before this call"
                    )
                })?;
                Arc::new(oauth_as::OAuthAsAuth::new(Arc::new(oauth.clone()), state))
            }
            other => anyhow::bail!("unknown auth provider: {other}"),
        };
        providers.push(p);
    }

    Ok(Arc::new(ProviderChain::new(providers)))
}

/// Check if a resource is allowed for the given identity.
pub fn is_resource_allowed(
    identity: &AuthIdentity,
    resource_uri: &str,
    acl: &Option<AclConfig>,
    ctx: Option<&acl::ResourceContext>,
    is_list: bool,
) -> Decision {
    match acl {
        Some(acl) => acl::is_resource_allowed(identity, resource_uri, acl, ctx, is_list),
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

/// Check if a prompt is allowed for the given identity.
pub fn is_prompt_allowed(
    identity: &AuthIdentity,
    prompt_name: &str,
    acl: &Option<AclConfig>,
    ctx: Option<&acl::PromptContext>,
    is_list: bool,
) -> Decision {
    match acl {
        Some(acl) => acl::is_prompt_allowed(identity, prompt_name, acl, ctx, is_list),
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
    async fn test_build_no_auth_for_empty_providers() {
        // Empty providers list = anonymous, suitable for stdio/dev.
        let config = ServerAuthConfig::default();
        let provider = build_auth_provider(&config, None).unwrap();
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
            providers: vec!["bearer".to_string()],
            bearer: Some(BearerConfig { tokens }),
            ..Default::default()
        };
        let provider = build_auth_provider(&config, None).unwrap();

        let mut creds = Credentials::new();
        creds.insert("authorization".to_string(), "Bearer secret-abc".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "alice");
    }

    #[tokio::test]
    async fn test_build_bearer_missing_config_fails_at_boot() {
        // Listing 'bearer' without a 'bearer' sub-config is a misconfig
        // that must NOT silently fall back to NoAuth.
        let config = ServerAuthConfig {
            providers: vec!["bearer".to_string()],
            bearer: None,
            ..Default::default()
        };
        let err = match build_auth_provider(&config, None) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("bearer"));
    }

    #[tokio::test]
    async fn test_build_forwarded_auth() {
        let config = ServerAuthConfig {
            providers: vec!["forwarded".to_string()],
            forwarded: Some(ForwardedConfig {
                header: "x-forwarded-user".to_string(),
                groups_header: "x-forwarded-groups".to_string(),
            }),
            ..Default::default()
        };
        let provider = build_auth_provider(&config, None).unwrap();

        let mut creds = Credentials::new();
        creds.insert("x-forwarded-user".to_string(), "bob".to_string());
        let identity = provider.authenticate(&creds).await.unwrap();
        assert_eq!(identity.subject, "bob");
    }

    #[test]
    fn test_build_unknown_provider() {
        let config = ServerAuthConfig {
            providers: vec!["jwt".to_string()],
            ..Default::default()
        };
        let err = match build_auth_provider(&config, None) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("unknown auth provider"));
    }

    #[test]
    fn test_build_oauth_as_without_subconfig_fails_at_boot() {
        // Same security guard as bearer/forwarded: missing sub-config
        // must NOT be papered over as NoAuth.
        let config = ServerAuthConfig {
            providers: vec!["oauth_as".to_string()],
            oauth_as: None,
            ..Default::default()
        };
        let err = match build_auth_provider(&config, None) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("oauthAs"));
    }

    #[tokio::test]
    async fn test_build_chain_with_bearer_and_forwarded() {
        // The actual issue #90 case: two providers active in parallel.
        // Static bearer covers local dev; forwarded covers proxy-fronted
        // deployments. Both must work in the same instance.
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-local".to_string(),
            BearerToken::Subject("avelino".to_string()),
        );
        let config = ServerAuthConfig {
            providers: vec!["bearer".to_string(), "forwarded".to_string()],
            bearer: Some(BearerConfig { tokens }),
            forwarded: Some(ForwardedConfig {
                header: "x-forwarded-user".to_string(),
                groups_header: "x-forwarded-groups".to_string(),
            }),
            ..Default::default()
        };
        let provider = build_auth_provider(&config, None).unwrap();

        // Path A: static bearer.
        let mut a = Credentials::new();
        a.insert("authorization".to_string(), "Bearer tok-local".to_string());
        assert_eq!(provider.authenticate(&a).await.unwrap().subject, "avelino");

        // Path B: forwarded header. Same instance, no reconfiguration.
        let mut b = Credentials::new();
        b.insert("x-forwarded-user".to_string(), "alice".to_string());
        assert_eq!(provider.authenticate(&b).await.unwrap().subject, "alice");
    }

    #[test]
    fn test_default_config_deserialize() {
        let json = r#"{}"#;
        let config: ServerAuthConfig = serde_json::from_str(json).unwrap();
        assert!(config.providers.is_empty());
        assert!(config.bearer.is_none());
        assert!(config.oauth_as.is_none());
        assert!(config.acl.is_none());
    }

    #[test]
    fn test_full_config_deserialize() {
        let json = r#"{
            "providers": ["bearer"],
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
        assert_eq!(config.providers, vec!["bearer".to_string()]);
        assert_eq!(config.bearer.unwrap().tokens.len(), 2);
        let acl = config.acl.unwrap();
        match &acl {
            AclConfig::Legacy(legacy) => assert_eq!(legacy.rules.len(), 1),
            AclConfig::RoleBased(_) => panic!("expected legacy schema"),
        }
    }

    #[test]
    fn test_legacy_provider_field_is_ignored_silently_into_no_auth() {
        // No backwards-compat: the old `provider: "bearer"` field is
        // not recognized. With #[serde(default)] on `providers`, the
        // unknown key is dropped and the chain becomes empty → NoAuth.
        // This is the documented breaking change for issue #90 — old
        // configs do not auto-upgrade.
        let json = r#"{
            "provider": "bearer",
            "bearer": { "tokens": { "tok-1": "alice" } }
        }"#;
        let config: ServerAuthConfig = serde_json::from_str(json).unwrap();
        assert!(
            config.providers.is_empty(),
            "legacy `provider` field must NOT auto-populate `providers`"
        );
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
