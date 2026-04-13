use std::collections::HashMap;
use std::fmt;

use serde::Deserialize;

use crate::classifier::{Kind, Source, ToolClassification};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AclPolicy {
    Allow,
    Deny,
}

pub(super) fn default_policy() -> AclPolicy {
    AclPolicy::Allow
}

// ---------------------------------------------------------------------------
// Legacy schema (first-match-wins, flat rules list)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct AclRule {
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub tools: Vec<String>,
    pub policy: AclPolicy,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LegacyAclConfig {
    #[serde(default = "default_policy")]
    pub default: AclPolicy,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

// ---------------------------------------------------------------------------
// New role-based schema
// ---------------------------------------------------------------------------

/// A single server string or array of server globs.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ServerPattern {
    Single(String),
    Multiple(Vec<String>),
}

/// The access level for a grant.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    Read,
    Write,
    #[serde(rename = "*")]
    All,
}

impl AccessLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessLevel::Read => "read",
            AccessLevel::Write => "write",
            AccessLevel::All => "*",
        }
    }
}

/// A single grant entry within a role definition or a subject's `extra` list.
#[derive(Debug, Clone, Deserialize)]
pub struct Grant {
    pub server: ServerPattern,
    pub access: AccessLevel,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub prompts: Vec<String>,
    #[serde(default)]
    pub deny: bool,
}

/// Per-subject configuration: assigned roles + optional extra grants.
#[derive(Debug, Clone, Deserialize)]
pub struct SubjectConfig {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub extra: Vec<Grant>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleBasedAclConfig {
    #[serde(default = "default_policy")]
    pub default: AclPolicy,
    #[serde(default, rename = "strictClassification")]
    pub strict_classification: bool,
    #[serde(default)]
    pub roles: HashMap<String, Vec<Grant>>,
    #[serde(default)]
    pub subjects: HashMap<String, SubjectConfig>,
}

// ---------------------------------------------------------------------------
// ToolContext — coordinates for role-based evaluation
// ---------------------------------------------------------------------------

pub struct ToolContext<'a> {
    pub server_alias: &'a str,
    pub tool_name: &'a str,
    pub classification: Option<&'a ToolClassification>,
}

pub struct ResourceContext<'a> {
    pub server_alias: &'a str,
    pub resource_uri: &'a str,
}

pub struct PromptContext<'a> {
    pub server_alias: &'a str,
    pub prompt_name: &'a str,
}

// ---------------------------------------------------------------------------
// Decision — structured result from ACL evaluation
// ---------------------------------------------------------------------------

/// Stable identifier for the rule that determined the access decision.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchedRule {
    /// Legacy schema: rule at index N matched.
    Legacy(usize),
    /// Legacy schema default policy.
    LegacyDefault,
    /// RBAC: grant from role at grant-index within that role.
    RoleGrant { role: String, index: usize },
    /// RBAC: extra grant on a subject.
    SubjectExtra { subject: String, index: usize },
    /// RBAC default policy.
    RbacDefault,
    /// No ACL configured.
    NoAcl,
}

impl fmt::Display for MatchedRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchedRule::Legacy(i) => write!(f, "legacy[{i}]"),
            MatchedRule::LegacyDefault => write!(f, "legacy:default"),
            MatchedRule::RoleGrant { role, index } => write!(f, "{role}[{index}]"),
            MatchedRule::SubjectExtra { subject, index } => {
                write!(f, "{subject}.extra[{index}]")
            }
            MatchedRule::RbacDefault => write!(f, "default"),
            MatchedRule::NoAcl => write!(f, "no-acl"),
        }
    }
}

/// Structured result from ACL evaluation, carrying the decision and its provenance.
#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub matched_rule: MatchedRule,
    pub classification_kind: Option<Kind>,
    pub classification_source: Option<Source>,
    pub classification_confidence: Option<f32>,
    pub access_evaluated: Option<AccessLevel>,
}

impl Decision {
    pub(super) fn from_ctx(
        allowed: bool,
        matched_rule: MatchedRule,
        ctx: Option<&ToolContext>,
    ) -> Self {
        let (kind, source, confidence) = match ctx.and_then(|c| c.classification) {
            Some(cls) => (Some(cls.kind), Some(cls.source), Some(cls.confidence)),
            None => (None, None, None),
        };
        Self {
            allowed,
            matched_rule,
            classification_kind: kind,
            classification_source: source,
            classification_confidence: confidence,
            access_evaluated: None,
        }
    }
}

/// A grant tagged with its provenance (which role/subject it came from).
pub(super) struct TaggedGrant<'a> {
    pub grant: &'a Grant,
    pub origin: MatchedRule,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matched_rule_display() {
        assert_eq!(MatchedRule::Legacy(0).to_string(), "legacy[0]");
        assert_eq!(MatchedRule::Legacy(3).to_string(), "legacy[3]");
        assert_eq!(MatchedRule::LegacyDefault.to_string(), "legacy:default");
        assert_eq!(
            MatchedRule::RoleGrant {
                role: "dev".to_string(),
                index: 1
            }
            .to_string(),
            "dev[1]"
        );
        assert_eq!(
            MatchedRule::SubjectExtra {
                subject: "alice".to_string(),
                index: 0
            }
            .to_string(),
            "alice.extra[0]"
        );
        assert_eq!(MatchedRule::RbacDefault.to_string(), "default");
        assert_eq!(MatchedRule::NoAcl.to_string(), "no-acl");
    }

    #[test]
    fn test_decision_access_level_as_str() {
        assert_eq!(AccessLevel::Read.as_str(), "read");
        assert_eq!(AccessLevel::Write.as_str(), "write");
        assert_eq!(AccessLevel::All.as_str(), "*");
    }

    // -----------------------------------------------------------------------
    // Deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_acl_config_deserialize() {
        let json = r#"{
            "default": "deny",
            "rules": [
                {
                    "subjects": ["alice"],
                    "tools": ["*"],
                    "policy": "allow"
                },
                {
                    "roles": ["viewer"],
                    "tools": ["sentry__*"],
                    "policy": "allow"
                }
            ]
        }"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        match &acl {
            super::super::AclConfig::Legacy(legacy) => {
                assert_eq!(legacy.default, AclPolicy::Deny);
                assert_eq!(legacy.rules.len(), 2);
                assert_eq!(legacy.rules[0].subjects, vec!["alice"]);
                assert!(legacy.rules[0].roles.is_empty());
                assert_eq!(legacy.rules[1].roles, vec!["viewer"]);
            }
            super::super::AclConfig::RoleBased(_) => panic!("expected legacy schema"),
        }
    }

    #[test]
    fn test_acl_default_deserialize() {
        let json = r#"{"rules": []}"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        match &acl {
            super::super::AclConfig::Legacy(legacy) => assert_eq!(legacy.default, AclPolicy::Allow),
            super::super::AclConfig::RoleBased(_) => panic!("expected legacy schema"),
        }
    }

    // -----------------------------------------------------------------------
    // Schema detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_deserialize_rbac_schema() {
        let json = r#"{
            "default": "deny",
            "roles": {
                "admin": [{ "server": "*", "access": "*" }]
            },
            "subjects": {
                "alice": { "roles": ["admin"] }
            }
        }"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        match &acl {
            super::super::AclConfig::RoleBased(rbac) => {
                assert_eq!(rbac.default, AclPolicy::Deny);
                assert!(rbac.roles.contains_key("admin"));
                assert!(rbac.subjects.contains_key("alice"));
            }
            super::super::AclConfig::Legacy(_) => panic!("expected role-based schema"),
        }
    }

    #[test]
    fn test_deserialize_subjects_only_schema() {
        let json = r#"{
            "default": "deny",
            "roles": { "dev": [{ "server": "*", "access": "read" }] },
            "subjects": {
                "bob": { "roles": ["dev"] }
            }
        }"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(acl, super::super::AclConfig::RoleBased(_)));
    }

    #[test]
    fn test_deserialize_both_schemas_error() {
        let json = r#"{
            "rules": [{"subjects": ["x"], "tools": ["*"], "policy": "allow"}],
            "roles": { "admin": [{ "server": "*", "access": "*" }] }
        }"#;
        let result: Result<super::super::AclConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot have both"));
    }

    #[test]
    fn test_deserialize_empty_acl() {
        let json = r#"{}"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        match &acl {
            super::super::AclConfig::Legacy(legacy) => {
                assert_eq!(legacy.default, AclPolicy::Allow);
                assert!(legacy.rules.is_empty());
            }
            super::super::AclConfig::RoleBased(_) => panic!("expected legacy for empty config"),
        }
    }

    #[test]
    fn test_deserialize_rbac_strict_classification() {
        let json = r#"{
            "default": "deny",
            "strictClassification": true,
            "roles": {}
        }"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        match &acl {
            super::super::AclConfig::RoleBased(rbac) => assert!(rbac.strict_classification),
            super::super::AclConfig::Legacy(_) => panic!("expected role-based schema"),
        }
    }

    #[test]
    fn test_deserialize_rbac_full_example() {
        let json = r#"{
            "default": "deny",
            "strictClassification": false,
            "roles": {
                "admin":    [{ "server": "*", "access": "*" }],
                "dev": [
                    { "server": ["github", "grafana"], "access": "read" },
                    { "server": "github", "access": "write", "tools": ["gh_pr", "gh_issue"] }
                ],
                "readonly": [{ "server": "*", "access": "read" }]
            },
            "subjects": {
                "alice":   { "roles": ["admin"] },
                "bob":     { "roles": ["dev"] },
                "charlie": {
                    "roles": ["readonly"],
                    "extra": [{ "server": "sentry", "access": "read", "resources": ["issue://*"] }]
                }
            }
        }"#;
        let acl: super::super::AclConfig = serde_json::from_str(json).unwrap();
        match &acl {
            super::super::AclConfig::RoleBased(rbac) => {
                assert_eq!(rbac.roles.len(), 3);
                assert_eq!(rbac.subjects.len(), 3);
                assert!(!rbac.strict_classification);
                let dev_grants = &rbac.roles["dev"];
                assert_eq!(dev_grants.len(), 2);
                let charlie = &rbac.subjects["charlie"];
                assert_eq!(charlie.extra.len(), 1);
                assert_eq!(charlie.extra[0].resources, vec!["issue://*"]);
            }
            super::super::AclConfig::Legacy(_) => panic!("expected role-based schema"),
        }
    }

    #[test]
    fn test_deserialize_roles_wrong_type_errors() {
        let json = r#"{
            "default": "deny",
            "roles": ["admin"]
        }"#;
        let result: Result<super::super::AclConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_subjects_wrong_type_errors() {
        let json = r#"{
            "default": "deny",
            "subjects": "alice"
        }"#;
        let result: Result<super::super::AclConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_unknown_role_reference_errors() {
        let json = r#"{
            "default": "deny",
            "roles": {
                "admin": [{ "server": "*", "access": "*" }]
            },
            "subjects": {
                "alice": { "roles": ["nonexistent"] }
            }
        }"#;
        let result: Result<super::super::AclConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown role"));
    }
}
