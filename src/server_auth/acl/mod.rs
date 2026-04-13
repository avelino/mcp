mod eval;
pub(crate) mod glob;
pub mod types;

use serde::Deserialize;

pub(crate) use glob::glob_match;
pub use types::{AclPolicy, Decision, MatchedRule, PromptContext, ResourceContext, ToolContext};

// Re-exported for tests in other modules (serve.rs)
#[cfg(test)]
pub use types::AclRule;
use types::{LegacyAclConfig, RoleBasedAclConfig};

use crate::server_auth::AuthIdentity;

// ---------------------------------------------------------------------------
// Unified AclConfig enum with custom deserializer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum AclConfig {
    Legacy(LegacyAclConfig),
    RoleBased(RoleBasedAclConfig),
}

impl<'de> Deserialize<'de> for AclConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        let obj = raw
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("ACL config must be a JSON object"))?;

        let has_rules = obj.contains_key("rules");
        let has_roles = obj.contains_key("roles");
        let has_subjects = obj.contains_key("subjects");
        let is_new = has_roles || has_subjects;

        if has_rules && is_new {
            return Err(serde::de::Error::custom(
                "ACL config cannot have both 'rules' (legacy) and 'roles'/'subjects' (new schema)",
            ));
        }

        if is_new {
            let rbac: RoleBasedAclConfig =
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?;
            // Validate that all roles referenced by subjects exist in the roles map.
            for (subject, config) in &rbac.subjects {
                for role in &config.roles {
                    if !rbac.roles.contains_key(role) {
                        return Err(serde::de::Error::custom(format!(
                            "subject '{}' references unknown role '{}'",
                            subject, role
                        )));
                    }
                }
            }
            Ok(AclConfig::RoleBased(rbac))
        } else {
            let legacy: LegacyAclConfig =
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?;
            Ok(AclConfig::Legacy(legacy))
        }
    }
}

#[cfg(test)]
impl AclConfig {
    pub fn legacy(default: AclPolicy, rules: Vec<AclRule>) -> Self {
        AclConfig::Legacy(LegacyAclConfig { default, rules })
    }
}

// ---------------------------------------------------------------------------
// Unified dispatchers
// ---------------------------------------------------------------------------

/// Check if a tool is allowed for the given identity.
/// Legacy schema uses first-match-wins; role-based uses union evaluation.
/// Returns a structured `Decision` with provenance information.
pub fn is_tool_allowed(
    identity: &AuthIdentity,
    tool_name: &str,
    acl: &AclConfig,
    ctx: Option<&ToolContext>,
) -> Decision {
    match acl {
        AclConfig::Legacy(legacy) => eval::legacy_is_tool_allowed(identity, tool_name, legacy, ctx),
        AclConfig::RoleBased(rbac) => match ctx {
            Some(c) => eval::is_tool_allowed_rbac(identity, c, rbac),
            None => Decision::from_ctx(
                rbac.default == AclPolicy::Allow,
                MatchedRule::RbacDefault,
                None,
            ),
        },
    }
}

pub fn is_resource_allowed(
    identity: &AuthIdentity,
    resource_uri: &str,
    acl: &AclConfig,
    ctx: Option<&ResourceContext>,
) -> Decision {
    eval::is_resource_allowed(identity, resource_uri, acl, ctx)
}

pub fn is_prompt_allowed(
    identity: &AuthIdentity,
    prompt_name: &str,
    acl: &AclConfig,
    ctx: Option<&PromptContext>,
) -> Decision {
    eval::is_prompt_allowed(identity, prompt_name, acl, ctx)
}
