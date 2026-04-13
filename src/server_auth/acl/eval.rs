use crate::classifier::Kind;

use super::glob::glob_match;
use super::types::{
    AccessLevel, AclPolicy, AclRule, Decision, Grant, LegacyAclConfig, MatchedRule, PromptContext,
    ResourceContext, RoleBasedAclConfig, ServerPattern, TaggedGrant, ToolContext,
};
use crate::server_auth::AuthIdentity;

// ---------------------------------------------------------------------------
// Legacy evaluator (first-match-wins, unchanged logic)
// ---------------------------------------------------------------------------

pub(super) fn legacy_is_tool_allowed(
    identity: &AuthIdentity,
    tool_name: &str,
    acl: &LegacyAclConfig,
    ctx: Option<&ToolContext>,
) -> Decision {
    for (i, rule) in acl.rules.iter().enumerate() {
        if !matches_identity(identity, rule) {
            continue;
        }
        if !matches_tool(tool_name, &rule.tools) {
            continue;
        }
        return Decision::from_ctx(rule.policy == AclPolicy::Allow, MatchedRule::Legacy(i), ctx);
    }
    Decision::from_ctx(
        acl.default == AclPolicy::Allow,
        MatchedRule::LegacyDefault,
        ctx,
    )
}

pub(super) fn matches_identity(identity: &AuthIdentity, rule: &AclRule) -> bool {
    let subject_match = rule.subjects.is_empty()
        || rule
            .subjects
            .iter()
            .any(|s| s == &identity.subject || s == "*");

    let role_match = rule.roles.is_empty()
        || rule
            .roles
            .iter()
            .any(|r| identity.roles.contains(r) || r == "*");

    subject_match && role_match
}

pub(super) fn matches_tool(tool_name: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| glob_match(pattern, tool_name))
}

// ---------------------------------------------------------------------------
// Role-based evaluator (union semantics)
// ---------------------------------------------------------------------------

pub(super) fn is_tool_allowed_rbac(
    identity: &AuthIdentity,
    ctx: &ToolContext,
    acl: &RoleBasedAclConfig,
) -> Decision {
    let (role_names, extra_grants) = resolve_subject(identity, acl);

    let (cls_kind, cls_source, cls_confidence) = match ctx.classification {
        Some(cls) => (Some(cls.kind), Some(cls.source), Some(cls.confidence)),
        None => (None, None, None),
    };

    // Collect all grants tagged with provenance.
    let mut all_grants: Vec<TaggedGrant> = Vec::new();
    for role_name in &role_names {
        if let Some(grants) = acl.roles.get(role_name) {
            for (i, grant) in grants.iter().enumerate() {
                all_grants.push(TaggedGrant {
                    grant,
                    origin: MatchedRule::RoleGrant {
                        role: role_name.clone(),
                        index: i,
                    },
                });
            }
        }
    }
    for (i, grant) in extra_grants.iter().enumerate() {
        all_grants.push(TaggedGrant {
            grant,
            origin: MatchedRule::SubjectExtra {
                subject: identity.subject.clone(),
                index: i,
            },
        });
    }

    // Filter to grants that match server + tool.
    let matching: Vec<&TaggedGrant> = all_grants
        .iter()
        .filter(|tg| {
            matches_server(tg.grant, ctx.server_alias)
                && matches_tool_grant(tg.grant, ctx.tool_name)
        })
        .collect();

    let kind = ctx.classification.map(|c| c.kind);

    // Union evaluation: deny always wins, but only for grants that also
    // cover the current access classification.
    if let Some(tg) = matching
        .iter()
        .find(|tg| tg.grant.deny && deny_covers_access(tg.grant, kind, acl.strict_classification))
    {
        return Decision {
            allowed: false,
            matched_rule: tg.origin.clone(),
            classification_kind: cls_kind,
            classification_source: cls_source,
            classification_confidence: cls_confidence,
            access_evaluated: Some(tg.grant.access.clone()),
        };
    }

    if let Some(tg) = matching
        .iter()
        .find(|tg| grant_covers_access(tg.grant, kind, acl.strict_classification))
    {
        return Decision {
            allowed: true,
            matched_rule: tg.origin.clone(),
            classification_kind: cls_kind,
            classification_source: cls_source,
            classification_confidence: cls_confidence,
            access_evaluated: Some(tg.grant.access.clone()),
        };
    }

    // No matching grant -> fall back to default.
    Decision {
        allowed: acl.default == AclPolicy::Allow,
        matched_rule: MatchedRule::RbacDefault,
        classification_kind: cls_kind,
        classification_source: cls_source,
        classification_confidence: cls_confidence,
        access_evaluated: None,
    }
}

/// Resolve roles and extra grants for an identity.
pub(super) fn resolve_subject<'a>(
    identity: &AuthIdentity,
    acl: &'a RoleBasedAclConfig,
) -> (Vec<String>, Vec<&'a Grant>) {
    let mut role_names: Vec<String> = identity.roles.clone();
    let mut extra: Vec<&Grant> = Vec::new();

    if let Some(subj_config) = acl.subjects.get(&identity.subject) {
        for r in &subj_config.roles {
            if !role_names.contains(r) {
                role_names.push(r.clone());
            }
        }
        extra.extend(subj_config.extra.iter());
    }

    (role_names, extra)
}

pub(super) fn matches_server(grant: &Grant, server: &str) -> bool {
    match &grant.server {
        ServerPattern::Single(s) => glob_match(s, server),
        ServerPattern::Multiple(list) => list.iter().any(|s| glob_match(s, server)),
    }
}

pub(super) fn matches_tool_grant(grant: &Grant, tool_name: &str) -> bool {
    if grant.tools.is_empty() {
        return true;
    }
    grant
        .tools
        .iter()
        .any(|pattern| glob_match(pattern, tool_name))
}

pub(super) fn matches_resource_grant(grant: &Grant, resource_uri: &str) -> bool {
    if grant.resources.is_empty() {
        return true;
    }
    grant
        .resources
        .iter()
        .any(|pattern| glob_match(pattern, resource_uri))
}

pub(super) fn matches_prompt_grant(grant: &Grant, prompt_name: &str) -> bool {
    if grant.prompts.is_empty() {
        return true;
    }
    grant
        .prompts
        .iter()
        .any(|pattern| glob_match(pattern, prompt_name))
}

/// Check if a grant's access level covers read (for resources/prompts).
pub(super) fn grant_covers_read(grant: &Grant) -> bool {
    matches!(grant.access, AccessLevel::All | AccessLevel::Read)
}

/// Check if a resource is allowed for the given identity.
/// For legacy schemas, `is_list` controls behavior: listing is always allowed,
/// but read requires `default: allow`.
pub(super) fn is_resource_allowed(
    identity: &AuthIdentity,
    _resource_uri: &str,
    acl: &super::AclConfig,
    ctx: Option<&ResourceContext>,
    is_list: bool,
) -> Decision {
    match acl {
        super::AclConfig::Legacy(legacy) => {
            // Legacy: allow list unconditionally; deny read unless default is allow.
            let allowed = if is_list {
                true
            } else {
                legacy.default == AclPolicy::Allow
            };
            Decision {
                allowed,
                matched_rule: MatchedRule::LegacyDefault,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
                access_evaluated: Some(AccessLevel::Read),
            }
        }
        super::AclConfig::RoleBased(rbac) => match ctx {
            Some(c) => is_resource_allowed_rbac(identity, c, rbac),
            None => Decision {
                allowed: rbac.default == AclPolicy::Allow,
                matched_rule: MatchedRule::RbacDefault,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
                access_evaluated: None,
            },
        },
    }
}

/// Check if a prompt is allowed for the given identity.
/// For legacy schemas, `is_list` controls behavior: listing is always allowed,
/// but get requires `default: allow`.
pub(super) fn is_prompt_allowed(
    identity: &AuthIdentity,
    _prompt_name: &str,
    acl: &super::AclConfig,
    ctx: Option<&PromptContext>,
    is_list: bool,
) -> Decision {
    match acl {
        super::AclConfig::Legacy(legacy) => {
            // Legacy: allow list unconditionally; deny get unless default is allow.
            let allowed = if is_list {
                true
            } else {
                legacy.default == AclPolicy::Allow
            };
            Decision {
                allowed,
                matched_rule: MatchedRule::LegacyDefault,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
                access_evaluated: Some(AccessLevel::Read),
            }
        }
        super::AclConfig::RoleBased(rbac) => match ctx {
            Some(c) => is_prompt_allowed_rbac(identity, c, rbac),
            None => Decision {
                allowed: rbac.default == AclPolicy::Allow,
                matched_rule: MatchedRule::RbacDefault,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
                access_evaluated: None,
            },
        },
    }
}

fn is_resource_allowed_rbac(
    identity: &AuthIdentity,
    ctx: &ResourceContext,
    acl: &RoleBasedAclConfig,
) -> Decision {
    let (role_names, extra_grants) = resolve_subject(identity, acl);

    let mut all_grants: Vec<TaggedGrant> = Vec::new();
    for role_name in &role_names {
        if let Some(grants) = acl.roles.get(role_name) {
            for (i, grant) in grants.iter().enumerate() {
                all_grants.push(TaggedGrant {
                    grant,
                    origin: MatchedRule::RoleGrant {
                        role: role_name.clone(),
                        index: i,
                    },
                });
            }
        }
    }
    for (i, grant) in extra_grants.iter().enumerate() {
        all_grants.push(TaggedGrant {
            grant,
            origin: MatchedRule::SubjectExtra {
                subject: identity.subject.clone(),
                index: i,
            },
        });
    }

    let matching: Vec<&TaggedGrant> = all_grants
        .iter()
        .filter(|tg| {
            matches_server(tg.grant, ctx.server_alias)
                && matches_resource_grant(tg.grant, ctx.resource_uri)
        })
        .collect();

    // Deny always wins.
    if let Some(tg) = matching
        .iter()
        .find(|tg| tg.grant.deny && grant_covers_read(tg.grant))
    {
        return Decision {
            allowed: false,
            matched_rule: tg.origin.clone(),
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
            access_evaluated: Some(tg.grant.access.clone()),
        };
    }

    if let Some(tg) = matching
        .iter()
        .find(|tg| !tg.grant.deny && grant_covers_read(tg.grant))
    {
        return Decision {
            allowed: true,
            matched_rule: tg.origin.clone(),
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
            access_evaluated: Some(tg.grant.access.clone()),
        };
    }

    Decision {
        allowed: acl.default == AclPolicy::Allow,
        matched_rule: MatchedRule::RbacDefault,
        classification_kind: None,
        classification_source: None,
        classification_confidence: None,
        access_evaluated: None,
    }
}

fn is_prompt_allowed_rbac(
    identity: &AuthIdentity,
    ctx: &PromptContext,
    acl: &RoleBasedAclConfig,
) -> Decision {
    let (role_names, extra_grants) = resolve_subject(identity, acl);

    let mut all_grants: Vec<TaggedGrant> = Vec::new();
    for role_name in &role_names {
        if let Some(grants) = acl.roles.get(role_name) {
            for (i, grant) in grants.iter().enumerate() {
                all_grants.push(TaggedGrant {
                    grant,
                    origin: MatchedRule::RoleGrant {
                        role: role_name.clone(),
                        index: i,
                    },
                });
            }
        }
    }
    for (i, grant) in extra_grants.iter().enumerate() {
        all_grants.push(TaggedGrant {
            grant,
            origin: MatchedRule::SubjectExtra {
                subject: identity.subject.clone(),
                index: i,
            },
        });
    }

    let matching: Vec<&TaggedGrant> = all_grants
        .iter()
        .filter(|tg| {
            matches_server(tg.grant, ctx.server_alias)
                && matches_prompt_grant(tg.grant, ctx.prompt_name)
        })
        .collect();

    if let Some(tg) = matching
        .iter()
        .find(|tg| tg.grant.deny && grant_covers_read(tg.grant))
    {
        return Decision {
            allowed: false,
            matched_rule: tg.origin.clone(),
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
            access_evaluated: Some(tg.grant.access.clone()),
        };
    }

    if let Some(tg) = matching
        .iter()
        .find(|tg| !tg.grant.deny && grant_covers_read(tg.grant))
    {
        return Decision {
            allowed: true,
            matched_rule: tg.origin.clone(),
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
            access_evaluated: Some(tg.grant.access.clone()),
        };
    }

    Decision {
        allowed: acl.default == AclPolicy::Allow,
        matched_rule: MatchedRule::RbacDefault,
        classification_kind: None,
        classification_source: None,
        classification_confidence: None,
        access_evaluated: None,
    }
}

/// Check if a grant's access level covers the tool's classified kind (for allow grants).
pub(super) fn grant_covers_access(grant: &Grant, kind: Option<Kind>, strict: bool) -> bool {
    if grant.deny {
        return false;
    }
    // Strict mode blocks ambiguous tools entirely, regardless of access level.
    if strict && matches!(kind, Some(Kind::Ambiguous)) {
        return false;
    }
    match grant.access {
        AccessLevel::All => true,
        AccessLevel::Read => matches!(kind, Some(Kind::Read)),
        AccessLevel::Write => matches!(kind, Some(Kind::Write) | Some(Kind::Ambiguous)),
    }
}

/// Check if a deny grant's access level covers the tool's classified kind.
/// Same expansion logic as allow, but ignores the `deny` flag guard.
pub(super) fn deny_covers_access(grant: &Grant, kind: Option<Kind>, strict: bool) -> bool {
    if strict && matches!(kind, Some(Kind::Ambiguous)) {
        return true; // strict mode: deny always catches ambiguous
    }
    match grant.access {
        AccessLevel::All => true,
        AccessLevel::Read => matches!(kind, Some(Kind::Read)),
        AccessLevel::Write => matches!(kind, Some(Kind::Write) | Some(Kind::Ambiguous)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::SubjectConfig;
    use super::*;
    use crate::classifier::{Source, ToolClassification};
    use std::collections::HashMap;

    fn alice() -> AuthIdentity {
        AuthIdentity::new("alice", vec!["admin".to_string()])
    }

    fn bob() -> AuthIdentity {
        AuthIdentity::new("bob", vec!["viewer".to_string()])
    }

    fn anon() -> AuthIdentity {
        AuthIdentity::anonymous()
    }

    fn make_classification(kind: Kind) -> ToolClassification {
        ToolClassification {
            kind,
            confidence: 1.0,
            source: Source::Classifier,
            reasons: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // Legacy tests (unchanged logic, wrapped in AclConfig::Legacy)
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_allow_no_rules() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Allow, vec![]);
        assert!(super::super::is_tool_allowed(&alice(), "any_tool", &acl, None).allowed);
        assert!(super::super::is_tool_allowed(&anon(), "any_tool", &acl, None).allowed);
    }

    #[test]
    fn test_default_deny_no_rules() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Deny, vec![]);
        assert!(!super::super::is_tool_allowed(&alice(), "any_tool", &acl, None).allowed);
    }

    #[test]
    fn test_deny_specific_subject() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        );

        assert!(
            !super::super::is_tool_allowed(&bob(), "sentry__search_issues", &acl, None).allowed
        );
        assert!(super::super::is_tool_allowed(&bob(), "slack__send_message", &acl, None).allowed);
        assert!(
            super::super::is_tool_allowed(&alice(), "sentry__search_issues", &acl, None).allowed
        );
    }

    #[test]
    fn test_allow_specific_role() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Deny,
            vec![AclRule {
                subjects: vec![],
                roles: vec!["admin".to_string()],
                tools: vec!["*".to_string()],
                policy: AclPolicy::Allow,
            }],
        );

        assert!(super::super::is_tool_allowed(&alice(), "anything", &acl, None).allowed);
        assert!(!super::super::is_tool_allowed(&bob(), "anything", &acl, None).allowed);
    }

    #[test]
    fn test_first_match_wins() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Allow,
            vec![
                AclRule {
                    subjects: vec!["bob".to_string()],
                    roles: vec![],
                    tools: vec!["sentry__search_issues".to_string()],
                    policy: AclPolicy::Allow,
                },
                AclRule {
                    subjects: vec!["bob".to_string()],
                    roles: vec![],
                    tools: vec!["sentry__*".to_string()],
                    policy: AclPolicy::Deny,
                },
            ],
        );

        assert!(super::super::is_tool_allowed(&bob(), "sentry__search_issues", &acl, None).allowed);
        assert!(
            !super::super::is_tool_allowed(&bob(), "sentry__delete_project", &acl, None).allowed
        );
    }

    #[test]
    fn test_wildcard_subject() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Deny,
            vec![AclRule {
                subjects: vec!["*".to_string()],
                roles: vec![],
                tools: vec!["health__*".to_string()],
                policy: AclPolicy::Allow,
            }],
        );

        assert!(super::super::is_tool_allowed(&alice(), "health__check", &acl, None).allowed);
        assert!(super::super::is_tool_allowed(&bob(), "health__check", &acl, None).allowed);
        assert!(super::super::is_tool_allowed(&anon(), "health__check", &acl, None).allowed);
        assert!(!super::super::is_tool_allowed(&alice(), "sentry__search", &acl, None).allowed);
    }

    #[test]
    fn test_combined_subject_and_role() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec!["admin".to_string()],
                tools: vec!["dangerous__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        );

        assert!(super::super::is_tool_allowed(&bob(), "dangerous__delete", &acl, None).allowed);

        let bob_admin = AuthIdentity::new("bob", vec!["admin".to_string()]);
        assert!(
            !super::super::is_tool_allowed(&bob_admin, "dangerous__delete", &acl, None).allowed
        );
    }

    #[test]
    fn test_acl_with_contains_pattern() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["*admin*".to_string()],
                policy: AclPolicy::Deny,
            }],
        );

        assert!(!super::super::is_tool_allowed(&bob(), "admin_panel", &acl, None).allowed);
        assert!(!super::super::is_tool_allowed(&bob(), "user_admin_panel", &acl, None).allowed);
        assert!(super::super::is_tool_allowed(&bob(), "user_panel", &acl, None).allowed);
        assert!(super::super::is_tool_allowed(&alice(), "admin_panel", &acl, None).allowed);
    }

    // -----------------------------------------------------------------------
    // Grant matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_pattern_single() {
        let grant = Grant {
            server: ServerPattern::Single("github".to_string()),
            access: AccessLevel::All,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_server(&grant, "github"));
        assert!(!matches_server(&grant, "grafana"));
    }

    #[test]
    fn test_server_pattern_wildcard() {
        let grant = Grant {
            server: ServerPattern::Single("*".to_string()),
            access: AccessLevel::All,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_server(&grant, "github"));
        assert!(matches_server(&grant, "grafana"));
        assert!(matches_server(&grant, "sentry"));
    }

    #[test]
    fn test_server_pattern_multiple() {
        let grant = Grant {
            server: ServerPattern::Multiple(vec!["github".to_string(), "grafana".to_string()]),
            access: AccessLevel::All,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_server(&grant, "github"));
        assert!(matches_server(&grant, "grafana"));
        assert!(!matches_server(&grant, "sentry"));
    }

    #[test]
    fn test_tool_glob_in_grant() {
        let grant = Grant {
            server: ServerPattern::Single("*".to_string()),
            access: AccessLevel::All,
            tools: vec!["gh_pr*".to_string()],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_tool_grant(&grant, "gh_pr_create"));
        assert!(matches_tool_grant(&grant, "gh_pr"));
        assert!(!matches_tool_grant(&grant, "gh_issue"));
    }

    #[test]
    fn test_grant_no_tools_means_all() {
        let grant = Grant {
            server: ServerPattern::Single("*".to_string()),
            access: AccessLevel::All,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_tool_grant(&grant, "anything"));
        assert!(matches_tool_grant(&grant, "gh_pr"));
    }

    // -----------------------------------------------------------------------
    // Access expansion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_access_allows_read_tools() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "viewer".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Read,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["viewer".to_string()]);
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "query_prometheus",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_read_access_denies_write_tools() {
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "viewer".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Read,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["viewer".to_string()]);
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "update_dashboard",
            classification: Some(&write_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_read_access_denies_ambiguous_tools() {
        let amb_cls = make_classification(Kind::Ambiguous);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "viewer".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Read,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["viewer".to_string()]);
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "execute_sql",
            classification: Some(&amb_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_write_access_allows_write_tools() {
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Write,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_pr",
            classification: Some(&write_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_write_access_allows_ambiguous_nonstrict() {
        let amb_cls = make_classification(Kind::Ambiguous);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Write,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);
        let ctx = ToolContext {
            server_alias: "databricks",
            tool_name: "execute_sql",
            classification: Some(&amb_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_write_access_denies_ambiguous_strict() {
        let amb_cls = make_classification(Kind::Ambiguous);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: true,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Write,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);
        let ctx = ToolContext {
            server_alias: "databricks",
            tool_name: "execute_sql",
            classification: Some(&amb_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_write_access_denies_read_tools() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "writer".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::Write,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["writer".to_string()]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_status",
            classification: Some(&read_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_all_access_allows_everything_non_strict() {
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "admin".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::All,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("alice", vec!["admin".to_string()]);

        for kind in [Kind::Read, Kind::Write, Kind::Ambiguous] {
            let cls = make_classification(kind);
            let ctx = ToolContext {
                server_alias: "any",
                tool_name: "any_tool",
                classification: Some(&cls),
            };
            assert!(
                is_tool_allowed_rbac(&identity, &ctx, &acl).allowed,
                "access=* non-strict should allow Kind::{kind:?}"
            );
        }
    }

    #[test]
    fn test_all_access_blocks_ambiguous_in_strict_mode() {
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: true,
            roles: HashMap::from([(
                "admin".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::All,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("alice", vec!["admin".to_string()]);

        // Read and Write still allowed
        for kind in [Kind::Read, Kind::Write] {
            let cls = make_classification(kind);
            let ctx = ToolContext {
                server_alias: "any",
                tool_name: "any_tool",
                classification: Some(&cls),
            };
            assert!(
                is_tool_allowed_rbac(&identity, &ctx, &acl).allowed,
                "access=* strict should allow Kind::{kind:?}"
            );
        }

        // Ambiguous blocked in strict mode
        let cls = make_classification(Kind::Ambiguous);
        let ctx = ToolContext {
            server_alias: "any",
            tool_name: "any_tool",
            classification: Some(&cls),
        };
        assert!(
            !is_tool_allowed_rbac(&identity, &ctx, &acl).allowed,
            "access=* strict should block Kind::Ambiguous"
        );
    }

    // -----------------------------------------------------------------------
    // Union evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_roles_union() {
        let read_cls = make_classification(Kind::Read);
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([
                (
                    "reader".to_string(),
                    vec![Grant {
                        server: ServerPattern::Single("*".to_string()),
                        access: AccessLevel::Read,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    }],
                ),
                (
                    "writer".to_string(),
                    vec![Grant {
                        server: ServerPattern::Single("*".to_string()),
                        access: AccessLevel::Write,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    }],
                ),
            ]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["reader".to_string(), "writer".to_string()]);

        let ctx_read = ToolContext {
            server_alias: "github",
            tool_name: "list_repos",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx_read, &acl).allowed);

        let ctx_write = ToolContext {
            server_alias: "github",
            tool_name: "create_pr",
            classification: Some(&write_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx_write, &acl).allowed);
    }

    #[test]
    fn test_deny_overrides_allow() {
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::All,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::Write,
                        tools: vec!["gh_repo_delete".to_string()],
                        resources: vec![],
                        prompts: vec![],
                        deny: true,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);

        let ctx_pr = ToolContext {
            server_alias: "github",
            tool_name: "gh_pr",
            classification: Some(&write_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx_pr, &acl).allowed);

        let ctx_delete = ToolContext {
            server_alias: "github",
            tool_name: "gh_repo_delete",
            classification: Some(&write_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx_delete, &acl).allowed);
    }

    #[test]
    fn test_extra_grants_merge_with_roles() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "readonly".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("github".to_string()),
                    access: AccessLevel::Read,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::from([(
                "charlie".to_string(),
                SubjectConfig {
                    roles: vec!["readonly".to_string()],
                    extra: vec![Grant {
                        server: ServerPattern::Single("sentry".to_string()),
                        access: AccessLevel::Read,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    }],
                },
            )]),
        };
        let identity = AuthIdentity::new("charlie", vec![]);

        // Can read github via role
        let ctx_gh = ToolContext {
            server_alias: "github",
            tool_name: "list_repos",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx_gh, &acl).allowed);

        // Can read sentry via extra
        let ctx_sentry = ToolContext {
            server_alias: "sentry",
            tool_name: "search_issues",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx_sentry, &acl).allowed);

        // Cannot read grafana (no grant)
        let ctx_grafana = ToolContext {
            server_alias: "grafana",
            tool_name: "query_prometheus",
            classification: Some(&read_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx_grafana, &acl).allowed);
    }

    #[test]
    fn test_no_matching_grants_falls_to_default_allow() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Allow,
            strict_classification: false,
            roles: HashMap::new(),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("unknown", vec![]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "anything",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_no_matching_grants_falls_to_default_deny() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::new(),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("unknown", vec![]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "anything",
            classification: Some(&read_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_subject_inherits_roles_from_config() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "admin".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("*".to_string()),
                    access: AccessLevel::All,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::from([(
                "alice".to_string(),
                SubjectConfig {
                    roles: vec!["admin".to_string()],
                    extra: vec![],
                },
            )]),
        };
        // Token has NO roles, but subject config assigns "admin"
        let identity = AuthIdentity::new("alice", vec![]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "anything",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_deny_glob_blocks_entire_server() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "restricted".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Single("*".to_string()),
                        access: AccessLevel::Read,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("sentry".to_string()),
                        access: AccessLevel::All,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: true,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["restricted".to_string()]);

        // GitHub read works
        let ctx_gh = ToolContext {
            server_alias: "github",
            tool_name: "list_repos",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx_gh, &acl).allowed);

        // Sentry is fully blocked by deny
        let ctx_sentry = ToolContext {
            server_alias: "sentry",
            tool_name: "search_issues",
            classification: Some(&read_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx_sentry, &acl).allowed);
    }

    #[test]
    fn test_server_as_array_in_grant() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![Grant {
                    server: ServerPattern::Multiple(vec![
                        "github".to_string(),
                        "grafana".to_string(),
                    ]),
                    access: AccessLevel::Read,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);

        for server in ["github", "grafana"] {
            let ctx = ToolContext {
                server_alias: server,
                tool_name: "some_tool",
                classification: Some(&read_cls),
            };
            assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
        }

        let ctx_sentry = ToolContext {
            server_alias: "sentry",
            tool_name: "some_tool",
            classification: Some(&read_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx_sentry, &acl).allowed);
    }

    #[test]
    fn test_dev_role_read_write_scoped() {
        let read_cls = make_classification(Kind::Read);
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Multiple(vec![
                            "github".to_string(),
                            "grafana".to_string(),
                        ]),
                        access: AccessLevel::Read,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::Write,
                        tools: vec!["gh_pr".to_string(), "gh_issue".to_string()],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);

        // Can read grafana
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "query_prometheus",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);

        // Cannot write grafana
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "update_dashboard",
            classification: Some(&write_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);

        // Can write gh_pr on github
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_pr",
            classification: Some(&write_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);

        // Cannot write gh_repo on github (not in tools list)
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_repo",
            classification: Some(&write_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);

        // Can read gh_repo on github (read grant covers all tools)
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_repo",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    // -----------------------------------------------------------------------
    // PR review fixes: deny access scoping, schema detection, role validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_deny_read_does_not_block_write() {
        let read_cls = make_classification(Kind::Read);
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::All,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::Read,
                        tools: vec!["gh_secret_tool".to_string()],
                        resources: vec![],
                        prompts: vec![],
                        deny: true,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("alice", vec!["dev".to_string()]);

        // Read is denied by the deny grant
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_secret_tool",
            classification: Some(&read_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);

        // Write is NOT denied -- the deny grant only covers read
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_secret_tool",
            classification: Some(&write_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    #[test]
    fn test_deny_write_does_not_block_read() {
        let read_cls = make_classification(Kind::Read);
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Single("*".to_string()),
                        access: AccessLevel::All,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::Write,
                        tools: vec!["gh_repo_delete".to_string()],
                        resources: vec![],
                        prompts: vec![],
                        deny: true,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);

        // Write is denied
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_repo_delete",
            classification: Some(&write_cls),
        };
        assert!(!is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);

        // Read is NOT denied -- the deny grant only covers write
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_repo_delete",
            classification: Some(&read_cls),
        };
        assert!(is_tool_allowed_rbac(&identity, &ctx, &acl).allowed);
    }

    // -----------------------------------------------------------------------
    // Decision provenance tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_decision_legacy_first_rule_match() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        );
        let d = super::super::is_tool_allowed(&bob(), "sentry__search_issues", &acl, None);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, MatchedRule::Legacy(0));
    }

    #[test]
    fn test_decision_legacy_second_rule_match() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Allow,
            vec![
                AclRule {
                    subjects: vec!["alice".to_string()],
                    roles: vec![],
                    tools: vec!["*".to_string()],
                    policy: AclPolicy::Allow,
                },
                AclRule {
                    subjects: vec!["bob".to_string()],
                    roles: vec![],
                    tools: vec!["sentry__*".to_string()],
                    policy: AclPolicy::Deny,
                },
            ],
        );
        let d = super::super::is_tool_allowed(&bob(), "sentry__delete", &acl, None);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, MatchedRule::Legacy(1));
    }

    #[test]
    fn test_decision_legacy_default_fallback() {
        let acl = super::super::AclConfig::legacy(
            AclPolicy::Deny,
            vec![AclRule {
                subjects: vec!["alice".to_string()],
                roles: vec![],
                tools: vec!["*".to_string()],
                policy: AclPolicy::Allow,
            }],
        );
        let d = super::super::is_tool_allowed(&bob(), "anything", &acl, None);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, MatchedRule::LegacyDefault);
    }

    #[test]
    fn test_decision_rbac_role_grant_index() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::Write,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("grafana".to_string()),
                        access: AccessLevel::Read,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "query_prometheus",
            classification: Some(&read_cls),
        };
        let d = is_tool_allowed_rbac(&identity, &ctx, &acl);
        assert!(d.allowed);
        assert_eq!(
            d.matched_rule,
            MatchedRule::RoleGrant {
                role: "dev".to_string(),
                index: 1
            }
        );
    }

    #[test]
    fn test_decision_rbac_subject_extra() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "readonly".to_string(),
                vec![Grant {
                    server: ServerPattern::Single("github".to_string()),
                    access: AccessLevel::Read,
                    tools: vec![],
                    resources: vec![],
                    prompts: vec![],
                    deny: false,
                }],
            )]),
            subjects: HashMap::from([(
                "charlie".to_string(),
                SubjectConfig {
                    roles: vec!["readonly".to_string()],
                    extra: vec![Grant {
                        server: ServerPattern::Single("sentry".to_string()),
                        access: AccessLevel::Read,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    }],
                },
            )]),
        };
        let identity = AuthIdentity::new("charlie", vec![]);
        let ctx = ToolContext {
            server_alias: "sentry",
            tool_name: "search_issues",
            classification: Some(&read_cls),
        };
        let d = is_tool_allowed_rbac(&identity, &ctx, &acl);
        assert!(d.allowed);
        assert_eq!(
            d.matched_rule,
            MatchedRule::SubjectExtra {
                subject: "charlie".to_string(),
                index: 0
            }
        );
    }

    #[test]
    fn test_decision_rbac_deny_provenance() {
        let write_cls = make_classification(Kind::Write);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::from([(
                "dev".to_string(),
                vec![
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::All,
                        tools: vec![],
                        resources: vec![],
                        prompts: vec![],
                        deny: false,
                    },
                    Grant {
                        server: ServerPattern::Single("github".to_string()),
                        access: AccessLevel::Write,
                        tools: vec!["gh_repo_delete".to_string()],
                        resources: vec![],
                        prompts: vec![],
                        deny: true,
                    },
                ],
            )]),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec!["dev".to_string()]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "gh_repo_delete",
            classification: Some(&write_cls),
        };
        let d = is_tool_allowed_rbac(&identity, &ctx, &acl);
        assert!(!d.allowed);
        assert_eq!(
            d.matched_rule,
            MatchedRule::RoleGrant {
                role: "dev".to_string(),
                index: 1
            }
        );
    }

    #[test]
    fn test_decision_rbac_default() {
        let read_cls = make_classification(Kind::Read);
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Deny,
            strict_classification: false,
            roles: HashMap::new(),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("unknown", vec![]);
        let ctx = ToolContext {
            server_alias: "github",
            tool_name: "anything",
            classification: Some(&read_cls),
        };
        let d = is_tool_allowed_rbac(&identity, &ctx, &acl);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, MatchedRule::RbacDefault);
    }

    #[test]
    fn test_decision_classification_populated() {
        let cls = ToolClassification {
            kind: Kind::Read,
            confidence: 0.72,
            source: Source::Classifier,
            reasons: vec!["test".to_string()],
        };
        let acl = RoleBasedAclConfig {
            default: AclPolicy::Allow,
            strict_classification: false,
            roles: HashMap::new(),
            subjects: HashMap::new(),
        };
        let identity = AuthIdentity::new("bob", vec![]);
        let ctx = ToolContext {
            server_alias: "grafana",
            tool_name: "query_prometheus",
            classification: Some(&cls),
        };
        let d = is_tool_allowed_rbac(&identity, &ctx, &acl);
        assert!(d.allowed);
        assert_eq!(d.classification_kind, Some(Kind::Read));
        assert_eq!(d.classification_source, Some(Source::Classifier));
        assert!((d.classification_confidence.unwrap() - 0.72).abs() < f32::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Resource ACL tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_matches_resource_grant_empty_allows_all() {
        let grant = Grant {
            server: ServerPattern::Single("sentry".to_string()),
            access: AccessLevel::Read,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_resource_grant(&grant, "issue://123"));
        assert!(matches_resource_grant(&grant, "project://foo"));
    }

    #[test]
    fn test_matches_resource_grant_glob_restricts() {
        let grant = Grant {
            server: ServerPattern::Single("sentry".to_string()),
            access: AccessLevel::Read,
            tools: vec![],
            resources: vec!["issue://*".to_string()],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_resource_grant(&grant, "issue://123"));
        assert!(matches_resource_grant(&grant, "issue://abc"));
        assert!(!matches_resource_grant(&grant, "project://foo"));
    }

    #[test]
    fn test_matches_resource_grant_multiple_globs() {
        let grant = Grant {
            server: ServerPattern::Single("sentry".to_string()),
            access: AccessLevel::Read,
            tools: vec![],
            resources: vec!["issue://*".to_string(), "project://*".to_string()],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_resource_grant(&grant, "issue://123"));
        assert!(matches_resource_grant(&grant, "project://foo"));
        assert!(!matches_resource_grant(&grant, "user://bar"));
    }

    #[test]
    fn test_matches_prompt_grant_empty_allows_all() {
        let grant = Grant {
            server: ServerPattern::Single("ai".to_string()),
            access: AccessLevel::Read,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(matches_prompt_grant(&grant, "summarize"));
        assert!(matches_prompt_grant(&grant, "translate"));
    }

    #[test]
    fn test_matches_prompt_grant_glob_restricts() {
        let grant = Grant {
            server: ServerPattern::Single("ai".to_string()),
            access: AccessLevel::Read,
            tools: vec![],
            resources: vec![],
            prompts: vec!["summarize*".to_string()],
            deny: false,
        };
        assert!(matches_prompt_grant(&grant, "summarize"));
        assert!(matches_prompt_grant(&grant, "summarize_long"));
        assert!(!matches_prompt_grant(&grant, "translate"));
    }

    fn rbac_with_resource_grants() -> super::super::AclConfig {
        let json = serde_json::json!({
            "default": "deny",
            "roles": {
                "reader": [
                    {
                        "server": "sentry",
                        "access": "read",
                        "resources": ["issue://*"]
                    }
                ],
                "all_access": [
                    {
                        "server": "*",
                        "access": "*"
                    }
                ]
            },
            "subjects": {
                "bob": { "roles": ["reader"] },
                "alice": { "roles": ["all_access"] }
            }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn test_resource_allowed_rbac_matching_grant() {
        let acl = rbac_with_resource_grants();
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "issue://123",
        };
        let d = is_resource_allowed(&bob(), "sentry__issue://123", &acl, Some(&ctx), false);
        assert!(d.allowed);
    }

    #[test]
    fn test_resource_denied_rbac_non_matching_uri() {
        let acl = rbac_with_resource_grants();
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "project://foo",
        };
        let d = is_resource_allowed(&bob(), "sentry__project://foo", &acl, Some(&ctx), false);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, MatchedRule::RbacDefault);
    }

    #[test]
    fn test_resource_allowed_rbac_wildcard_server() {
        let acl = rbac_with_resource_grants();
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "project://foo",
        };
        let d = is_resource_allowed(&alice(), "sentry__project://foo", &acl, Some(&ctx), false);
        assert!(d.allowed);
    }

    #[test]
    fn test_resource_denied_rbac_unknown_subject() {
        let acl = rbac_with_resource_grants();
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "issue://123",
        };
        let unknown = AuthIdentity::new("charlie", vec![]);
        let d = is_resource_allowed(&unknown, "sentry__issue://123", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_resource_deny_grant_wins() {
        let json = serde_json::json!({
            "default": "allow",
            "roles": {
                "restricted": [
                    {
                        "server": "sentry",
                        "access": "read",
                        "resources": ["secret://*"],
                        "deny": true
                    },
                    {
                        "server": "sentry",
                        "access": "read"
                    }
                ]
            },
            "subjects": {
                "bob": { "roles": ["restricted"] }
            }
        });
        let acl: super::super::AclConfig = serde_json::from_value(json).unwrap();
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "secret://key",
        };
        let d = is_resource_allowed(&bob(), "sentry__secret://key", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_resource_legacy_deny_default() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Deny, vec![]);
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "issue://123",
        };
        let d = is_resource_allowed(&bob(), "sentry__issue://123", &acl, Some(&ctx), false);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, MatchedRule::LegacyDefault);
    }

    #[test]
    fn test_resource_legacy_allow_default() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Allow, vec![]);
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "issue://123",
        };
        let d = is_resource_allowed(&bob(), "sentry__issue://123", &acl, Some(&ctx), false);
        assert!(d.allowed);
    }

    #[test]
    fn test_resource_no_server_escalation() {
        let acl = rbac_with_resource_grants();
        // bob has reader on sentry, not on github
        let ctx = ResourceContext {
            server_alias: "github",
            resource_uri: "issue://123",
        };
        let d = is_resource_allowed(&bob(), "github__issue://123", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_resource_write_only_grant_denies_read() {
        let json = serde_json::json!({
            "default": "deny",
            "roles": {
                "writer": [
                    {
                        "server": "sentry",
                        "access": "write",
                        "resources": ["issue://*"]
                    }
                ]
            },
            "subjects": {
                "bob": { "roles": ["writer"] }
            }
        });
        let acl: super::super::AclConfig = serde_json::from_value(json).unwrap();
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "issue://123",
        };
        let d = is_resource_allowed(&bob(), "sentry__issue://123", &acl, Some(&ctx), false);
        // write-only grant should NOT cover read access for resources
        assert!(!d.allowed);
    }

    // -----------------------------------------------------------------------
    // Prompt ACL tests
    // -----------------------------------------------------------------------

    fn rbac_with_prompt_grants() -> super::super::AclConfig {
        let json = serde_json::json!({
            "default": "deny",
            "roles": {
                "prompter": [
                    {
                        "server": "ai",
                        "access": "read",
                        "prompts": ["summarize*"]
                    }
                ]
            },
            "subjects": {
                "bob": { "roles": ["prompter"] }
            }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn test_prompt_allowed_rbac_matching_grant() {
        let acl = rbac_with_prompt_grants();
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "summarize",
        };
        let d = is_prompt_allowed(&bob(), "ai__summarize", &acl, Some(&ctx), false);
        assert!(d.allowed);
    }

    #[test]
    fn test_prompt_allowed_rbac_glob_match() {
        let acl = rbac_with_prompt_grants();
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "summarize_long",
        };
        let d = is_prompt_allowed(&bob(), "ai__summarize_long", &acl, Some(&ctx), false);
        assert!(d.allowed);
    }

    #[test]
    fn test_prompt_denied_rbac_non_matching() {
        let acl = rbac_with_prompt_grants();
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "translate",
        };
        let d = is_prompt_allowed(&bob(), "ai__translate", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_prompt_denied_rbac_wrong_server() {
        let acl = rbac_with_prompt_grants();
        let ctx = PromptContext {
            server_alias: "other",
            prompt_name: "summarize",
        };
        let d = is_prompt_allowed(&bob(), "other__summarize", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_prompt_deny_grant_wins() {
        let json = serde_json::json!({
            "default": "allow",
            "roles": {
                "restricted": [
                    {
                        "server": "ai",
                        "access": "read",
                        "prompts": ["dangerous*"],
                        "deny": true
                    },
                    {
                        "server": "ai",
                        "access": "read"
                    }
                ]
            },
            "subjects": {
                "bob": { "roles": ["restricted"] }
            }
        });
        let acl: super::super::AclConfig = serde_json::from_value(json).unwrap();
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "dangerous_prompt",
        };
        let d = is_prompt_allowed(&bob(), "ai__dangerous_prompt", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_prompt_legacy_deny_default() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Deny, vec![]);
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "summarize",
        };
        let d = is_prompt_allowed(&bob(), "ai__summarize", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_prompt_legacy_allow_default() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Allow, vec![]);
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "summarize",
        };
        let d = is_prompt_allowed(&bob(), "ai__summarize", &acl, Some(&ctx), false);
        assert!(d.allowed);
    }

    #[test]
    fn test_prompt_no_server_escalation() {
        let acl = rbac_with_prompt_grants();
        let ctx = PromptContext {
            server_alias: "other",
            prompt_name: "summarize",
        };
        let d = is_prompt_allowed(&bob(), "other__summarize", &acl, Some(&ctx), false);
        assert!(!d.allowed);
    }

    #[test]
    fn test_grant_covers_read_access_levels() {
        let mut grant = Grant {
            server: ServerPattern::Single("x".to_string()),
            access: AccessLevel::Read,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            deny: false,
        };
        assert!(grant_covers_read(&grant));
        grant.access = AccessLevel::All;
        assert!(grant_covers_read(&grant));
        grant.access = AccessLevel::Write;
        assert!(!grant_covers_read(&grant));
    }

    // -----------------------------------------------------------------------
    // Legacy list vs read/get distinction
    // -----------------------------------------------------------------------

    #[test]
    fn test_resource_legacy_deny_default_allows_list() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Deny, vec![]);
        let ctx = ResourceContext {
            server_alias: "sentry",
            resource_uri: "issue://123",
        };
        // List is always allowed in legacy, even with default=deny
        let d = is_resource_allowed(&bob(), "sentry__issue://123", &acl, Some(&ctx), true);
        assert!(d.allowed);
    }

    #[test]
    fn test_prompt_legacy_deny_default_allows_list() {
        let acl = super::super::AclConfig::legacy(AclPolicy::Deny, vec![]);
        let ctx = PromptContext {
            server_alias: "ai",
            prompt_name: "summarize",
        };
        // List is always allowed in legacy, even with default=deny
        let d = is_prompt_allowed(&bob(), "ai__summarize", &acl, Some(&ctx), true);
        assert!(d.allowed);
    }
}
