use serde::Deserialize;

use super::AuthIdentity;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AclPolicy {
    Allow,
    Deny,
}

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
pub struct AclConfig {
    #[serde(default = "default_policy")]
    pub default: AclPolicy,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

fn default_policy() -> AclPolicy {
    AclPolicy::Allow
}

/// Check if a tool is allowed for the given identity against ACL rules.
/// Rules are evaluated in order; first match wins.
pub fn is_tool_allowed(identity: &AuthIdentity, tool_name: &str, acl: &AclConfig) -> bool {
    for rule in &acl.rules {
        if !matches_identity(identity, rule) {
            continue;
        }
        if !matches_tool(tool_name, &rule.tools) {
            continue;
        }
        return rule.policy == AclPolicy::Allow;
    }
    acl.default == AclPolicy::Allow
}

fn matches_identity(identity: &AuthIdentity, rule: &AclRule) -> bool {
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

fn matches_tool(tool_name: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| glob_match(pattern, tool_name))
}

/// Simple glob matching: supports `*` as wildcard for any characters.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }

    pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> AuthIdentity {
        AuthIdentity::new("alice", vec!["admin".to_string()])
    }

    fn bob() -> AuthIdentity {
        AuthIdentity::new("bob", vec!["viewer".to_string()])
    }

    fn anon() -> AuthIdentity {
        AuthIdentity::anonymous()
    }

    #[test]
    fn test_default_allow_no_rules() {
        let acl = AclConfig {
            default: AclPolicy::Allow,
            rules: vec![],
        };
        assert!(is_tool_allowed(&alice(), "any_tool", &acl));
        assert!(is_tool_allowed(&anon(), "any_tool", &acl));
    }

    #[test]
    fn test_default_deny_no_rules() {
        let acl = AclConfig {
            default: AclPolicy::Deny,
            rules: vec![],
        };
        assert!(!is_tool_allowed(&alice(), "any_tool", &acl));
    }

    #[test]
    fn test_deny_specific_subject() {
        let acl = AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        };

        assert!(!is_tool_allowed(&bob(), "sentry__search_issues", &acl));
        assert!(is_tool_allowed(&bob(), "slack__send_message", &acl));
        assert!(is_tool_allowed(&alice(), "sentry__search_issues", &acl));
    }

    #[test]
    fn test_allow_specific_role() {
        let acl = AclConfig {
            default: AclPolicy::Deny,
            rules: vec![AclRule {
                subjects: vec![],
                roles: vec!["admin".to_string()],
                tools: vec!["*".to_string()],
                policy: AclPolicy::Allow,
            }],
        };

        assert!(is_tool_allowed(&alice(), "anything", &acl));
        assert!(!is_tool_allowed(&bob(), "anything", &acl));
    }

    #[test]
    fn test_first_match_wins() {
        let acl = AclConfig {
            default: AclPolicy::Allow,
            rules: vec![
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
        };

        // First rule matches — allow
        assert!(is_tool_allowed(&bob(), "sentry__search_issues", &acl));
        // Second rule matches — deny
        assert!(!is_tool_allowed(&bob(), "sentry__delete_project", &acl));
    }

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("my_tool", "my_tool"));
        assert!(!glob_match("my_tool", "other_tool"));
    }

    #[test]
    fn test_glob_wildcard_all() {
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn test_glob_prefix_wildcard() {
        assert!(glob_match("sentry__*", "sentry__search_issues"));
        assert!(glob_match("sentry__*", "sentry__"));
        assert!(!glob_match("sentry__*", "slack__send"));
    }

    #[test]
    fn test_glob_suffix_wildcard() {
        assert!(glob_match("*_issues", "search_issues"));
        assert!(!glob_match("*_issues", "search_users"));
    }

    #[test]
    fn test_wildcard_subject() {
        let acl = AclConfig {
            default: AclPolicy::Deny,
            rules: vec![AclRule {
                subjects: vec!["*".to_string()],
                roles: vec![],
                tools: vec!["health__*".to_string()],
                policy: AclPolicy::Allow,
            }],
        };

        assert!(is_tool_allowed(&alice(), "health__check", &acl));
        assert!(is_tool_allowed(&bob(), "health__check", &acl));
        assert!(is_tool_allowed(&anon(), "health__check", &acl));
        assert!(!is_tool_allowed(&alice(), "sentry__search", &acl));
    }

    #[test]
    fn test_combined_subject_and_role() {
        let acl = AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec!["admin".to_string()],
                tools: vec!["dangerous__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        };

        // bob doesn't have admin role -> rule doesn't match -> falls to default (allow)
        assert!(is_tool_allowed(&bob(), "dangerous__delete", &acl));

        // identity with both bob + admin
        let bob_admin = AuthIdentity::new("bob", vec!["admin".to_string()]);
        assert!(!is_tool_allowed(&bob_admin, "dangerous__delete", &acl));
    }

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
        let acl: AclConfig = serde_json::from_str(json).unwrap();
        assert_eq!(acl.default, AclPolicy::Deny);
        assert_eq!(acl.rules.len(), 2);
        assert_eq!(acl.rules[0].subjects, vec!["alice"]);
        assert!(acl.rules[0].roles.is_empty());
        assert_eq!(acl.rules[1].roles, vec!["viewer"]);
    }

    #[test]
    fn test_acl_default_deserialize() {
        let json = r#"{"rules": []}"#;
        let acl: AclConfig = serde_json::from_str(json).unwrap();
        assert_eq!(acl.default, AclPolicy::Allow);
    }
}
