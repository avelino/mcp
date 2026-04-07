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

/// Glob matching: supports `*` as wildcard for any characters.
/// Handles multiple wildcards (e.g., `*admin*`, `foo*bar*baz`).
fn glob_match(pattern: &str, value: &str) -> bool {
    let segments: Vec<&str> = pattern.split('*').collect();

    if segments.len() == 1 {
        return pattern == value;
    }

    let starts_with_star = pattern.starts_with('*');
    let ends_with_star = pattern.ends_with('*');

    let segments = segments.as_slice();

    if !starts_with_star {
        let first = segments[0];
        if !value.starts_with(first) {
            return false;
        }
        let rest = &value[first.len()..];
        return match_middle_and_end(&segments[1..], rest, ends_with_star);
    }

    if !ends_with_star {
        let last = segments[segments.len() - 1];
        if !value.ends_with(last) {
            return false;
        }
        let rest = &value[..value.len() - last.len()];
        return match_middle(&segments[..segments.len() - 1], rest);
    }

    match_middle(segments, value)
}

fn match_middle(segments: &[&str], mut value: &str) -> bool {
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        match value.find(seg) {
            Some(pos) => {
                if i == 0 {
                    value = &value[pos + seg.len()..];
                } else {
                    value = &value[pos + seg.len()..];
                }
            }
            None => return false,
        }
    }
    true
}

fn match_middle_and_end(segments: &[&str], mut value: &str, ends_with_star: bool) -> bool {
    if segments.is_empty() {
        return true;
    }

    let count = if ends_with_star {
        segments.len()
    } else {
        segments.len() - 1
    };

    for seg in &segments[..count] {
        if seg.is_empty() {
            continue;
        }
        match value.find(seg) {
            Some(pos) => {
                value = &value[pos + seg.len()..];
            }
            None => return false,
        }
    }

    if !ends_with_star {
        let last = segments[segments.len() - 1];
        if last.is_empty() {
            return true;
        }
        return value.ends_with(last);
    }

    true
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
    fn test_glob_both_wildcards() {
        assert!(glob_match("*admin*", "admin_tool"));
        assert!(glob_match("*admin*", "my_admin_cmd"));
        assert!(glob_match("*admin*", "admin"));
        assert!(glob_match("*admin*", "administrator"));
        assert!(!glob_match("*admin*", "adm"));
        assert!(!glob_match("*admin*", "dmin"));
    }

    #[test]
    fn test_glob_both_wildcards_with_literal() {
        assert!(glob_match("*_admin_*", "sentry_admin_search"));
        assert!(glob_match("*_admin_*", "x_admin_y"));
        assert!(!glob_match("*_admin_*", "admin_ping"));
        assert!(!glob_match("*_admin_*", "admin"));
        assert!(!glob_match("*_admin_*", "admin_"));
        assert!(!glob_match("*_admin_*", "_admin"));
    }

    #[test]
    fn test_glob_prefix_and_suffix_no_bookend() {
        assert!(glob_match("foo*bar", "foobar"));
        assert!(glob_match("foo*bar", "fooXYZbar"));
        assert!(!glob_match("foo*bar", "barfoo"));
        assert!(!glob_match("foo*bar", "foo"));
        assert!(!glob_match("foo*bar", "bar"));
    }

    #[test]
    fn test_glob_multiple_wildcards() {
        assert!(glob_match("a*b*c", "aXXXbYYYc"));
        assert!(glob_match("a*b*c", "abc"));
        assert!(!glob_match("a*b*c", "ac"));
        assert!(!glob_match("a*b*c", "abcX"));
        assert!(!glob_match("a*b*c", "Xabc"));
        assert!(glob_match(
            "sentry__*_admin__*",
            "sentry__team_admin__delete"
        ));
        assert!(!glob_match("sentry__*_admin__*", "sentry__admin__list"));
    }

    #[test]
    fn test_glob_empty_segments() {
        assert!(glob_match("**", "anything"));
        assert!(glob_match("**", ""));
    }

    #[test]
    fn test_glob_regression_existing() {
        assert!(glob_match("my_tool", "my_tool"));
        assert!(!glob_match("my_tool", "other_tool"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("sentry__*", "sentry__search_issues"));
        assert!(glob_match("sentry__*", "sentry__"));
        assert!(!glob_match("sentry__*", "slack__send"));
        assert!(glob_match("*_issues", "search_issues"));
        assert!(!glob_match("*_issues", "search_users"));
    }

    #[test]
    fn test_acl_with_contains_pattern() {
        let acl = AclConfig {
            default: AclPolicy::Allow,
            rules: vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["*admin*".to_string()],
                policy: AclPolicy::Deny,
            }],
        };

        assert!(!is_tool_allowed(&bob(), "admin_panel", &acl));
        assert!(!is_tool_allowed(&bob(), "user_admin_panel", &acl));
        assert!(is_tool_allowed(&bob(), "user_panel", &acl));
        assert!(is_tool_allowed(&alice(), "admin_panel", &acl));
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
