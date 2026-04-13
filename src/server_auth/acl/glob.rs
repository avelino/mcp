/// Glob matching: supports `*` as wildcard for any characters.
/// Handles multiple wildcards (e.g., `*admin*`, `foo*bar*baz`).
pub(crate) fn glob_match(pattern: &str, value: &str) -> bool {
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
    for seg in segments.iter() {
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
}
