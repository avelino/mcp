//! Tool read/write classifier.
//!
//! Pure function over `(tool name, description, input schema, annotations)`.
//! Produces a [`ToolClassification`] that downstream ACL enforcement will
//! consume. This module does no I/O — persistence lives in
//! [`crate::classifier_cache`] and the hot-path wiring in `serve.rs`.
//!
//! Decision order (first hit wins):
//! 1. Manual override in `servers.json` → `Source::Override`
//! 2. `readOnlyHint` / `destructiveHint` annotations → `Source::Annotation`
//! 3. Name-token + description-regex + inputSchema scoring → `Source::Classifier`
//! 4. Fallback `Ambiguous` (fail-safe; downstream treats as write)

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use crate::config::ToolOverrides;
use crate::protocol::Tool;
use crate::server_auth::glob_match;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Read,
    Write,
    Ambiguous,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Read => "read",
            Kind::Write => "write",
            Kind::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Override,
    Annotation,
    Classifier,
    Fallback,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Override => "override",
            Source::Annotation => "annotation",
            Source::Classifier => "classifier",
            Source::Fallback => "fallback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolClassification {
    pub kind: Kind,
    pub confidence: f32,
    pub source: Source,
    pub reasons: Vec<String>,
}

// --- Token dictionaries (from docs/acl-redesign-plan.md §2.3) ---

const READ_TOKENS: &[&str] = &[
    "get",
    "list",
    "search",
    "find",
    "query",
    "read",
    "fetch",
    "describe",
    "show",
    "view",
    "inspect",
    "analyze",
    "check",
    "status",
    "history",
    "logs",
    "events",
    "explain",
    "diff",
    "top",
    "snapshot",
    "dump",
    "export",
    "poll",
    "info",
    "stats",
    "count",
    "whoami",
    "version",
    "resolve",
    "backlinks",
];

const WRITE_TOKENS: &[&str] = &[
    "create", "update", "delete", "remove", "write", "set", "patch", "put", "post", "send",
    "apply", "execute", "run", "start", "stop", "cancel", "kill", "drop", "insert", "upsert",
    "modify", "edit", "rename", "move", "copy", "upload", "publish", "deploy", "rollout", "scale",
    "drain", "cordon", "taint", "exec", "attach", "click", "navigate", "type", "fill", "press",
    "drag", "reply", "react", "add",
];

// --- Description regex bundles ---

struct DescPattern {
    re: regex::Regex,
    weight: i32,
    label: &'static str,
}

static READ_STRONG: LazyLock<Vec<DescPattern>> = LazyLock::new(|| {
    [
        (r"(?i)read[\s\-]only", 4, "read-only"),
        (r"(?i)without modifying", 4, "without modifying"),
        (r"(?i)does not modify", 4, "does not modify"),
        (r"(?i)returns information", 3, "returns information"),
        (r"(?i)\bretrieves\b", 3, "retrieves"),
        (r"(?i)\bfetches\b", 3, "fetches"),
    ]
    .into_iter()
    .map(|(p, w, l)| DescPattern {
        re: regex::Regex::new(p).unwrap(),
        weight: w,
        label: l,
    })
    .collect()
});

static READ_WEAK: LazyLock<Vec<DescPattern>> = LazyLock::new(|| {
    [
        (r"(?i)\blists?\b", 1, "list"),
        (r"(?i)\bshows?\b", 1, "show"),
        (r"(?i)\bdescribes?\b", 1, "describe"),
        (r"(?i)\bsearch(es|ing|ed)?\b", 1, "search"),
        (r"(?i)\binspects?\b", 1, "inspect"),
        (r"(?i)\breturns?\b", 1, "returns"),
        (r"(?i)\bquer(y|ies)\b", 1, "query"),
    ]
    .into_iter()
    .map(|(p, w, l)| DescPattern {
        re: regex::Regex::new(p).unwrap(),
        weight: w,
        label: l,
    })
    .collect()
});

static WRITE_DESC: LazyLock<Vec<DescPattern>> = LazyLock::new(|| {
    [
        (r"(?i)\bcreates?\b", -3, "creates"),
        (r"(?i)\bupdates?\b", -3, "updates"),
        (r"(?i)\bdeletes?\b", -3, "deletes"),
        (r"(?i)\bmodif(y|ies)\b", -3, "modifies"),
        (r"(?i)\bwrites?\b", -3, "writes"),
        (r"(?i)\bsends?\b", -2, "sends"),
        (r"(?i)\bexecutes?\b", -3, "executes"),
        (r"(?i)\bapplies\b", -2, "applies"),
        (r"(?i)\bremoves?\b", -3, "removes"),
        (r"(?i)\bpublishes?\b", -2, "publishes"),
        (r"(?i)\bposts?\b", -2, "posts"),
        (r"(?i)\buploads?\b", -2, "uploads"),
    ]
    .into_iter()
    .map(|(p, w, l)| DescPattern {
        re: regex::Regex::new(p).unwrap(),
        weight: w,
        label: l,
    })
    .collect()
});

/// Split a tool name into lowercased tokens (handles `_`, `-`, camelCase).
pub(crate) fn tokenize(name: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    for ch in name.chars() {
        if ch == '_' || ch == '-' || ch == ' ' || ch == '.' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current).to_lowercase());
            }
        } else if ch.is_ascii_uppercase() && !current.is_empty() {
            tokens.push(std::mem::take(&mut current).to_lowercase());
            current.push(ch);
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current.to_lowercase());
    }
    tokens
}

/// Classify a single tool.
pub fn classify(tool: &Tool, overrides: Option<&ToolOverrides>) -> ToolClassification {
    // 1. Manual override — highest priority.
    if let Some(ov) = overrides {
        let read_hit = ov.read.iter().any(|p| glob_match(p, &tool.name));
        let write_hit = ov.write.iter().any(|p| glob_match(p, &tool.name));
        match (read_hit, write_hit) {
            (true, true) => {
                // Conflicting overrides at runtime: fail-safe to write.
                return ToolClassification {
                    kind: Kind::Write,
                    confidence: 1.0,
                    source: Source::Override,
                    reasons: vec![format!(
                        "conflicting override: '{}' matches both read and write → write (fail-safe)",
                        tool.name
                    )],
                };
            }
            (true, false) => {
                return ToolClassification {
                    kind: Kind::Read,
                    confidence: 1.0,
                    source: Source::Override,
                    reasons: vec![format!("override: '{}' → read", tool.name)],
                };
            }
            (false, true) => {
                return ToolClassification {
                    kind: Kind::Write,
                    confidence: 1.0,
                    source: Source::Override,
                    reasons: vec![format!("override: '{}' → write", tool.name)],
                };
            }
            (false, false) => {}
        }
    }

    // 2. Protocol annotations.
    if let Some(ann) = tool.annotations.as_ref() {
        if ann.read_only_hint == Some(true) {
            return ToolClassification {
                kind: Kind::Read,
                confidence: 0.95,
                source: Source::Annotation,
                reasons: vec!["annotation: readOnlyHint=true".to_string()],
            };
        }
        if ann.destructive_hint == Some(true) {
            return ToolClassification {
                kind: Kind::Write,
                confidence: 0.95,
                source: Source::Annotation,
                reasons: vec!["annotation: destructiveHint=true".to_string()],
            };
        }
    }

    // 3. Scoring classifier. Positive score → read, negative → write.
    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();

    // Name tokens
    for tok in tokenize(&tool.name) {
        if READ_TOKENS.contains(&tok.as_str()) {
            score += 1;
            reasons.push(format!("name token '{tok}' → read (+1)"));
        } else if WRITE_TOKENS.contains(&tok.as_str()) {
            score -= 2;
            reasons.push(format!("name token '{tok}' → write (-2)"));
        }
    }

    // Description patterns
    if let Some(desc) = tool.description.as_deref() {
        for p in READ_STRONG.iter() {
            if p.re.is_match(desc) {
                score += p.weight;
                reasons.push(format!("desc '{}' → read (+{})", p.label, p.weight));
            }
        }
        for p in READ_WEAK.iter() {
            if p.re.is_match(desc) {
                score += p.weight;
                reasons.push(format!("desc '{}' → read (+{})", p.label, p.weight));
            }
        }
        for p in WRITE_DESC.iter() {
            if p.re.is_match(desc) {
                score += p.weight;
                reasons.push(format!("desc '{}' → write ({})", p.label, p.weight));
            }
        }
    }

    // Input schema hints
    if let Some(schema) = tool.input_schema.as_ref() {
        if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
            let mut read_props = 0;
            let mut write_props = 0;
            for key in props.keys() {
                let k = key.to_lowercase();
                if matches!(
                    k.as_str(),
                    "limit" | "offset" | "page" | "cursor" | "filter" | "pattern"
                ) {
                    read_props += 1;
                } else if matches!(k.as_str(), "body" | "content" | "payload") {
                    write_props += 1;
                }
            }
            if read_props > 0 {
                score += read_props;
                reasons.push(format!(
                    "schema pagination/filter props → read (+{read_props})"
                ));
            }
            if write_props > 0 {
                score -= write_props;
                reasons.push(format!(
                    "schema body/content/payload → write (-{write_props})"
                ));
            }
        }
    }

    // Decision thresholds. Chosen empirically from the real MCP set in this
    // repo; tuning is a one-line change.
    let (kind, source, confidence) = if score >= 2 {
        let c = (score as f32 / 10.0).clamp(0.5, 1.0);
        (Kind::Read, Source::Classifier, c)
    } else if score <= -2 {
        let c = ((-score) as f32 / 10.0).clamp(0.5, 1.0);
        (Kind::Write, Source::Classifier, c)
    } else {
        reasons.push(format!(
            "score {score} in undecided band → ambiguous (fail-safe: treat as write)"
        ));
        (Kind::Ambiguous, Source::Fallback, 0.0)
    };

    ToolClassification {
        kind,
        confidence,
        source,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Tool, ToolAnnotations};
    use serde_json::json;

    fn tool(name: &str, desc: Option<&str>) -> Tool {
        Tool {
            name: name.to_string(),
            description: desc.map(String::from),
            input_schema: None,
            annotations: None,
        }
    }

    // --- Tokenizer ---

    #[test]
    fn tokenize_underscore() {
        assert_eq!(
            tokenize("execute_sql_read_only"),
            vec!["execute", "sql", "read", "only"]
        );
    }

    #[test]
    fn tokenize_camel_case() {
        assert_eq!(tokenize("getUserInfo"), vec!["get", "user", "info"]);
    }

    #[test]
    fn tokenize_mixed() {
        assert_eq!(
            tokenize("gh_pullRequest-list"),
            vec!["gh", "pull", "request", "list"]
        );
    }

    // --- Motivating case from the issue ---

    #[test]
    fn execute_sql_is_write() {
        let c = classify(
            &tool(
                "execute_sql",
                Some("Executes a SQL statement against the warehouse."),
            ),
            None,
        );
        assert_eq!(c.kind, Kind::Write, "reasons={:?}", c.reasons);
    }

    #[test]
    fn execute_sql_read_only_is_read() {
        let c = classify(
            &tool(
                "execute_sql_read_only",
                Some("Runs a read-only SQL query and returns the result set."),
            ),
            None,
        );
        assert_eq!(c.kind, Kind::Read, "reasons={:?}", c.reasons);
    }

    // --- Grafana read-heavy tools (real MCP set) ---

    #[test]
    fn grafana_get_list_query_find_search_are_read() {
        for name in &[
            "get_dashboard_by_uid",
            "list_datasources",
            "query_prometheus",
            "find_slow_requests",
            "search_dashboards",
            "get_alert_group",
            "list_loki_label_names",
        ] {
            let c = classify(&tool(name, Some("Retrieves data from Grafana.")), None);
            assert_eq!(c.kind, Kind::Read, "{name} should be read: {:?}", c.reasons);
        }
    }

    #[test]
    fn grafana_write_tools_are_write() {
        for name in &[
            "update_dashboard",
            "create_annotation",
            "create_incident",
            "delete_page",
        ] {
            let c = classify(&tool(name, Some("Updates or creates a resource.")), None);
            assert_eq!(
                c.kind,
                Kind::Write,
                "{name} should be write: {:?}",
                c.reasons
            );
        }
    }

    // --- Annotation source ---

    #[test]
    fn read_only_hint_wins_over_write_tokens() {
        let mut t = tool("send_message", Some("Sends a message."));
        t.annotations = Some(ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        });
        let c = classify(&t, None);
        assert_eq!(c.kind, Kind::Read);
        assert_eq!(c.source, Source::Annotation);
    }

    #[test]
    fn destructive_hint_wins_over_read_tokens() {
        let mut t = tool("get_thing", Some("Retrieves."));
        t.annotations = Some(ToolAnnotations {
            destructive_hint: Some(true),
            ..Default::default()
        });
        let c = classify(&t, None);
        assert_eq!(c.kind, Kind::Write);
        assert_eq!(c.source, Source::Annotation);
    }

    // --- Override source (from config) ---

    #[test]
    fn override_read_beats_classifier() {
        let ov = ToolOverrides {
            read: vec!["execute_sql".to_string()],
            write: vec![],
        };
        let c = classify(&tool("execute_sql", Some("Executes SQL.")), Some(&ov));
        assert_eq!(c.kind, Kind::Read);
        assert_eq!(c.source, Source::Override);
    }

    #[test]
    fn override_write_beats_classifier() {
        let ov = ToolOverrides {
            read: vec![],
            write: vec!["get_*".to_string()],
        };
        let c = classify(&tool("get_thing", Some("Reads.")), Some(&ov));
        assert_eq!(c.kind, Kind::Write);
        assert_eq!(c.source, Source::Override);
    }

    #[test]
    fn override_glob_matches() {
        let ov = ToolOverrides {
            read: vec!["list_*".to_string(), "get_*".to_string()],
            write: vec![],
        };
        let c = classify(&tool("list_repos", None), Some(&ov));
        assert_eq!(c.kind, Kind::Read);
    }

    #[test]
    fn conflicting_override_fails_safe_to_write() {
        // Cross-glob intersection: read pattern `get_*` and write pattern `*_thing`
        // both match `get_thing`. Runtime check must NOT trust it as Read.
        let ov = ToolOverrides {
            read: vec!["get_*".to_string()],
            write: vec!["*_thing".to_string()],
        };
        let c = classify(&tool("get_thing", None), Some(&ov));
        assert_eq!(c.kind, Kind::Write);
        assert_eq!(c.source, Source::Override);
    }

    // --- Ambiguous fallback ---

    #[test]
    fn unknown_tool_falls_to_ambiguous() {
        let c = classify(&tool("foo_bar", None), None);
        assert_eq!(c.kind, Kind::Ambiguous);
        assert_eq!(c.source, Source::Fallback);
    }

    #[test]
    fn tool_without_description_never_becomes_read_silently() {
        // Security: a bare tool with no signals must NOT be classified as read.
        let c = classify(&tool("do_thing", None), None);
        assert_ne!(c.kind, Kind::Read);
    }

    // --- InputSchema hints ---

    #[test]
    fn pagination_props_nudge_to_read() {
        let mut t = tool("query_things", Some("Runs a query."));
        t.input_schema = Some(json!({
            "type": "object",
            "properties": {
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
                "cursor": {"type": "string"},
                "filter": {"type": "string"}
            }
        }));
        let c = classify(&t, None);
        assert_eq!(c.kind, Kind::Read, "{:?}", c.reasons);
    }

    // --- Real MCP sample set (github, kubectl, sentry, slack, honeycomb, playwright) ---

    #[test]
    fn kubectl_writes() {
        for name in &[
            "kubectl_apply",
            "kubectl_delete",
            "kubectl_patch",
            "kubectl_scale",
            "kubectl_exec",
            "kubectl_drain",
            "kubectl_cordon",
        ] {
            let c = classify(&tool(name, Some("Modifies cluster state.")), None);
            assert_eq!(
                c.kind,
                Kind::Write,
                "{name} should be write: {:?}",
                c.reasons
            );
        }
    }

    #[test]
    fn kubectl_reads() {
        for name in &[
            "kubectl_get",
            "kubectl_describe",
            "kubectl_logs",
            "kubectl_top",
            "kubectl_events",
            "kubectl_explain",
            "kubectl_api_versions",
            "kubectl_version",
        ] {
            let c = classify(&tool(name, Some("Retrieves information.")), None);
            assert_eq!(c.kind, Kind::Read, "{name} should be read: {:?}", c.reasons);
        }
    }

    #[test]
    fn sentry_find_and_search_are_read() {
        for name in &[
            "find_organizations",
            "find_projects",
            "search_events",
            "search_issues",
            "search_docs",
            "get_issue_tag_values",
            "whoami",
        ] {
            let c = classify(&tool(name, Some("Searches Sentry.")), None);
            assert_eq!(c.kind, Kind::Read, "{name} should be read: {:?}", c.reasons);
        }
    }

    #[test]
    fn playwright_actions_are_write() {
        for name in &[
            "browser_click",
            "browser_navigate",
            "browser_type",
            "browser_press_key",
            "browser_drag",
            "browser_fill_form",
        ] {
            let c = classify(&tool(name, Some("Interacts with the page.")), None);
            assert_eq!(
                c.kind,
                Kind::Write,
                "{name} should be write: {:?}",
                c.reasons
            );
        }
    }

    #[test]
    fn playwright_snapshot_is_read() {
        let c = classify(
            &tool("browser_snapshot", Some("Returns a DOM snapshot.")),
            None,
        );
        assert_eq!(c.kind, Kind::Read);
    }

    #[test]
    fn slack_writes_vs_reads() {
        let w = classify(
            &tool("conversations_mark", Some("Marks a channel as read.")),
            None,
        );
        // "marks" isn't in our token list; "read" is — but "mark" on a channel
        // mutates state. This is a legitimate ambiguous case — document it.
        assert_ne!(w.kind, Kind::Read, "mark is ambiguous at best");

        let r = classify(&tool("channels_list", Some("Lists channels.")), None);
        assert_eq!(r.kind, Kind::Read);
    }
}
