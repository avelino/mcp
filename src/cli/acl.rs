use anyhow::{bail, Result};
use std::sync::Arc;

use crate::audit;
use crate::classifier;
use crate::classifier_cache;
use crate::client;
use crate::config;
use crate::output::OutputFormat;
use crate::server_auth;
use crate::server_auth::{AclConfig, Decision, ToolContext};

/// `mcp acl classify [--server <alias>] [--format table|json]`
///
/// Connects to each configured backend (or one named via --server), runs
/// `tools/list`, and classifies each tool via `classifier::classify`.
/// No HTTP listener, no ACL enforcement — this is the inspection path that
/// validates the classifier itself (issue #54).
pub async fn handle_acl_command(
    args: &[String],
    cfg: &config::Config,
    fmt: OutputFormat,
    audit: &Arc<audit::AuditLogger>,
) -> Result<()> {
    let sub = args.first().map(String::as_str).ok_or_else(|| {
        anyhow::anyhow!(
            "usage: mcp acl <classify|check> [flags]\n  mcp acl classify [--server <alias>]\n  mcp acl check --subject <name> --server <alias> --tool <name>|--resource <uri>|--prompt <name>"
        )
    })?;
    match sub {
        "classify" => {}
        "check" => return handle_acl_check(&args[1..], cfg, fmt, audit).await,
        _ => bail!("unknown acl subcommand: {sub} (available: classify, check)"),
    }

    // Parse flags
    let usage = "usage: mcp acl classify [--server <alias>] [--format table|json]";
    let mut server_filter: Option<String> = None;
    let mut format_override: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                let value = args
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| anyhow::anyhow!("{usage}"))?;
                server_filter = Some(value.clone());
                i += 2;
            }
            "--format" => {
                let value = args
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| anyhow::anyhow!("{usage}"))?;
                format_override = Some(value.clone());
                i += 2;
            }
            other => bail!("unknown flag: {other}"),
        }
    }
    let use_json = match format_override.as_deref() {
        Some("json") => true,
        Some("table") => false,
        Some(other) => bail!("unknown --format: {other} (expected 'table' or 'json')"),
        None => matches!(fmt, OutputFormat::Json),
    };

    // Pick servers to classify.
    let targets: Vec<(&String, &config::ServerConfig)> = match &server_filter {
        Some(name) => {
            let cfg_entry = cfg
                .servers
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("server \"{name}\" not found in config"))?;
            vec![(name, cfg_entry)]
        }
        None => cfg.servers.iter().collect(),
    };

    #[derive(serde::Serialize)]
    struct Row {
        server: String,
        tool: String,
        kind: &'static str,
        confidence: f32,
        source: &'static str,
        reasons: Vec<String>,
    }

    let mut rows: Vec<Row> = Vec::new();
    let mut cache = classifier_cache::ClassifierCache::load();

    for (name, server_config) in targets {
        if !use_json {
            eprintln!("[acl] listing tools from {name}...");
        }
        let client = match client::McpClient::connect(server_config).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[acl] {name}: failed to connect: {e:#}");
                continue;
            }
        };
        let tools = match client.list_tools().await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[acl] {name}: failed to list tools: {e:#}");
                let _ = client.shutdown().await;
                continue;
            }
        };
        let overrides = server_config.tool_acl();
        let has_overrides = overrides.is_some_and(|o| !o.read.is_empty() || !o.write.is_empty());
        for tool in &tools {
            let c = if has_overrides {
                classifier::classify(tool, overrides)
            } else {
                let key = classifier_cache::cache_key(
                    name,
                    &tool.name,
                    tool.description.as_deref(),
                    tool.annotations.as_ref(),
                );
                if let Some(cached) = cache.get(&key).cloned() {
                    cached
                } else {
                    let c = classifier::classify(tool, None);
                    cache.put(key, c.clone());
                    c
                }
            };
            rows.push(Row {
                server: name.clone(),
                tool: tool.name.clone(),
                kind: c.kind.as_str(),
                confidence: c.confidence,
                source: c.source.as_str(),
                reasons: c.reasons,
            });
        }
        let _ = client.shutdown().await;
    }

    cache.save();

    // Stable ordering.
    rows.sort_by(|a, b| a.server.cmp(&b.server).then(a.tool.cmp(&b.tool)));

    if use_json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    // Table output. Highlight Ambiguous with a `[!]` prefix for easy grep.
    println!(
        "{:<20} {:<40} {:<10} {:<6} {:<11} reasons",
        "SERVER", "TOOL", "KIND", "CONF", "SOURCE"
    );
    for r in &rows {
        let flag = if r.kind == "ambiguous" { "[!]" } else { "   " };
        let reasons = if r.reasons.is_empty() {
            String::new()
        } else {
            r.reasons.join("; ")
        };
        println!(
            "{flag} {server:<16} {tool:<40} {kind:<10} {conf:<6.2} {source:<11} {reasons}",
            server = r.server,
            tool = r.tool,
            kind = r.kind,
            conf = r.confidence,
            source = r.source,
        );
    }

    Ok(())
}

/// `mcp acl check --subject <name> --server <alias> --tool <name> [flags]`
///
/// Pure policy check: loads config, synthesizes an identity, and evaluates the
/// ACL without starting the proxy. Useful for validating rule changes before
/// rolling them out.
pub async fn handle_acl_check(
    args: &[String],
    cfg: &config::Config,
    fmt: OutputFormat,
    audit: &Arc<audit::AuditLogger>,
) -> Result<()> {
    let usage = "usage: mcp acl check --subject <name> --server <alias> --tool <name> \
                 [--access read|write] [--role <name>] [--all-tools] [--resource <uri>] \
                 [--prompt <name>] [--format json|table]";

    let mut subject: Option<String> = None;
    let mut server_alias: Option<String> = None;
    let mut tool_name: Option<String> = None;
    let mut resource_uri: Option<String> = None;
    let mut prompt_name: Option<String> = None;
    let mut access_override: Option<String> = None;
    let mut role_override: Option<String> = None;
    let mut all_tools = false;
    let mut format_override: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--subject" => {
                subject = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            "--server" => {
                server_alias = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            "--tool" => {
                tool_name = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            "--access" => {
                let val = args
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                    .clone();
                if val != "read" && val != "write" {
                    bail!("--access must be 'read' or 'write', got '{val}'");
                }
                access_override = Some(val);
                i += 2;
            }
            "--role" => {
                role_override = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            "--resource" => {
                resource_uri = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            "--prompt" => {
                prompt_name = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            "--all-tools" => {
                all_tools = true;
                i += 1;
            }
            "--format" => {
                format_override = Some(
                    args.get(i + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("{usage}"))?
                        .clone(),
                );
                i += 2;
            }
            other => bail!("unknown flag: {other}\n{usage}"),
        }
    }

    let use_json = match format_override.as_deref() {
        Some("json") => true,
        Some("table") => false,
        Some(other) => bail!("unknown --format: {other} (expected 'table' or 'json')"),
        None => matches!(fmt, OutputFormat::Json),
    };

    let server = server_alias.ok_or_else(|| anyhow::anyhow!("--server is required\n{usage}"))?;
    if subject.is_none() && role_override.is_none() {
        bail!("--subject or --role is required\n{usage}");
    }
    let target_count = [
        tool_name.is_some(),
        resource_uri.is_some(),
        prompt_name.is_some(),
        all_tools,
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    if target_count == 0 {
        bail!("one of --tool, --resource, --prompt, or --all-tools is required\n{usage}");
    }
    if target_count > 1 {
        bail!("--tool, --resource, --prompt, and --all-tools are mutually exclusive\n{usage}");
    }

    // Verify server exists in config.
    if !cfg.servers.contains_key(&server) {
        bail!("server \"{server}\" not found in config");
    }

    let acl_config = &cfg.server_auth.acl;

    // Synthesize identity.
    let identity = match (&subject, &role_override) {
        (Some(subj), Some(role)) => {
            // Subject with a specific role override
            server_auth::AuthIdentity::new(subj.clone(), vec![role.clone()])
        }
        (Some(subj), None) => {
            // Look up roles from subjects map in ACL config
            let roles = match acl_config {
                Some(AclConfig::RoleBased(rbac)) => rbac
                    .subjects
                    .get(subj.as_str())
                    .map(|sc| sc.roles.clone())
                    .unwrap_or_default(),
                _ => vec![],
            };
            server_auth::AuthIdentity::new(subj.clone(), roles)
        }
        (None, Some(role)) => {
            // Hypothetical role check
            server_auth::AuthIdentity::new("__check__", vec![role.clone()])
        }
        (None, None) => unreachable!(), // validated above
    };

    // Build the classification for tool(s).
    #[derive(serde::Serialize)]
    struct CheckResult {
        tool: String,
        decision: &'static str,
        matched_rule: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        access_evaluated: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        classification_kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        classification_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        classification_confidence: Option<f32>,
    }

    fn decision_to_result(tool_name: &str, d: &Decision) -> CheckResult {
        CheckResult {
            tool: tool_name.to_string(),
            decision: if d.allowed { "ALLOW" } else { "DENY" },
            matched_rule: d.matched_rule.to_string(),
            access_evaluated: d.access_evaluated.as_ref().map(|a| a.as_str().to_string()),
            classification_kind: d.classification_kind.map(|k| k.as_str().to_string()),
            classification_source: d.classification_source.map(|s| s.as_str().to_string()),
            classification_confidence: d.classification_confidence,
        }
    }

    let mut results: Vec<CheckResult> = Vec::new();

    if all_tools {
        // Connect to backend, list tools, classify, and check each.
        let server_config = &cfg.servers[&server];
        if !use_json {
            eprintln!("[acl] listing tools from {server}...");
        }
        let mcp_client = client::McpClient::connect(server_config).await?;
        let tools = mcp_client.list_tools().await?;
        let overrides = server_config.tool_acl();
        let mut cache = classifier_cache::ClassifierCache::load();

        let has_overrides = overrides.is_some_and(|o| !o.read.is_empty() || !o.write.is_empty());

        for tool in &tools {
            let cls = if has_overrides {
                classifier::classify(tool, overrides)
            } else {
                let key = classifier_cache::cache_key(
                    &server,
                    &tool.name,
                    tool.description.as_deref(),
                    tool.annotations.as_ref(),
                );
                if let Some(cached) = cache.get(&key).cloned() {
                    cached
                } else {
                    let c = classifier::classify(tool, None);
                    cache.put(key, c.clone());
                    c
                }
            };

            // Legacy ACL matches namespaced tools (e.g. "sentry__search_issues"),
            // while RBAC matches un-namespaced tool names. Pass the namespaced
            // form to is_tool_allowed (legacy rules match on it; RBAC ToolContext
            // uses the original tool_name field for grant matching).
            let namespaced = format!("{server}__{}", tool.name);
            let ctx = ToolContext {
                server_alias: &server,
                tool_name: &tool.name,
                classification: Some(&cls),
            };
            let d = server_auth::is_tool_allowed(&identity, &namespaced, acl_config, Some(&ctx));
            results.push(decision_to_result(&tool.name, &d));
        }
        cache.save();
        let _ = mcp_client.shutdown().await;
    } else {
        // Single tool check.
        let tool = tool_name.unwrap();
        let cls = match access_override.as_deref() {
            Some("read") => Some(classifier::ToolClassification {
                kind: classifier::Kind::Read,
                confidence: 1.0,
                source: classifier::Source::Override,
                reasons: vec!["--access flag".to_string()],
            }),
            Some("write") => Some(classifier::ToolClassification {
                kind: classifier::Kind::Write,
                confidence: 1.0,
                source: classifier::Source::Override,
                reasons: vec!["--access flag".to_string()],
            }),
            _ => {
                // No --access given: connect to backend and classify the tool
                // so grants with access=read/write can match correctly.
                let server_config = &cfg.servers[&server];
                if !use_json {
                    eprintln!("[acl] connecting to {server} to classify {tool}...");
                }
                match client::McpClient::connect(server_config).await {
                    Ok(mcp_client) => {
                        let tools = mcp_client.list_tools().await.unwrap_or_default();
                        let _ = mcp_client.shutdown().await;
                        tools
                            .iter()
                            .find(|t| t.name == tool)
                            .map(|t| classifier::classify(t, server_config.tool_acl()))
                    }
                    Err(e) => {
                        if !use_json {
                            eprintln!("[acl] warning: could not connect to classify tool: {e:#}");
                        }
                        None
                    }
                }
            }
        };
        let namespaced = format!("{server}__{tool}");
        let ctx = ToolContext {
            server_alias: &server,
            tool_name: &tool,
            classification: cls.as_ref(),
        };

        let d = server_auth::is_tool_allowed(&identity, &namespaced, acl_config, Some(&ctx));
        results.push(decision_to_result(&tool, &d));
    }

    if let Some(ref uri) = resource_uri {
        let namespaced = format!("{server}__{uri}");
        let ctx = server_auth::ResourceContext {
            server_alias: &server,
            resource_uri: uri,
        };
        let d =
            server_auth::is_resource_allowed(&identity, &namespaced, acl_config, Some(&ctx), false);
        results.push(decision_to_result(uri, &d));
    }

    if let Some(ref name) = prompt_name {
        let namespaced = format!("{server}__{name}");
        let ctx = server_auth::PromptContext {
            server_alias: &server,
            prompt_name: name,
        };
        let d =
            server_auth::is_prompt_allowed(&identity, &namespaced, acl_config, Some(&ctx), false);
        results.push(decision_to_result(name, &d));
    }

    // Sort results for stable output.
    results.sort_by(|a, b| a.tool.cmp(&b.tool));

    if use_json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        if all_tools {
            println!(
                "{:<40} {:<6} {:<25} {:<6} {:<10} {:<11} CONF",
                "TOOL", "DECISION", "RULE", "ACCESS", "KIND", "SOURCE"
            );
        }
        for r in &results {
            let access = r.access_evaluated.as_deref().unwrap_or("-");
            let kind = r.classification_kind.as_deref().unwrap_or("-");
            let source = r.classification_source.as_deref().unwrap_or("-");
            let conf = r
                .classification_confidence
                .map(|c| format!("{c:.2}"))
                .unwrap_or_else(|| "-".to_string());

            if all_tools {
                println!(
                    "{:<40} {:<6} {:<25} {:<6} {:<10} {:<11} {}",
                    r.tool, r.decision, r.matched_rule, access, kind, source, conf
                );
            } else {
                println!(
                    "{:<6} via {}  access={}  classification={}:{} (confidence {})",
                    r.decision, r.matched_rule, access, source, kind, conf
                );
            }
        }
    }

    // Log the check to audit.
    let identity_str = subject
        .as_deref()
        .or(role_override.as_deref())
        .unwrap_or("unknown");
    for r in &results {
        audit.log(audit::AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "acl/check".to_string(),
            tool_name: Some(r.tool.clone()),
            server_name: Some(server.clone()),
            identity: identity_str.to_string(),
            duration_ms: 0,
            success: true,
            error_message: None,
            arguments: None,
            acl_decision: Some(r.decision.to_lowercase()),
            acl_matched_rule: Some(r.matched_rule.clone()),
            acl_access_kind: r.access_evaluated.clone(),
            classification_kind: r.classification_kind.clone(),
            classification_source: r.classification_source.clone(),
            classification_confidence: r.classification_confidence,
        });
    }

    // Exit code: for single tool, 1 = deny.
    if !all_tools && results.first().is_some_and(|r| r.decision == "DENY") {
        std::process::exit(1);
    }

    Ok(())
}
