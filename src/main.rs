mod audit;
mod auth;
mod cache;
mod classifier;
mod classifier_cache;
mod cli_discovery;
mod client;
mod config;
mod db;
mod manager;
mod output;
mod protocol;
mod registry;
mod serve;
mod server_auth;
mod spinner;
mod transport;

use anyhow::{bail, Result};
use output::OutputFormat;
use std::io::{IsTerminal, Read};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!("mcp — CLI that turns MCP servers into terminal commands");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  mcp --list                          List configured servers");
    eprintln!("  mcp <server> --list                 List tools from a server");
    eprintln!("  mcp <server> --info                 List tools with input schemas");
    eprintln!("  mcp <server> --health               Check if server is reachable");
    eprintln!("  mcp <server> <tool> [json]          Call a tool");
    eprintln!("  mcp search <query>                  Search MCP registry");
    eprintln!("  mcp add <name>                      Add server from registry");
    eprintln!("  mcp add --url <url> <name>          Add HTTP server manually");
    eprintln!("  mcp remove <name>                   Remove server from config");
    eprintln!("  mcp update <name>                   Refresh server config from registry");
    eprintln!("  mcp serve                           Start proxy server (stdio)");
    eprintln!("  mcp serve --http [addr]             Start proxy server over HTTP");
    eprintln!("  mcp logs                            Show recent audit log entries");
    eprintln!("  mcp logs --limit N                  Show last N entries (default: 50)");
    eprintln!("  mcp logs --server <name>            Filter by backend server");
    eprintln!("  mcp logs --tool <prefix>            Filter by tool name prefix");
    eprintln!("  mcp logs --errors                   Show only failures");
    eprintln!("  mcp logs --since <duration>         Filter by time (5m, 1h, 24h, 7d)");
    eprintln!("  mcp logs -f                         Follow mode (streams new entries live)");
    eprintln!("  mcp acl classify                    Classify tools as read/write");
    eprintln!("  mcp acl classify --server <alias>   Classify tools for one backend");
    eprintln!("  mcp acl classify --format json      Emit classification as JSON");
    eprintln!("  mcp acl check --subject <name> --server <alias> --tool <name>");
    eprintln!("                                      Check ACL decision for a tool request");
    eprintln!("  mcp acl check --subject <name> --server <alias> --resource <uri>");
    eprintln!("                                      Check ACL decision for a resource");
    eprintln!("  mcp acl check --subject <name> --server <alias> --prompt <name>");
    eprintln!("                                      Check ACL decision for a prompt");
    eprintln!("  mcp acl check --role <name> --server <alias> --all-tools");
    eprintln!("                                      Check all tools for a role");
    eprintln!("  mcp healthcheck [url]               HTTP health probe (for containers)");
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  --json                              Force JSON output");
    eprintln!("  --insecure                          Allow HTTP on non-loopback interfaces");
    eprintln!();
    eprintln!("Output defaults to human-readable tables when run interactively.");
    eprintln!("Piped output defaults to JSON for scripting.");
}

async fn run() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    let json_flag = raw_args.iter().any(|a| a == "--json");
    let args: Vec<String> = raw_args.into_iter().filter(|a| a != "--json").collect();
    let fmt = OutputFormat::detect(json_flag);

    let cfg = config::load_config()?;
    let conflicts = config::validate_server_names(&cfg);
    for name in &conflicts {
        eprintln!("warning: server \"{name}\" conflicts with a reserved command name");
        eprintln!(
            "  → rename it in {} to avoid unexpected behavior",
            cfg.path.display()
        );
    }

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(());
    }

    // Built-in HTTP health probe for container health checks (scratch/distroless
    // images have no curl/wget). Exits 0 if the endpoint returns 2xx, 1 otherwise.
    if args[0] == "healthcheck" {
        let url = args
            .get(1)
            .map(|s| s.as_str())
            .unwrap_or("http://localhost:8080/health");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        let resp = client.get(url).send().await;
        match resp {
            Ok(r) if r.status().is_success() => {
                std::process::exit(0);
            }
            Ok(r) => {
                eprintln!("healthcheck failed: HTTP {}", r.status());
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("healthcheck failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // `serve` manages its own db pool — handle it before creating the shared one.
    if args[0] == "serve" {
        let rest = &args[1..];
        let insecure = rest.iter().any(|a| a == "--insecure");
        let http_addr = if let Some(pos) = rest.iter().position(|a| a == "--http") {
            let addr = rest
                .get(pos + 1)
                .filter(|a| !a.starts_with("--"))
                .map(|a| a.as_str())
                .unwrap_or("127.0.0.1:8080");
            Some(addr.to_string())
        } else {
            None
        };
        return serve::run(cfg, http_addr.as_deref(), insecure).await;
    }

    // Shared database pool for audit logging and tool cache
    let db_pool = db::create_pool(&cfg.audit).unwrap_or_else(|e| {
        eprintln!("warning: failed to create db pool: {e:#}");
        Arc::new(db::DbPool::disabled())
    });

    // Audit logger shared across all commands
    let audit = Arc::new(
        audit::AuditLogger::open(&cfg.audit, db_pool.clone())
            .unwrap_or(audit::AuditLogger::Disabled),
    );

    if args[0] == "--list" {
        let start = std::time::Instant::now();
        let result = output::print_servers(&cfg.servers, fmt);
        audit.log(audit::AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "servers/list".to_string(),
            tool_name: None,
            server_name: None,
            identity: "local".to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
            success: result.is_ok(),
            error_message: result.as_ref().err().map(|e| format!("{e:#}")),
            arguments: None,
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        });
        return result;
    }

    let first = &args[0];

    match first.as_str() {
        "search" => {
            if args.len() < 2 {
                bail!("usage: mcp search <query>");
            }
            let query = args[1..].join(" ");
            let start = std::time::Instant::now();
            let sp = spinner::Spinner::start("searching registry...");
            let result = registry::search_servers(&query).await;
            sp.stop();

            let (success, error_message) = match &result {
                Ok(_) => (true, None),
                Err(e) => (false, Some(format!("{e:#}"))),
            };

            audit.log(audit::AuditEntry {
                timestamp: chrono::Local::now().to_rfc3339(),
                source: "cli".to_string(),
                method: "registry/search".to_string(),
                tool_name: None,
                server_name: None,
                identity: "local".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
                success,
                error_message,
                arguments: Some(serde_json::json!({"query": query})),
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });

            output::print_search_results(&result?, fmt)?;
            return Ok(());
        }
        "add" => {
            return handle_add(&args[1..], &audit).await;
        }
        "remove" => {
            if args.len() < 2 {
                bail!("usage: mcp remove <name>");
            }
            let start = std::time::Instant::now();
            let result = manager::remove_server(&args[1]);

            audit.log(audit::AuditEntry {
                timestamp: chrono::Local::now().to_rfc3339(),
                source: "cli".to_string(),
                method: "config/remove".to_string(),
                tool_name: None,
                server_name: Some(args[1].clone()),
                identity: "local".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
                success: result.is_ok(),
                error_message: result.as_ref().err().map(|e| format!("{e:#}")),
                arguments: None,
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });

            return result;
        }
        "update" => {
            if args.len() < 2 {
                bail!("usage: mcp update <name>");
            }
            let start = std::time::Instant::now();
            let result = manager::update_from_registry(&args[1]).await;

            audit.log(audit::AuditEntry {
                timestamp: chrono::Local::now().to_rfc3339(),
                source: "cli".to_string(),
                method: "config/update".to_string(),
                tool_name: None,
                server_name: Some(args[1].clone()),
                identity: "local".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
                success: result.is_ok(),
                error_message: result.as_ref().err().map(|e| format!("{e:#}")),
                arguments: None,
                acl_decision: None,
                acl_matched_rule: None,
                acl_access_kind: None,
                classification_kind: None,
                classification_source: None,
                classification_confidence: None,
            });

            return result;
        }
        "logs" => {
            return handle_logs_command(&args[1..], &cfg, fmt, db_pool.clone()).await;
        }
        "acl" => {
            return handle_acl_command(&args[1..], &cfg, fmt, &audit).await;
        }
        _ => {}
    }

    handle_server_command(&args, &cfg, fmt, &audit).await
}

async fn handle_logs_command(
    args: &[String],
    cfg: &config::Config,
    fmt: OutputFormat,
    pool: Arc<db::DbPool>,
) -> Result<()> {
    let filter = audit::parse_filter_args(args)?;

    if filter.follow {
        return handle_logs_follow(cfg, fmt, &filter, pool).await;
    }

    let audit_logger = audit::AuditLogger::open(&cfg.audit, pool)?;
    let entries = audit_logger.query_filtered(&filter)?;

    if entries.is_empty() {
        eprintln!("No audit log entries found.");
        return Ok(());
    }

    output::print_audit_logs(&entries, fmt)
}

async fn handle_logs_follow(
    cfg: &config::Config,
    fmt: OutputFormat,
    filter: &audit::AuditFilter,
    pool: Arc<db::DbPool>,
) -> Result<()> {
    let audit_logger = audit::AuditLogger::open(&cfg.audit, pool)?;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    eprintln!("[logs] following audit log (ctrl+c to stop)...");

    // Seed with current entries so we only show new ones
    let existing = audit_logger.query_recent(100)?;
    for entry in &existing {
        seen.insert(format!(
            "{}:{}:{}",
            entry.timestamp, entry.method, entry.identity
        ));
    }

    loop {
        let entries = audit_logger.query_recent(100)?;
        for entry in &entries {
            let key = format!("{}:{}:{}", entry.timestamp, entry.method, entry.identity);
            if seen.insert(key) && filter.matches(entry) {
                output::print_audit_log_entry(entry, fmt)?;
            }
        }
        // Cap memory: keep only recent keys since query_recent returns at most 100
        if seen.len() > 500 {
            seen.clear();
            for entry in &entries {
                seen.insert(format!(
                    "{}:{}:{}",
                    entry.timestamp, entry.method, entry.identity
                ));
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// `mcp acl classify [--server <alias>] [--format table|json]`
///
/// Connects to each configured backend (or one named via --server), runs
/// `tools/list`, and classifies each tool via `classifier::classify`.
/// No HTTP listener, no ACL enforcement — this is the inspection path that
/// validates the classifier itself (issue #54).
async fn handle_acl_command(
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
async fn handle_acl_check(
    args: &[String],
    cfg: &config::Config,
    fmt: OutputFormat,
    audit: &Arc<audit::AuditLogger>,
) -> Result<()> {
    use server_auth::{AclConfig, Decision, ToolContext};

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
        let d = server_auth::is_resource_allowed(&identity, &namespaced, acl_config, Some(&ctx));
        results.push(decision_to_result(uri, &d));
    }

    if let Some(ref name) = prompt_name {
        let namespaced = format!("{server}__{name}");
        let ctx = server_auth::PromptContext {
            server_alias: &server,
            prompt_name: name,
        };
        let d = server_auth::is_prompt_allowed(&identity, &namespaced, acl_config, Some(&ctx));
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

async fn handle_server_command(
    args: &[String],
    cfg: &config::Config,
    fmt: OutputFormat,
    audit: &Arc<audit::AuditLogger>,
) -> Result<()> {
    let server_name = &args[0];
    let server_config = cfg
        .servers
        .get(server_name)
        .ok_or_else(|| anyhow::anyhow!("server \"{server_name}\" not found in config"))?;

    let sp = spinner::Spinner::start(&format!("connecting to {server_name}..."));
    let client = client::McpClient::connect(server_config).await?;
    sp.stop();

    if args.len() == 1 || (args.len() >= 2 && args[1] == "--list") {
        let start = std::time::Instant::now();
        let sp = spinner::Spinner::start("listing tools...");
        let result = client.list_tools().await;
        sp.stop();

        let (tools, success, error_message) = match &result {
            Ok(tools) => (Some(tools.clone()), true, None),
            Err(e) => (None, false, Some(format!("{e:#}"))),
        };

        audit.log(audit::AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "tools/list".to_string(),
            tool_name: None,
            server_name: Some(server_name.clone()),
            identity: "local".to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
            success,
            error_message,
            arguments: None,
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        });

        if let Some(tools) = tools {
            output::print_tools(&tools, fmt)?;
        } else {
            result?;
        }
        client.shutdown().await?;
        return Ok(());
    }

    if args.len() >= 2 && args[1] == "--health" {
        let start = std::time::Instant::now();

        audit.log(audit::AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "health".to_string(),
            tool_name: None,
            server_name: Some(server_name.clone()),
            identity: "local".to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
            success: true,
            error_message: None,
            arguments: None,
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        });

        client.shutdown().await?;

        match fmt {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::json!({"server": server_name, "status": "ok"})
                );
            }
            OutputFormat::Text => {
                println!("{server_name}: ok");
            }
        }
        return Ok(());
    }

    if args.len() >= 2 && args[1] == "--info" {
        let start = std::time::Instant::now();
        let sp = spinner::Spinner::start("listing tools...");
        let result = client.list_tools().await;
        sp.stop();

        let (tools, success, error_message) = match &result {
            Ok(tools) => (Some(tools.clone()), true, None),
            Err(e) => (None, false, Some(format!("{e:#}"))),
        };

        audit.log(audit::AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "tools/info".to_string(),
            tool_name: None,
            server_name: Some(server_name.clone()),
            identity: "local".to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
            success,
            error_message,
            arguments: None,
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        });

        if let Some(tools) = tools {
            output::print_tools_info(&tools, fmt)?;
        } else {
            result?;
        }
        client.shutdown().await?;
        return Ok(());
    }

    let tool_name = &args[1];
    let json_args = if args.len() >= 3 {
        serde_json::from_str(&args[2])?
    } else {
        read_stdin_or_empty()?
    };

    let start = std::time::Instant::now();
    let sp = spinner::Spinner::start(&format!("calling {tool_name}..."));
    let result = client.call_tool(tool_name, json_args.clone()).await;
    sp.stop();

    let (call_result, success, error_message) = match &result {
        Ok(r) => {
            let is_err = r.is_error.unwrap_or(false);
            let err_msg = if is_err {
                r.content.first().and_then(|c| c.text.clone())
            } else {
                None
            };
            (Some(r.clone()), !is_err, err_msg)
        }
        Err(e) => (None, false, Some(format!("{e:#}"))),
    };

    let log_arguments = if cfg.audit.log_arguments {
        Some(json_args)
    } else {
        None
    };

    audit.log(audit::AuditEntry {
        timestamp: chrono::Local::now().to_rfc3339(),
        source: "cli".to_string(),
        method: "tools/call".to_string(),
        tool_name: Some(tool_name.clone()),
        server_name: Some(server_name.clone()),
        identity: "local".to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
        success,
        error_message,
        arguments: log_arguments,
        acl_decision: None,
        acl_matched_rule: None,
        acl_access_kind: None,
        classification_kind: None,
        classification_source: None,
        classification_confidence: None,
    });

    if let Some(r) = call_result {
        output::print_tool_result(&r, fmt)?;
    } else {
        result?;
    }
    client.shutdown().await?;

    Ok(())
}

async fn handle_add(args: &[String], audit: &Arc<audit::AuditLogger>) -> Result<()> {
    if args.is_empty() {
        bail!("usage: mcp add <name> or mcp add --url <url> <name>");
    }

    let start = std::time::Instant::now();

    if args[0] == "--url" {
        if args.len() < 3 {
            bail!("usage: mcp add --url <url> <name>");
        }
        let url = &args[1];
        let name = &args[2];
        let result = manager::add_http(name, url);

        audit.log(audit::AuditEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            source: "cli".to_string(),
            method: "config/add".to_string(),
            tool_name: None,
            server_name: Some(name.to_string()),
            identity: "local".to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
            success: result.is_ok(),
            error_message: result.as_ref().err().map(|e| format!("{e:#}")),
            arguments: Some(serde_json::json!({"url": url})),
            acl_decision: None,
            acl_matched_rule: None,
            acl_access_kind: None,
            classification_kind: None,
            classification_source: None,
            classification_confidence: None,
        });

        return result;
    }

    let name = &args[0];
    let result = manager::add_from_registry(name).await;

    audit.log(audit::AuditEntry {
        timestamp: chrono::Local::now().to_rfc3339(),
        source: "cli".to_string(),
        method: "config/add".to_string(),
        tool_name: None,
        server_name: Some(name.to_string()),
        identity: "local".to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
        success: result.is_ok(),
        error_message: result.as_ref().err().map(|e| format!("{e:#}")),
        arguments: Some(serde_json::json!({"from": "registry"})),
        acl_decision: None,
        acl_matched_rule: None,
        acl_access_kind: None,
        classification_kind: None,
        classification_source: None,
        classification_confidence: None,
    });

    result
}

fn read_stdin_or_empty() -> Result<serde_json::Value> {
    if std::io::stdin().is_terminal() {
        return Ok(serde_json::json!({}));
    }

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input = input.trim();
    if input.is_empty() {
        Ok(serde_json::json!({}))
    } else {
        Ok(serde_json::from_str(input)?)
    }
}
