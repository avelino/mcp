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
            });

            return result;
        }
        "logs" => {
            return handle_logs_command(&args[1..], &cfg, fmt, db_pool.clone()).await;
        }
        "acl" => {
            return handle_acl_command(&args[1..], &cfg, fmt).await;
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
) -> Result<()> {
    let sub = args.first().map(String::as_str).ok_or_else(|| {
        anyhow::anyhow!("usage: mcp acl classify [--server <alias>] [--format table|json]")
    })?;
    if sub != "classify" {
        bail!("unknown acl subcommand: {sub} (did you mean 'classify'?)");
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
