mod audit;
mod auth;
mod cache;
mod classifier;
mod classifier_cache;
mod cli;
mod cli_discovery;
mod client;
mod config;
mod db;
mod logging;
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
    logging::init();
    if let Err(e) = run().await {
        tracing::error!(error = format!("{e:#}"), "fatal error");
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
    eprintln!("  mcp config path                     Show config file path");
    eprintln!("  mcp config edit                     Open config in $EDITOR");
    eprintln!("  mcp completions <shell>             Generate shell completions (bash, zsh, fish)");
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
        tracing::warn!(
            server = %name,
            config = %cfg.path.display(),
            "server name conflicts with a reserved command name — rename it to avoid unexpected behavior"
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

    // Shared database pool for audit logging and tool cache.
    // Skip heavy DB init when audit output goes to stdout/stderr/none.
    let db_pool = if cfg.audit.output == audit::AuditOutput::File {
        db::create_pool(&cfg.audit).unwrap_or_else(|e| {
            tracing::warn!(error = format!("{e:#}"), "failed to create db pool");
            Arc::new(db::DbPool::disabled())
        })
    } else {
        Arc::new(db::DbPool::disabled())
    };

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
            return cli::handle_logs_command(&args[1..], &cfg, fmt, db_pool.clone()).await;
        }
        "acl" => {
            return cli::handle_acl_command(&args[1..], &cfg, fmt, &audit).await;
        }
        "config" => {
            return cli::handle_config_command(&args[1..], fmt);
        }
        "completions" => {
            return cli::handle_completions_command(&args[1..]);
        }
        _ => {}
    }

    cli::handle_server_command(&args, &cfg, fmt, &audit).await
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

pub(crate) fn read_stdin_or_empty() -> Result<serde_json::Value> {
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
