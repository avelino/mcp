mod auth;
mod client;
mod config;
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
    eprintln!("  mcp <server> <tool> [json]          Call a tool");
    eprintln!("  mcp search <query>                  Search MCP registry");
    eprintln!("  mcp add <name>                      Add server from registry");
    eprintln!("  mcp add --url <url> <name>          Add HTTP server manually");
    eprintln!("  mcp remove <name>                   Remove server from config");
    eprintln!("  mcp serve                           Start proxy server (stdio)");
    eprintln!("  mcp serve --http [addr]             Start proxy server over HTTP");
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

    if args[0] == "--list" {
        return output::print_servers(&cfg.servers, fmt);
    }

    let first = &args[0];

    match first.as_str() {
        "search" => {
            if args.len() < 2 {
                bail!("usage: mcp search <query>");
            }
            let query = args[1..].join(" ");
            let sp = spinner::Spinner::start("searching registry...");
            let results = registry::search_servers(&query).await?;
            sp.stop();
            output::print_search_results(&results, fmt)?;
            return Ok(());
        }
        "serve" => {
            let rest = &args[1..];
            let insecure = rest.iter().any(|a| a == "--insecure");
            let http_addr = if let Some(pos) = rest.iter().position(|a| a == "--http") {
                // Next arg is the bind address, or default to 127.0.0.1:8080
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
        "add" => {
            return handle_add(&args[1..]).await;
        }
        "remove" => {
            if args.len() < 2 {
                bail!("usage: mcp remove <name>");
            }
            manager::remove_server(&args[1])?;
            return Ok(());
        }
        _ => {}
    }

    handle_server_command(&args, &cfg, fmt).await
}

async fn handle_server_command(
    args: &[String],
    cfg: &config::Config,
    fmt: OutputFormat,
) -> Result<()> {
    let server_name = &args[0];
    let server_config = cfg
        .servers
        .get(server_name)
        .ok_or_else(|| anyhow::anyhow!("server \"{server_name}\" not found in config"))?;

    let sp = spinner::Spinner::start(&format!("connecting to {server_name}..."));
    let mut client = client::McpClient::connect(server_config).await?;
    sp.stop();

    if args.len() == 1 || (args.len() >= 2 && args[1] == "--list") {
        let sp = spinner::Spinner::start("listing tools...");
        let tools = client.list_tools().await?;
        sp.stop();
        output::print_tools(&tools, fmt)?;
        client.shutdown().await?;
        return Ok(());
    }

    if args.len() >= 2 && args[1] == "--info" {
        let sp = spinner::Spinner::start("listing tools...");
        let tools = client.list_tools().await?;
        sp.stop();
        output::print_tools_info(&tools, fmt)?;
        client.shutdown().await?;
        return Ok(());
    }

    let tool_name = &args[1];
    let json_args = if args.len() >= 3 {
        serde_json::from_str(&args[2])?
    } else {
        read_stdin_or_empty()?
    };

    let sp = spinner::Spinner::start(&format!("calling {tool_name}..."));
    let result = client.call_tool(tool_name, json_args).await?;
    sp.stop();
    output::print_tool_result(&result, fmt)?;
    client.shutdown().await?;

    Ok(())
}

async fn handle_add(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: mcp add <name> or mcp add --url <url> <name>");
    }

    if args[0] == "--url" {
        if args.len() < 3 {
            bail!("usage: mcp add --url <url> <name>");
        }
        let url = &args[1];
        let name = &args[2];
        manager::add_http(name, url)?;
        return Ok(());
    }

    let name = &args[0];
    manager::add_from_registry(name).await?;

    Ok(())
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
