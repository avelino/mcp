mod auth;
mod client;
mod config;
mod manager;
mod output;
mod protocol;
mod registry;
mod transport;

use anyhow::{bail, Result};
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
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let cfg = config::load_config()?;
    let conflicts = config::validate_server_names(&cfg);
    for name in &conflicts {
        eprintln!(
            "warning: server \"{name}\" conflicts with a reserved command name"
        );
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
        return output::print_servers(&cfg.servers);
    }

    let first = &args[0];

    match first.as_str() {
        "search" => {
            if args.len() < 2 {
                bail!("usage: mcp search <query>");
            }
            let query = args[1..].join(" ");
            let results = registry::search_servers(&query).await?;
            if results.is_empty() {
                eprintln!("no servers found for \"{query}\"");
            } else {
                output::print_search_results(&results)?;
            }
            return Ok(());
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

    handle_server_command(&args, &cfg).await
}

async fn handle_server_command(args: &[String], cfg: &config::Config) -> Result<()> {
    let server_name = &args[0];
    let server_config = cfg
        .servers
        .get(server_name)
        .ok_or_else(|| anyhow::anyhow!("server \"{server_name}\" not found in config"))?;

    let mut client = client::McpClient::connect(server_config).await?;

    if args.len() == 1 || (args.len() >= 2 && args[1] == "--list") {
        let tools = client.list_tools().await?;
        output::print_tools(&tools)?;
        client.shutdown().await?;
        return Ok(());
    }

    if args.len() >= 2 && args[1] == "--info" {
        let tools = client.list_tools().await?;
        output::print_tools_info(&tools)?;
        client.shutdown().await?;
        return Ok(());
    }

    let tool_name = &args[1];
    let json_args = if args.len() >= 3 {
        serde_json::from_str(&args[2])?
    } else {
        read_stdin_or_empty()?
    };

    let result = client.call_tool(tool_name, json_args).await?;
    output::print_tool_result(&result)?;
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
