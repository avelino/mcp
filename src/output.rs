use anyhow::Result;
use comfy_table::{presets, Attribute, Cell, Color, ContentArrangement, Table};
use console::style;
use crate::config::ServerConfig;
use crate::protocol::{Tool, ToolCallResult};
use crate::registry::RegistryServer;
use serde_json::json;
use std::collections::HashMap;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn detect(json_flag: bool) -> Self {
        if json_flag {
            OutputFormat::Json
        } else if std::io::stdout().is_terminal() {
            OutputFormat::Text
        } else {
            OutputFormat::Json
        }
    }
}

pub fn print_servers(servers: &HashMap<String, ServerConfig>, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_servers_json(servers),
        OutputFormat::Text => print_servers_text(servers),
    }
}

pub fn print_tools(tools: &[Tool], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_tools_json(tools),
        OutputFormat::Text => print_tools_text(tools),
    }
}

pub fn print_tools_info(tools: &[Tool], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_tools_info_json(tools),
        OutputFormat::Text => print_tools_info_text(tools),
    }
}

pub fn print_tool_result(result: &ToolCallResult, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_tool_result_json(result),
        OutputFormat::Text => print_tool_result_text(result),
    }
}

pub fn print_search_results(servers: &[RegistryServer], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_search_results_json(servers),
        OutputFormat::Text => print_search_results_text(servers),
    }
}

// --- JSON output (existing behavior) ---

fn print_servers_json(servers: &HashMap<String, ServerConfig>) -> Result<()> {
    let list: Vec<serde_json::Value> = servers
        .iter()
        .map(|(name, config)| match config {
            ServerConfig::Stdio { command, args, .. } => json!({
                "name": name,
                "type": "stdio",
                "command": command,
                "args": args,
            }),
            ServerConfig::Http { url, .. } => json!({
                "name": name,
                "type": "http",
                "url": url,
            }),
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

fn print_tools_json(tools: &[Tool]) -> Result<()> {
    let list: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

fn print_tools_info_json(tools: &[Tool]) -> Result<()> {
    let list: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

fn print_tool_result_json(result: &ToolCallResult) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}

fn print_search_results_json(servers: &[RegistryServer]) -> Result<()> {
    let list: Vec<serde_json::Value> = servers
        .iter()
        .map(|s| {
            let mut entry = json!({
                "name": s.name,
                "description": s.description,
            });

            if let Some(ref repo) = s.repository {
                entry["repository"] = json!(repo.url);
            }

            if !s.packages.is_empty() {
                let install: Vec<String> = s
                    .packages
                    .iter()
                    .map(|p| {
                        if let Some(ref runtime) = p.runtime {
                            format!("{} {}", runtime, p.name)
                        } else {
                            p.name.clone()
                        }
                    })
                    .collect();
                entry["install"] = json!(install);
            }

            entry
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}

// --- Human-friendly text output ---

fn header_cell(text: &str) -> Cell {
    Cell::new(text)
        .add_attribute(Attribute::Bold)
        .fg(Color::Cyan)
}

fn type_cell(stype: &str) -> Cell {
    let color = match stype {
        "stdio" => Color::Yellow,
        "http" => Color::Green,
        _ => Color::White,
    };
    Cell::new(stype).fg(color)
}

fn print_servers_text(servers: &HashMap<String, ServerConfig>) -> Result<()> {
    if servers.is_empty() {
        println!("{}", style("No servers configured.").dim());
        return Ok(());
    }

    let mut rows: Vec<(String, String, String)> = servers
        .iter()
        .map(|(name, config)| match config {
            ServerConfig::Stdio { command, args, .. } => {
                let endpoint = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };
                (name.clone(), "stdio".to_string(), endpoint)
            }
            ServerConfig::Http { url, .. } => {
                (name.clone(), "http".to_string(), url.clone())
            }
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    let mut table = Table::new();
    table
        .load_preset(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header_cell("Server"),
            header_cell("Type"),
            header_cell("Endpoint"),
        ]);

    for (name, stype, endpoint) in &rows {
        table.add_row(vec![
            Cell::new(name).add_attribute(Attribute::Bold),
            type_cell(stype),
            Cell::new(endpoint).fg(Color::DarkGrey),
        ]);
    }

    println!("{table}");
    println!(
        "\n{}",
        style(format!("{} server(s) configured", rows.len())).dim()
    );
    Ok(())
}

fn print_tools_text(tools: &[Tool]) -> Result<()> {
    if tools.is_empty() {
        println!("{}", style("No tools available.").dim());
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header_cell("Tool"),
            header_cell("Description"),
        ]);

    for t in tools {
        let desc = t.description.as_deref().unwrap_or("-");
        table.add_row(vec![
            Cell::new(&t.name).add_attribute(Attribute::Bold),
            Cell::new(desc),
        ]);
    }

    println!("{table}");
    println!(
        "\n{}",
        style(format!("{} tool(s) available", tools.len())).dim()
    );
    Ok(())
}

fn print_tools_info_text(tools: &[Tool]) -> Result<()> {
    if tools.is_empty() {
        println!("{}", style("No tools available.").dim());
        return Ok(());
    }

    for (i, t) in tools.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("{}", style(&t.name).bold().cyan());
        if let Some(ref desc) = t.description {
            println!("  {}", desc);
        }
        if let Some(ref schema) = t.input_schema {
            if let Some(props) = schema.get("properties") {
                if let Some(obj) = props.as_object() {
                    let required: Vec<String> = schema
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    println!("  {}:", style("Parameters").dim());
                    for (name, prop) in obj {
                        let ptype = prop
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("any");
                        let is_req = required.contains(name);
                        let pdesc = prop
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let req_tag = if is_req {
                            format!(" {}", style("(required)").yellow())
                        } else {
                            String::new()
                        };

                        if pdesc.is_empty() {
                            println!(
                                "    {} {}{}",
                                style(name).green(),
                                style(ptype).dim(),
                                req_tag,
                            );
                        } else {
                            println!(
                                "    {} {} — {}{}",
                                style(name).green(),
                                style(ptype).dim(),
                                pdesc,
                                req_tag,
                            );
                        }
                    }
                }
            }
        }
    }
    println!(
        "\n{}",
        style(format!("{} tool(s) available", tools.len())).dim()
    );
    Ok(())
}

fn print_tool_result_text(result: &ToolCallResult) -> Result<()> {
    let is_error = result.is_error.unwrap_or(false);

    if is_error {
        eprint!("{} ", style("error:").red().bold());
    }

    for content in &result.content {
        match content.content_type.as_str() {
            "text" => {
                if let Some(ref text) = content.text {
                    if is_error {
                        eprintln!("{}", text);
                    } else {
                        println!("{}", text);
                    }
                }
            }
            "image" => {
                let mime = content.mime_type.as_deref().unwrap_or("image/*");
                println!("{}", style(format!("[image: {mime}]")).dim());
            }
            "resource" => {
                if let Some(ref text) = content.text {
                    println!("{}", text);
                } else {
                    let mime = content.mime_type.as_deref().unwrap_or("unknown");
                    println!("{}", style(format!("[resource: {mime}]")).dim());
                }
            }
            other => {
                if let Some(ref text) = content.text {
                    println!("{}", text);
                } else {
                    println!("{}", style(format!("[{other}: unsupported content type]")).dim());
                }
            }
        }
    }
    Ok(())
}

fn print_search_results_text(servers: &[RegistryServer]) -> Result<()> {
    if servers.is_empty() {
        println!("{}", style("No servers found.").dim());
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header_cell("Name"),
            header_cell("Description"),
            header_cell("Install"),
        ]);

    for s in servers {
        let desc = s.description.as_deref().unwrap_or("-");
        let install = if !s.packages.is_empty() {
            s.packages
                .iter()
                .map(|p| {
                    if let Some(ref runtime) = p.runtime {
                        format!("{} {}", runtime, p.name)
                    } else {
                        p.name.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            "-".to_string()
        };

        table.add_row(vec![
            Cell::new(&s.name).add_attribute(Attribute::Bold),
            Cell::new(desc),
            Cell::new(&install).fg(Color::DarkGrey),
        ]);
    }

    println!("{table}");
    println!(
        "\n{}",
        style(format!("{} result(s)", servers.len())).dim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Content;
    use crate::registry::{Package, Repository};

    fn text_content(text: &str) -> Content {
        Content {
            content_type: "text".to_string(),
            text: Some(text.to_string()),
            data: None,
            mime_type: None,
        }
    }

    // --- OutputFormat ---

    #[test]
    fn test_output_format_json_flag_forces_json() {
        assert_eq!(OutputFormat::detect(true), OutputFormat::Json);
    }

    // --- Servers ---

    #[test]
    fn test_print_servers_json_includes_both_types() {
        let mut servers = HashMap::new();
        servers.insert(
            "local".to_string(),
            ServerConfig::Stdio {
                command: "echo".to_string(),
                args: vec!["hello".to_string()],
                env: HashMap::new(),
            },
        );
        servers.insert(
            "remote".to_string(),
            ServerConfig::Http {
                url: "https://example.com/mcp".to_string(),
                headers: HashMap::new(),
            },
        );
        // Should not panic and produces valid JSON
        print_servers_json(&servers).unwrap();
    }

    #[test]
    fn test_print_servers_text_empty() {
        print_servers_text(&HashMap::new()).unwrap();
    }

    #[test]
    fn test_print_servers_text_sorted_output() {
        let mut servers = HashMap::new();
        servers.insert(
            "sentry".to_string(),
            ServerConfig::Http {
                url: "https://mcp.sentry.dev/mcp".to_string(),
                headers: HashMap::new(),
            },
        );
        servers.insert(
            "slack".to_string(),
            ServerConfig::Stdio {
                command: "npx".to_string(),
                args: vec!["-y".to_string(), "slack-mcp-server".to_string()],
                env: HashMap::new(),
            },
        );
        servers.insert(
            "grafana".to_string(),
            ServerConfig::Stdio {
                command: "uvx".to_string(),
                args: vec![],
                env: HashMap::new(),
            },
        );
        print_servers_text(&servers).unwrap();
    }

    // --- Tools ---

    #[test]
    fn test_print_tools_json_structure() {
        let tools = vec![Tool {
            name: "search".to_string(),
            description: Some("Search things".to_string()),
            input_schema: None,
        }];
        print_tools_json(&tools).unwrap();
    }

    #[test]
    fn test_print_tools_text_empty() {
        print_tools_text(&[]).unwrap();
    }

    #[test]
    fn test_print_tools_text_with_and_without_description() {
        let tools = vec![
            Tool {
                name: "search_issues".to_string(),
                description: Some("Search for issues in Sentry".to_string()),
                input_schema: None,
            },
            Tool {
                name: "ping".to_string(),
                description: None,
                input_schema: None,
            },
        ];
        print_tools_text(&tools).unwrap();
    }

    // --- Tools info ---

    #[test]
    fn test_print_tools_info_text_with_schema() {
        let tools = vec![Tool {
            name: "search_issues".to_string(),
            description: Some("Search for issues".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "limit": {
                        "type": "integer"
                    }
                },
                "required": ["query"]
            })),
        }];
        print_tools_info_text(&tools).unwrap();
    }

    #[test]
    fn test_print_tools_info_text_no_schema() {
        let tools = vec![Tool {
            name: "ping".to_string(),
            description: None,
            input_schema: None,
        }];
        print_tools_info_text(&tools).unwrap();
    }

    #[test]
    fn test_print_tools_info_text_empty() {
        print_tools_info_text(&[]).unwrap();
    }

    #[test]
    fn test_print_tools_info_json_with_schema() {
        let tools = vec![Tool {
            name: "search".to_string(),
            description: Some("Search".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"]
            })),
        }];
        print_tools_info_json(&tools).unwrap();
    }

    // --- Tool result ---

    #[test]
    fn test_tool_result_text_prints_text() {
        let result = ToolCallResult {
            content: vec![text_content("hello world")],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_error_goes_to_stderr() {
        let result = ToolCallResult {
            content: vec![text_content("something failed")],
            is_error: Some(true),
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_image_shows_mime() {
        let result = ToolCallResult {
            content: vec![Content {
                content_type: "image".to_string(),
                text: None,
                data: Some("base64data".to_string()),
                mime_type: Some("image/png".to_string()),
            }],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_image_no_mime() {
        let result = ToolCallResult {
            content: vec![Content {
                content_type: "image".to_string(),
                text: None,
                data: Some("data".to_string()),
                mime_type: None,
            }],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_resource_with_text() {
        let result = ToolCallResult {
            content: vec![Content {
                content_type: "resource".to_string(),
                text: Some("resource content".to_string()),
                data: None,
                mime_type: Some("text/plain".to_string()),
            }],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_resource_without_text() {
        let result = ToolCallResult {
            content: vec![Content {
                content_type: "resource".to_string(),
                text: None,
                data: None,
                mime_type: Some("application/pdf".to_string()),
            }],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_unknown_type_with_text() {
        let result = ToolCallResult {
            content: vec![Content {
                content_type: "custom".to_string(),
                text: Some("custom data".to_string()),
                data: None,
                mime_type: None,
            }],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_unknown_type_without_text() {
        let result = ToolCallResult {
            content: vec![Content {
                content_type: "binary".to_string(),
                text: None,
                data: Some("raw".to_string()),
                mime_type: None,
            }],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_multiple_content_blocks() {
        let result = ToolCallResult {
            content: vec![
                text_content("first block"),
                text_content("second block"),
                Content {
                    content_type: "image".to_string(),
                    text: None,
                    data: Some("img".to_string()),
                    mime_type: Some("image/jpeg".to_string()),
                },
            ],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_text_empty_content() {
        let result = ToolCallResult {
            content: vec![],
            is_error: None,
        };
        print_tool_result_text(&result).unwrap();
    }

    #[test]
    fn test_tool_result_json() {
        let result = ToolCallResult {
            content: vec![text_content("data")],
            is_error: Some(false),
        };
        print_tool_result_json(&result).unwrap();
    }

    // --- Search results ---

    #[test]
    fn test_print_search_results_text_empty() {
        print_search_results_text(&[]).unwrap();
    }

    #[test]
    fn test_print_search_results_text_with_data() {
        let servers = vec![
            RegistryServer {
                name: "filesystem".to_string(),
                description: Some("Access local files".to_string()),
                repository: Some(Repository {
                    url: "https://github.com/example/fs".to_string(),
                }),
                packages: vec![Package {
                    name: "@mcp/filesystem".to_string(),
                    runtime: Some("npx".to_string()),
                    runtime_args: vec![],
                    package_args: vec![],
                    environment_variables: vec![],
                }],
                remotes: vec![],
            },
            RegistryServer {
                name: "database".to_string(),
                description: None,
                repository: None,
                packages: vec![],
                remotes: vec![],
            },
        ];
        print_search_results_text(&servers).unwrap();
    }

    #[test]
    fn test_print_search_results_json_with_data() {
        let servers = vec![RegistryServer {
            name: "test-server".to_string(),
            description: Some("A test server".to_string()),
            repository: Some(Repository {
                url: "https://github.com/test/repo".to_string(),
            }),
            packages: vec![Package {
                name: "test-pkg".to_string(),
                runtime: Some("node".to_string()),
                runtime_args: vec![],
                package_args: vec![],
                environment_variables: vec![],
            }],
            remotes: vec![],
        }];
        print_search_results_json(&servers).unwrap();
    }

    // --- Dispatch: format selection routes correctly ---

    #[test]
    fn test_print_servers_dispatches_json() {
        let servers = HashMap::new();
        print_servers(&servers, OutputFormat::Json).unwrap();
    }

    #[test]
    fn test_print_servers_dispatches_text() {
        let servers = HashMap::new();
        print_servers(&servers, OutputFormat::Text).unwrap();
    }

    #[test]
    fn test_print_tools_dispatches_json() {
        print_tools(&[], OutputFormat::Json).unwrap();
    }

    #[test]
    fn test_print_tools_dispatches_text() {
        print_tools(&[], OutputFormat::Text).unwrap();
    }

    #[test]
    fn test_print_tool_result_dispatches_json() {
        let result = ToolCallResult {
            content: vec![text_content("ok")],
            is_error: None,
        };
        print_tool_result(&result, OutputFormat::Json).unwrap();
    }

    #[test]
    fn test_print_tool_result_dispatches_text() {
        let result = ToolCallResult {
            content: vec![text_content("ok")],
            is_error: None,
        };
        print_tool_result(&result, OutputFormat::Text).unwrap();
    }
}
