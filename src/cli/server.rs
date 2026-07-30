use anyhow::Result;
use std::sync::Arc;

use crate::audit;
use crate::client;
use crate::config;
use crate::output;
use crate::output::OutputFormat;
use crate::protocol::Tool;
use crate::spinner;

pub async fn handle_server_command(
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

    // Route through a running `mcp serve` proxy (which keeps backends warm) when
    // MCP_PROXY_URL is set — avoids the per-call cold start of spawning a fresh
    // backend. The proxy namespaces tools as `{server}__{tool}`, so we prefix on
    // calls and strip the prefix from listings. Falls back to a local spawn if
    // the proxy is unreachable.
    let proxy_url = std::env::var("MCP_PROXY_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    let mut via_proxy = false;
    let sp = spinner::Spinner::start(&format!("connecting to {server_name}..."));
    let client = match &proxy_url {
        Some(url) => match client::McpClient::connect_via_proxy(url).await {
            Ok(c) => {
                via_proxy = true;
                c
            }
            Err(e) => {
                eprintln!("mcp: proxy {url} unreachable ({e}); spawning {server_name} locally");
                client::McpClient::connect(server_config).await?
            }
        },
        None => client::McpClient::connect(server_config).await?,
    };
    sp.stop();

    if args.len() == 1 || (args.len() >= 2 && args[1] == "--list") {
        let start = std::time::Instant::now();
        let sp = spinner::Spinner::start("listing tools...");
        let result = client
            .list_tools()
            .await
            .map(|tools| filter_if_proxy(tools, via_proxy, server_name));
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

        // The revision we agreed on is the single most useful thing a health
        // check can report once two revisions are in play: it says whether we
        // fell back to the legacy handshake or negotiated 2026-07-28. Added
        // as a JSON field only — the text line stays byte-identical for
        // whatever is already grepping it.
        let protocol_version = client.protocol_version().to_string();
        client.shutdown().await?;

        match fmt {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::json!({
                        "server": server_name,
                        "status": "ok",
                        "protocolVersion": protocol_version,
                    })
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
        let result = client
            .list_tools()
            .await
            .map(|tools| filter_if_proxy(tools, via_proxy, server_name));
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
        crate::read_stdin_or_empty()?
    };

    // The proxy addresses tools by their namespaced `{server}__{tool}` name.
    let call_name = if via_proxy {
        format!("{server_name}__{tool_name}")
    } else {
        tool_name.clone()
    };
    let start = std::time::Instant::now();
    let sp = spinner::Spinner::start(&format!("calling {tool_name}..."));
    let result = client.call_tool(&call_name, json_args.clone()).await;
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

/// Strip a `{server}__` namespace prefix, returning the bare tool name when the
/// prefix matches this exact server (not a longer one). `None` for tools that
/// belong to a different backend or carry no namespace.
fn strip_server_prefix<'a>(name: &'a str, server: &str) -> Option<&'a str> {
    name.strip_prefix(server)
        .and_then(|rest| rest.strip_prefix("__"))
}

/// Keep only this server's tools and strip the `{server}__` prefix so proxy-routed
/// listings match the shape of a direct-spawn listing.
fn filter_server_tools(tools: Vec<Tool>, server: &str) -> Vec<Tool> {
    tools
        .into_iter()
        .filter_map(|mut t| {
            let bare = strip_server_prefix(&t.name, server).map(str::to_string);
            bare.map(|name| {
                t.name = name;
                t
            })
        })
        .collect()
}

/// No-op unless routing through the proxy, where every backend's tools come back
/// namespaced and must be narrowed to the requested server.
fn filter_if_proxy(tools: Vec<Tool>, via_proxy: bool, server: &str) -> Vec<Tool> {
    if via_proxy {
        filter_server_tools(tools, server)
    } else {
        tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_prefix_matches_exact_server_only() {
        assert_eq!(
            strip_server_prefix("roam__get_page", "roam"),
            Some("get_page")
        );
        assert_eq!(strip_server_prefix("roam__a__b", "roam"), Some("a__b"));
        // different backend
        assert_eq!(strip_server_prefix("github__gh_pr", "roam"), None);
        // longer server name that merely starts with the prefix
        assert_eq!(strip_server_prefix("roamx__t", "roam"), None);
        // no namespace at all
        assert_eq!(strip_server_prefix("bare", "roam"), None);
    }

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn filter_keeps_only_this_server_and_strips_prefix() {
        let tools = vec![
            tool("roam__get_page"),
            tool("github__gh_pr"),
            tool("roam__search"),
            tool("bare"),
        ];
        let names: Vec<_> = filter_server_tools(tools, "roam")
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["get_page", "search"]);
    }

    #[test]
    fn filter_if_proxy_is_noop_when_local() {
        let tools = vec![tool("roam__get_page"), tool("bare")];
        let got = filter_if_proxy(tools, false, "roam");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "roam__get_page");
    }
}
