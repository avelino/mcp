use anyhow::Result;
use std::sync::Arc;

use crate::audit;
use crate::client;
use crate::config;
use crate::output;
use crate::output::OutputFormat;
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
        crate::read_stdin_or_empty()?
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
