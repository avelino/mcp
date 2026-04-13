use anyhow::Result;
use std::sync::Arc;

use crate::audit;
use crate::config;
use crate::db;
use crate::output;
use crate::output::OutputFormat;

pub async fn handle_logs_command(
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
