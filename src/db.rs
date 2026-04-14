use anyhow::{Context, Result};
use chrondb::ChronDB;
use std::sync::Arc;
use std::time::Duration;

use crate::audit::AuditConfig;
use crate::config;

/// How long the ChronDB isolate can be idle before it suspends itself.
const DB_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Holds a ChronDB instance with built-in idle suspension.
///
/// ChronDB 0.2+ manages the GraalVM isolate lifecycle internally via
/// `builder().idle_timeout()` — the isolate suspends after inactivity
/// and transparently resumes on next operation. No external GC thread needed.
///
/// Shared across audit logging, tool cache, and future consumers.
pub struct DbPool {
    db: Option<Arc<ChronDB>>,
}

impl DbPool {
    /// Creates a disabled pool (no database available).
    pub fn disabled() -> Self {
        Self { db: None }
    }

    /// Opens a ChronDB instance with idle timeout via the builder API.
    fn open(data_path: &str, index_path: &str, idle_timeout: Duration) -> Result<Self> {
        let db = ChronDB::builder(data_path, index_path)
            .idle_timeout(idle_timeout)
            .open()
            .map_err(|e| anyhow::anyhow!("failed to open db: {e:?}"))?;
        tracing::info!(idle_timeout = ?idle_timeout, "database opened");
        Ok(Self {
            db: Some(Arc::new(db)),
        })
    }

    /// Acquire a handle to ChronDB.
    pub fn acquire(&self) -> Result<Arc<ChronDB>> {
        self.db
            .clone()
            .ok_or_else(|| anyhow::anyhow!("database not available"))
    }
}

/// Creates a shared DbPool using ChronDB's native idle timeout.
/// Uses audit config path overrides if set, otherwise falls back to the shared db paths.
/// Returns a disabled pool when audit is disabled (e.g. container with read-only fs).
pub fn create_pool(audit_config: &AuditConfig) -> Result<Arc<DbPool>> {
    if !audit_config.enabled {
        tracing::info!("audit disabled, skipping database initialization");
        return Ok(Arc::new(DbPool::disabled()));
    }

    let data_path = match audit_config.data_path_override() {
        Some(p) => p.to_string(),
        None => config::db_data_path()?,
    };
    let index_path = match audit_config.index_path_override() {
        Some(p) => p.to_string(),
        None => config::db_index_path()?,
    };

    std::fs::create_dir_all(&data_path)
        .with_context(|| format!("failed to create db data dir: {data_path}"))?;
    std::fs::create_dir_all(&index_path)
        .with_context(|| format!("failed to create db index dir: {index_path}"))?;

    let pool = DbPool::open(&data_path, &index_path, DB_IDLE_TIMEOUT)?;
    Ok(Arc::new(pool))
}
