use anyhow::{Context, Result};
use chrondb::ChronDB;
use std::sync::Arc;

use crate::audit::AuditConfig;
use crate::config;

/// How long the ChronDB connection can be idle before the GC closes it.
const DB_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// How often the GC thread checks for idle connections.
const DB_GC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Manages the ChronDB connection lifecycle: open on first use, close when idle.
///
/// ChronDB loads a GraalVM native-image shared library whose internal threads
/// consume CPU even when no operations are in flight. This struct ensures the
/// isolate only exists while the database is actively being used.
///
/// A background GC thread monitors `last_used` and drops the connection after
/// [`DB_IDLE_TIMEOUT`] of inactivity, tearing down the GraalVM isolate.
/// The next operation transparently reopens it.
///
/// Shared across audit logging, tool cache, and future consumers.
pub struct DbPool {
    data_path: String,
    index_path: String,
    inner: std::sync::Mutex<DbPoolInner>,
}

struct DbPoolInner {
    db: Option<Arc<ChronDB>>,
    last_used: std::time::Instant,
}

impl DbPool {
    pub fn new(data_path: String, index_path: String) -> Self {
        Self {
            data_path,
            index_path,
            inner: std::sync::Mutex::new(DbPoolInner {
                db: None,
                last_used: std::time::Instant::now(),
            }),
        }
    }

    /// Acquire a handle to ChronDB — opens if not connected.
    pub fn acquire(&self) -> Result<Arc<ChronDB>> {
        let mut inner = self.inner.lock().unwrap();
        inner.last_used = std::time::Instant::now();
        if let Some(ref db) = inner.db {
            return Ok(db.clone());
        }
        let db = ChronDB::open(&self.data_path, &self.index_path)
            .map_err(|e| anyhow::anyhow!("failed to open db: {e:?}"))?;
        let db = Arc::new(db);
        inner.db = Some(db.clone());
        eprintln!("[db] database opened");
        Ok(db)
    }

    /// GC tick: close if idle longer than `max_idle`.
    /// Returns true if the connection was closed.
    pub fn gc(&self, max_idle: std::time::Duration) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.db.is_some() && inner.last_used.elapsed() >= max_idle {
            inner.db = None;
            eprintln!("[db] database closed (idle {:?})", max_idle);
            return true;
        }
        false
    }
}

/// Creates a shared DbPool with a background GC thread.
/// Uses audit config path overrides if set, otherwise falls back to the shared db paths.
pub fn create_pool(audit_config: &AuditConfig) -> Result<Arc<DbPool>> {
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

    let pool = Arc::new(DbPool::new(data_path, index_path));

    let gc_pool = pool.clone();
    std::thread::Builder::new()
        .name("db-gc".to_string())
        .spawn(move || loop {
            std::thread::sleep(DB_GC_INTERVAL);
            gc_pool.gc(DB_IDLE_TIMEOUT);
        })
        .ok();

    Ok(pool)
}
