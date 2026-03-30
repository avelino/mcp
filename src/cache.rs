use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::db::DbPool;
use crate::protocol::Tool;

const KEY_PREFIX: &str = "cache:tools:";

#[derive(Serialize, Deserialize, Clone)]
pub struct BackendToolCache {
    pub config_hash: String,
    pub tools: Vec<Tool>,
    pub cached_at: String,
}

pub struct ToolCacheStore {
    pool: Arc<DbPool>,
}

impl ToolCacheStore {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }

    pub fn load_backend(&self, name: &str) -> Option<BackendToolCache> {
        let db = self.pool.acquire().ok()?;
        let key = format!("{KEY_PREFIX}{name}");
        let val = db.get(&key, None).ok()?;
        serde_json::from_value(val).ok()
    }

    pub fn save_backend(&self, name: &str, entry: &BackendToolCache) {
        let db = match self.pool.acquire() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("[cache] failed to acquire db: {e}");
                return;
            }
        };
        let key = format!("{KEY_PREFIX}{name}");
        let val = match serde_json::to_value(entry) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[cache] failed to serialize cache for {name}: {e}");
                return;
            }
        };
        if let Err(e) = db.put(&key, &val, None) {
            eprintln!("[cache] failed to save cache for {name}: {e}");
        }
    }

    /// Load all cached backends, filtering by current config hashes.
    pub fn load_valid_backends(
        &self,
        config_hashes: &HashMap<String, String>,
    ) -> HashMap<String, BackendToolCache> {
        let mut result = HashMap::new();
        for (name, expected_hash) in config_hashes {
            if let Some(entry) = self.load_backend(name) {
                if entry.config_hash == *expected_hash {
                    result.insert(name.clone(), entry);
                } else {
                    eprintln!("[cache] stale cache for {name} (config changed)");
                }
            }
        }
        result
    }
}
