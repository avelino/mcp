use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
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

#[derive(Clone)]
pub struct ToolCacheStore {
    pool: Arc<DbPool>,
    /// JSON-file fallback used when ChronDB is unavailable (no prebuilt
    /// library for the platform, e.g. Windows). One `<backend>.json` per
    /// backend. `None` keeps the old behaviour: no persistent cache.
    file_dir: Option<PathBuf>,
}

impl ToolCacheStore {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self {
            pool,
            file_dir: None,
        }
    }

    /// Persist the cache as JSON files under `<config dir>/tool-cache/` when
    /// the database is unavailable, so a proxy restart still serves tools
    /// instantly instead of blocking on full discovery. No-op when the
    /// database works.
    pub fn with_file_fallback(mut self) -> Self {
        if self.pool.acquire().is_err() {
            match crate::config::config_dir() {
                Ok(dir) => {
                    let dir = dir.join("tool-cache");
                    match std::fs::create_dir_all(&dir) {
                        Ok(()) => self.file_dir = Some(dir),
                        Err(e) => eprintln!("[cache] file fallback unavailable: {e}"),
                    }
                }
                Err(e) => eprintln!("[cache] file fallback unavailable: {e}"),
            }
        }
        self
    }

    fn file_path(&self, name: &str) -> Option<PathBuf> {
        // Backend names come from the user's config; keep them to one path
        // component so a name can never point outside the cache dir.
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.file_dir
            .as_ref()
            .map(|d| d.join(format!("{safe}.json")))
    }

    pub fn load_backend(&self, name: &str) -> Option<BackendToolCache> {
        if let Some(path) = self.file_path(name) {
            let text = std::fs::read_to_string(path).ok()?;
            return serde_json::from_str(&text).ok();
        }
        let db = self.pool.acquire().ok()?;
        let key = format!("{KEY_PREFIX}{name}");
        let val = db.get(&key, None).ok()?;
        serde_json::from_value(val).ok()
    }

    pub fn save_backend(&self, name: &str, entry: &BackendToolCache) {
        if let Some(path) = self.file_path(name) {
            let text = match serde_json::to_string(entry) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[cache] failed to serialize cache for {name}: {e}");
                    return;
                }
            };
            // Write-then-rename so a crash mid-write never leaves a torn file
            // that would be served on the next start.
            let tmp = path.with_extension("json.tmp");
            if let Err(e) = std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, &path)) {
                eprintln!("[cache] failed to save cache for {name}: {e}");
            }
            return;
        }
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

    /// Drops a backend's cached tool list. Failures are logged, not
    /// propagated: a missing key or unavailable db must not fail a reload.
    pub fn delete_backend(&self, name: &str) {
        if let Some(path) = self.file_path(name) {
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("[cache] failed to delete cache for {name}: {e}");
                }
            }
            return;
        }
        let db = match self.pool.acquire() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("[cache] failed to acquire db: {e}");
                return;
            }
        };
        let key = format!("{KEY_PREFIX}{name}");
        if let Err(e) = db.delete(&key, None) {
            eprintln!("[cache] failed to delete cache for {name}: {e}");
        }
    }

    /// Names of every backend that currently holds a cached tool list.
    ///
    /// `mcp reload` needs this to evict entries for backends that left the
    /// config. Those are invisible to `load_valid_backends`, which only looks
    /// up names the config still knows, so without a listing nothing would
    /// ever reclaim them.
    ///
    /// Best effort by design: the listing comes back as untyped JSON whose
    /// shape belongs to the storage layer, so an unrecognized shape yields an
    /// empty list instead of failing the reload that asked.
    pub fn list_cached_backends(&self) -> Vec<String> {
        if let Some(dir) = &self.file_dir {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    e.file_name()
                        .to_str()
                        .and_then(|f| f.strip_suffix(".json"))
                        .map(str::to_string)
                })
                .collect();
            names.sort();
            return names;
        }
        let Ok(db) = self.pool.acquire() else {
            return Vec::new();
        };
        let value = match db.list_by_prefix(KEY_PREFIX, None) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "could not list cached backends");
                return Vec::new();
            }
        };
        let mut names: Vec<String> = collect_ids(&value)
            .into_iter()
            .filter_map(|id| id.strip_prefix(KEY_PREFIX).map(str::to_string))
            .filter(|name| !name.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names
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

/// Pull document ids out of a listing, tolerating the shapes a document store
/// may return: a bare array of ids, an array of documents, or an envelope
/// keyed by id. Anything unrecognized contributes nothing.
fn collect_ids(value: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;

    fn id_of(item: &Value) -> Option<String> {
        match item {
            Value::String(s) => Some(s.clone()),
            Value::Object(map) => ["_id", "id", "key", "_key"]
                .iter()
                .find_map(|k| map.get(*k))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            _ => None,
        }
    }

    match value {
        Value::Array(items) => items.iter().filter_map(id_of).collect(),
        Value::Object(map) => {
            let keyed: Vec<String> = map
                .keys()
                .filter(|k| k.starts_with(KEY_PREFIX))
                .cloned()
                .collect();
            if !keyed.is_empty() {
                return keyed;
            }
            // Envelope around the real list.
            ["documents", "results", "docs", "data", "items"]
                .iter()
                .find_map(|k| map.get(*k))
                .map(collect_ids)
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_backend_with_disabled_pool_does_not_panic() {
        let store = ToolCacheStore::new(Arc::new(DbPool::disabled()));
        store.delete_backend("grafana");
        assert!(store.load_backend("grafana").is_none());
    }

    #[test]
    fn file_fallback_round_trips_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ToolCacheStore::new(Arc::new(DbPool::disabled()));
        store.file_dir = Some(dir.path().to_path_buf());
        let entry = BackendToolCache {
            config_hash: "h1".to_string(),
            tools: vec![],
            cached_at: "now".to_string(),
        };
        store.save_backend("kicad-yaz", &entry);
        assert_eq!(store.load_backend("kicad-yaz").unwrap().config_hash, "h1");
        assert_eq!(store.list_cached_backends(), vec!["kicad-yaz"]);
        let mut hashes = HashMap::new();
        hashes.insert("kicad-yaz".to_string(), "h2".to_string());
        assert!(
            store.load_valid_backends(&hashes).is_empty(),
            "stale hash must not load"
        );
        store.delete_backend("kicad-yaz");
        assert!(store.load_backend("kicad-yaz").is_none());
    }

    #[test]
    fn file_fallback_keeps_names_inside_the_cache_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ToolCacheStore::new(Arc::new(DbPool::disabled()));
        store.file_dir = Some(dir.path().to_path_buf());
        let path = store.file_path("../evil").unwrap();
        assert_eq!(path.parent().unwrap(), dir.path());
    }

    #[test]
    fn list_cached_backends_with_disabled_pool_is_empty() {
        let store = ToolCacheStore::new(Arc::new(DbPool::disabled()));
        assert!(store.list_cached_backends().is_empty());
    }

    #[test]
    fn collect_ids_reads_an_array_of_ids() {
        let value = serde_json::json!(["cache:tools:roam", "cache:tools:grafana"]);
        assert_eq!(
            collect_ids(&value),
            vec!["cache:tools:roam", "cache:tools:grafana"]
        );
    }

    #[test]
    fn collect_ids_reads_an_array_of_documents() {
        let value = serde_json::json!([
            {"_id": "cache:tools:roam", "tools": []},
            {"id": "cache:tools:grafana"},
            {"key": "cache:tools:sentry"},
        ]);
        assert_eq!(
            collect_ids(&value),
            vec![
                "cache:tools:roam",
                "cache:tools:grafana",
                "cache:tools:sentry"
            ]
        );
    }

    #[test]
    fn collect_ids_reads_a_map_keyed_by_id() {
        let value = serde_json::json!({
            "cache:tools:roam": {"tools": []},
            "cache:tools:grafana": {"tools": []},
        });
        let mut ids = collect_ids(&value);
        ids.sort();
        assert_eq!(ids, vec!["cache:tools:grafana", "cache:tools:roam"]);
    }

    #[test]
    fn collect_ids_unwraps_an_envelope() {
        for key in ["documents", "results", "docs", "data", "items"] {
            let value = serde_json::json!({ key: ["cache:tools:roam"] });
            assert_eq!(
                collect_ids(&value),
                vec!["cache:tools:roam"],
                "envelope key {key} must be unwrapped"
            );
        }
    }

    /// The shape of the listing belongs to the storage layer. A reload must
    /// survive it changing, so anything unrecognized yields nothing.
    #[test]
    fn collect_ids_tolerates_unknown_shapes() {
        for value in [
            serde_json::json!(null),
            serde_json::json!(42),
            serde_json::json!("cache:tools:roam"),
            serde_json::json!({"unexpected": {"nested": true}}),
            serde_json::json!([1, 2, 3]),
        ] {
            assert!(
                collect_ids(&value).is_empty(),
                "unexpected shape must yield nothing: {value}"
            );
        }
    }
}
