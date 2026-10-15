//! Persistent classification cache for tool read/write metadata.
//!
//! Lives at `~/.config/mcp/tool-classification.json` by default, or at the
//! path given by `$MCP_CLASSIFIER_CACHE` (for CI/container use).
//!
//! Key format: `server_alias:tool_name:sha256(description+annotations)`. When the
//! description changes, the cache key changes and the old entry is
//! transparently replaced.
//!
//! Corrupt or unreadable cache is **not fatal**: we log a warning and
//! proceed with an empty cache. Overrides are never cached — they are
//! re-read from config on every run.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::classifier::ToolClassification;
use crate::protocol::ToolAnnotations;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ClassifierCache {
    #[serde(default)]
    entries: HashMap<String, ToolClassification>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    dirty: bool,
}

fn default_cache_path() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("MCP_CLASSIFIER_CACHE") {
        return Some(PathBuf::from(env));
    }
    crate::config::config_dir()
        .ok()
        .map(|d| d.join("tool-classification.json"))
}

pub fn cache_key(
    server: &str,
    tool: &str,
    description: Option<&str>,
    annotations: Option<&ToolAnnotations>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(description.unwrap_or("").as_bytes());
    // Include annotations so that changes to readOnlyHint/destructiveHint
    // invalidate the cache entry even when the description is unchanged.
    if let Some(ann) = annotations {
        if let Some(v) = ann.read_only_hint {
            hasher.update(if v { b"ro:1" } else { b"ro:0" });
        }
        if let Some(v) = ann.destructive_hint {
            hasher.update(if v { b"dh:1" } else { b"dh:0" });
        }
    }
    let hash = hasher.finalize();
    // First 8 bytes hex is enough — collision within a single (server,tool) is
    // effectively impossible for any realistic description set.
    let short: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{server}:{tool}:{short}")
}

impl ClassifierCache {
    pub fn load() -> Self {
        let Some(path) = default_cache_path() else {
            return Self::default();
        };
        if !path.exists() {
            return Self {
                path,
                ..Default::default()
            };
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<ClassifierCache>(&content) {
                Ok(mut cache) => {
                    cache.path = path;
                    cache
                }
                Err(e) => {
                    eprintln!(
                        "[classifier-cache] warning: cache at {} is corrupt, starting fresh: {e}",
                        path.display()
                    );
                    Self {
                        path,
                        ..Default::default()
                    }
                }
            },
            Err(e) => {
                eprintln!(
                    "[classifier-cache] warning: could not read {}: {e}",
                    path.display()
                );
                Self {
                    path,
                    ..Default::default()
                }
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&ToolClassification> {
        self.entries.get(key)
    }

    pub fn put(&mut self, key: String, value: ToolClassification) {
        self.entries.insert(key, value);
        self.dirty = true;
    }

    /// Persist to disk. No-op if nothing changed or the path is unset.
    pub fn save(&mut self) {
        if !self.dirty || self.path.as_os_str().is_empty() {
            return;
        }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    eprintln!(
                        "[classifier-cache] warning: failed to write {}: {e}",
                        self.path.display()
                    );
                } else {
                    self.dirty = false;
                }
            }
            Err(e) => {
                eprintln!("[classifier-cache] warning: failed to serialize cache: {e}");
            }
        }
    }

    /// Forgets every entry for a server. The `:` in the prefix keeps `buser`
    /// from matching `buser_sentry`. Returns how many entries were dropped.
    /// Every server this cache holds an entry for.
    ///
    /// A server removed from the config leaves entries behind that nothing
    /// else reclaims: the tool cache has its own eviction path, but a
    /// classification outlives it whenever the backend was classified without
    /// a tool cache entry to match. `mcp reload` uses this to find them.
    pub fn known_servers(&self) -> Vec<String> {
        let mut servers: Vec<String> = self
            .entries
            .keys()
            // Keys are `server:tool:hash`, and a server name never contains a
            // colon, so the first segment is the whole name.
            .filter_map(|key| key.split(':').next())
            .map(str::to_string)
            .collect();
        servers.sort();
        servers.dedup();
        servers
    }

    pub fn forget_server(&mut self, server: &str) -> usize {
        let prefix = format!("{server}:");
        let before = self.entries.len();
        self.entries.retain(|k, _| !k.starts_with(&prefix));
        let dropped = before - self.entries.len();
        self.dirty = true;
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{Kind, Source, ToolClassification};

    fn sample() -> ToolClassification {
        ToolClassification {
            kind: Kind::Read,
            confidence: 0.8,
            source: Source::Classifier,
            reasons: vec!["name token 'get' → read".to_string()],
        }
    }

    #[test]
    fn key_changes_when_description_changes() {
        let k1 = cache_key("grafana", "get_thing", Some("returns data"), None);
        let k2 = cache_key("grafana", "get_thing", Some("returns NEW data"), None);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_stable_for_same_description() {
        let k1 = cache_key("grafana", "get_thing", Some("x"), None);
        let k2 = cache_key("grafana", "get_thing", Some("x"), None);
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_changes_when_annotations_change() {
        use crate::protocol::ToolAnnotations;
        let ann_ro = ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        };
        let ann_dh = ToolAnnotations {
            destructive_hint: Some(true),
            ..Default::default()
        };
        let k_none = cache_key("s", "t", Some("d"), None);
        let k_ro = cache_key("s", "t", Some("d"), Some(&ann_ro));
        let k_dh = cache_key("s", "t", Some("d"), Some(&ann_dh));
        assert_ne!(k_none, k_ro);
        assert_ne!(k_none, k_dh);
        assert_ne!(k_ro, k_dh);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip.json");
        // Serial access to avoid env var races with the other cache tests.
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_CLASSIFIER_CACHE", &path);

        let mut cache = ClassifierCache::load();
        cache.put("k1".to_string(), sample());
        cache.save();

        let reloaded = ClassifierCache::load();
        let got = reloaded.get("k1").unwrap();
        assert_eq!(got.kind, Kind::Read);
        assert_eq!(got.source, Source::Classifier);

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn corrupt_cache_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, "this is not json {{{").unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_CLASSIFIER_CACHE", &path);

        let cache = ClassifierCache::load();
        assert!(cache.get("anything").is_none());

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    #[test]
    fn missing_cache_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MCP_CLASSIFIER_CACHE", &path);
        let cache = ClassifierCache::load();
        assert!(cache.get("anything").is_none());
        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    fn cache_at(path: &std::path::Path) -> ClassifierCache {
        std::env::set_var("MCP_CLASSIFIER_CACHE", path);
        ClassifierCache::load()
    }

    #[test]
    fn known_servers_lists_each_server_once() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cache = cache_at(&dir.path().join("c.json"));
        cache.put("grafana:get_a:h1".to_string(), sample());
        cache.put("grafana:get_b:h2".to_string(), sample());
        cache.put("sentry:get_a:h3".to_string(), sample());

        assert_eq!(cache.known_servers(), vec!["grafana", "sentry"]);

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    /// `buser` and `buser_sentry` are distinct servers, and the colon in the
    /// key is what keeps them apart.
    #[test]
    fn known_servers_keeps_shared_prefixes_apart() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cache = cache_at(&dir.path().join("c.json"));
        cache.put("buser:a:h1".to_string(), sample());
        cache.put("buser_sentry:a:h2".to_string(), sample());

        assert_eq!(cache.known_servers(), vec!["buser", "buser_sentry"]);

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    #[test]
    fn known_servers_on_an_empty_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let cache = cache_at(&dir.path().join("c.json"));

        assert!(cache.known_servers().is_empty());

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    #[test]
    fn forget_server_removes_only_that_server() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cache = cache_at(&dir.path().join("c.json"));
        cache.put("grafana:get_a:h1".to_string(), sample());
        cache.put("grafana:get_b:h2".to_string(), sample());
        cache.put("sentry:get_a:h3".to_string(), sample());

        assert_eq!(cache.forget_server("grafana"), 2);
        assert!(cache.get("grafana:get_a:h1").is_none());
        assert!(cache.get("grafana:get_b:h2").is_none());
        assert!(cache.get("sentry:get_a:h3").is_some());

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    #[test]
    fn forget_server_does_not_touch_server_with_shared_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cache = cache_at(&dir.path().join("c.json"));
        cache.put("buser:get_a:h1".to_string(), sample());
        cache.put("buser_sentry:get_a:h2".to_string(), sample());

        assert_eq!(cache.forget_server("buser"), 1);
        assert!(cache.get("buser:get_a:h1").is_none());
        assert!(cache.get("buser_sentry:get_a:h2").is_some());

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    #[test]
    fn forget_server_persists_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cache = cache_at(&path);
        cache.put("a:t:h1".to_string(), sample());
        cache.put("b:t:h2".to_string(), sample());
        cache.save();

        assert_eq!(cache.forget_server("a"), 1);
        cache.save();

        let reloaded = ClassifierCache::load();
        assert!(reloaded.get("a:t:h1").is_none());
        assert!(reloaded.get("b:t:h2").is_some());

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }

    #[test]
    fn forget_unknown_server_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cache = cache_at(&dir.path().join("c.json"));
        cache.put("a:t:h1".to_string(), sample());

        assert_eq!(cache.forget_server("nope"), 0);
        assert!(cache.get("a:t:h1").is_some());

        std::env::remove_var("MCP_CLASSIFIER_CACHE");
    }
}
