//! Test-only helpers shared across the oauth_as submodules.
//!
//! Centralizes the env-var lock and the `save_disabled` guard so
//! tests that touch process-global state serialize correctly. Without
//! a shared lock, `cargo test` runs the suite in parallel and tests
//! that mutate `MCP_AUTH_SERVER_CONFIG` race the file-roundtrip test
//! in `store.rs` — green locally on a fast machine, red in CI.

use std::sync::Mutex;

const STATE_INLINE_ENV: &str = "MCP_AUTH_SERVER_CONFIG";

/// Process-wide lock for any test in `oauth_as` that mutates
/// `MCP_AUTH_SERVER_CONFIG` or `MCP_AUTH_SERVER_PATH`. Hold it for
/// the entire body of the test.
pub(super) fn env_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

/// Guard that points the AS state to an in-memory inline blob, so
/// `super::store::save` becomes a no-op (writes go to the cache,
/// never to disk) for the lifetime of the guard. Restores the
/// previous env value on Drop.
///
/// Acquires `env_lock()` to serialize against every other test in
/// the module that touches the same env var. The lock is released
/// when the guard drops along with the env restoration.
pub(super) struct InlineSaveGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev_inline: Option<String>,
}

impl InlineSaveGuard {
    pub(super) fn acquire() -> Self {
        let lock = match env_lock().lock() {
            Ok(g) => g,
            // A previous test panicked while holding the lock — recover
            // its state and keep going.
            Err(poisoned) => poisoned.into_inner(),
        };
        let prev_inline = std::env::var(STATE_INLINE_ENV).ok();
        std::env::set_var(STATE_INLINE_ENV, r#"{"clients":{},"refresh_tokens":{}}"#);
        Self {
            _lock: lock,
            prev_inline,
        }
    }
}

impl Drop for InlineSaveGuard {
    fn drop(&mut self) {
        match &self.prev_inline {
            Some(v) => std::env::set_var(STATE_INLINE_ENV, v),
            None => std::env::remove_var(STATE_INLINE_ENV),
        }
    }
}
