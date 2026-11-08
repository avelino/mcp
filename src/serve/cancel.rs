//! Cancellation of in-flight requests.
//!
//! `notifications/cancelled` arrives as a separate message, after the request
//! it refers to is already running. Nothing connects the two unless the proxy
//! keeps a handle on what is in flight, which is what this module is.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::sync::watch;

use crate::protocol::{JsonRpcResponse, CANCELLED_NOTIFICATION};

/// A one-way flag a waiter can await.
#[derive(Clone)]
pub(crate) struct CancelToken {
    tx: Arc<watch::Sender<bool>>,
}

impl Default for CancelToken {
    fn default() -> Self {
        Self {
            tx: Arc::new(watch::channel(false).0),
        }
    }
}

impl CancelToken {
    pub(crate) fn cancel(&self) {
        // `send` is the wrong call here: it refuses to write the value at all
        // when no receiver is alive, and this token holds no receiver of its
        // own. `send_replace` always writes, and still wakes whoever is
        // waiting.
        self.tx.send_replace(true);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves once [`Self::cancel`] has been called, immediately if it
    /// already has.
    ///
    /// The receiver is taken before the flag is read, which is what closes the
    /// race: a `cancel` landing between the two is already visible to
    /// `changed`.
    pub(crate) async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();
        if *rx.borrow_and_update() {
            return;
        }
        // `Err` means the sender is gone. It lives in an `Arc` this token
        // holds, so that cannot happen while `&self` is alive.
        let _ = rx.changed().await;
    }
}

/// Identifies one in-flight request.
///
/// The subject is part of the key, not metadata alongside it. Request ids are
/// chosen by the client, so `1` from one caller collides with `1` from every
/// other caller: keyed on the id alone, any authenticated peer could cancel a
/// stranger's work by guessing a small integer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CancelKey {
    subject: String,
    request_id: String,
}

impl CancelKey {
    pub(crate) fn new(subject: &str, request_id: &Value) -> Self {
        Self {
            subject: subject.to_string(),
            // Serialized rather than coerced to a string: JSON-RPC allows a
            // string or a number id, and `"7"` and `7` are different requests.
            request_id: request_id.to_string(),
        }
    }
}

/// The in-flight requests this process could still be asked to cancel.
///
/// Guarded by a `std::sync::Mutex` and not tokio's: every section here is a
/// single map operation and none of them awaits, so there is nothing for an
/// async lock to yield across. It also lets [`CancelGuard::drop`] remove its
/// entry inline, which a `.await` could not.
#[derive(Default)]
pub(crate) struct CancelRegistry {
    inner: Mutex<HashMap<CancelKey, CancelToken>>,
}

impl CancelRegistry {
    /// Track a request until the returned guard is dropped.
    pub(crate) fn register(self: &Arc<Self>, key: CancelKey) -> CancelGuard {
        let token = CancelToken::default();
        self.lock().insert(key.clone(), token.clone());
        CancelGuard {
            registry: Arc::clone(self),
            key,
            token,
        }
    }

    /// Cancel a tracked request. `false` when nothing matches the key, which
    /// is the common case: a cancellation that lost the race with the response
    /// it was trying to stop.
    pub(crate) fn cancel(&self, key: &CancelKey) -> bool {
        match self.lock().get(key) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// Recovers from a poisoned lock instead of propagating the panic.
    ///
    /// The guarded value is a plain map of tokens with no invariant spanning
    /// two operations, so a panic elsewhere cannot have left it inconsistent.
    /// Refusing to cancel for the rest of the process's life is the worse
    /// outcome.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CancelKey, CancelToken>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Removes its request from the registry on drop, so a completed request
/// cannot be cancelled and the map cannot grow without bound.
pub(crate) struct CancelGuard {
    registry: Arc<CancelRegistry>,
    key: CancelKey,
    token: CancelToken,
}

impl CancelGuard {
    pub(crate) fn token(&self) -> &CancelToken {
        &self.token
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.key);
    }
}

/// Act on an inbound notification, reporting whether it was one we handle.
///
/// Takes the raw message because that is what both transports have at the
/// point a notification is recognized: stdio cannot even parse one into
/// `JsonRpcRequest` (its `id` is not optional), and the HTTP path decides on
/// the absence of `id` before any typed parse.
///
/// `subject` is the authenticated caller, and it scopes the lookup. A peer can
/// only cancel what it started.
pub(crate) fn handle_notification(registry: &CancelRegistry, msg: &Value, subject: &str) -> bool {
    if msg.get("method").and_then(Value::as_str) != Some(CANCELLED_NOTIFICATION) {
        return false;
    }

    // A cancellation that names nothing, or names a request this subject never
    // started, is still a cancellation we consumed. The miss is the ordinary
    // case: the response usually wins the race.
    if let Some(request_id) = msg.get("params").and_then(|params| params.get("requestId")) {
        registry.cancel(&CancelKey::new(subject, request_id));
    }
    true
}

/// Internal marker on the response of a cancelled request.
///
/// The spec forbids answering a cancelled request, so this never reaches a
/// peer: both transports recognize it and write nothing. It exists because
/// `dispatch_request` has to return *something* on the way out, and an
/// `Option` in that signature would push the distinction into every one of
/// its callers and tests.
const SUPPRESSED: i64 = -32001;

/// The response a cancelled request unwinds with.
pub(crate) fn suppressed_response(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::error(id, SUPPRESSED, "request cancelled by client")
}

/// Whether this response must be dropped instead of written to the peer.
pub(crate) fn is_suppressed(resp: &JsonRpcResponse) -> bool {
    resp.error.as_ref().is_some_and(|e| e.code == SUPPRESSED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn cancelling_a_tracked_request_fires_its_token() {
        let registry = Arc::new(CancelRegistry::default());
        let guard = registry.register(CancelKey::new("alice", &json!(7)));

        assert!(!guard.token().is_cancelled());
        assert!(registry.cancel(&CancelKey::new("alice", &json!(7))));

        assert!(guard.token().is_cancelled());
    }

    #[tokio::test]
    async fn another_identity_cannot_cancel_the_same_request_id() {
        let registry = Arc::new(CancelRegistry::default());
        let guard = registry.register(CancelKey::new("alice", &json!(7)));

        assert!(!registry.cancel(&CancelKey::new("bob", &json!(7))));

        assert!(
            !guard.token().is_cancelled(),
            "bob cancelled alice's in-flight request"
        );
    }

    #[tokio::test]
    async fn cancelling_an_unknown_request_reports_no_match() {
        let registry = Arc::new(CancelRegistry::default());

        assert!(!registry.cancel(&CancelKey::new("alice", &json!(7))));
    }

    #[tokio::test]
    async fn a_dropped_guard_stops_being_cancellable() {
        let registry = Arc::new(CancelRegistry::default());
        drop(registry.register(CancelKey::new("alice", &json!(7))));

        assert!(!registry.cancel(&CancelKey::new("alice", &json!(7))));
    }

    #[tokio::test]
    async fn string_and_number_ids_are_different_requests() {
        let registry = Arc::new(CancelRegistry::default());
        let guard = registry.register(CancelKey::new("alice", &json!(7)));

        assert!(!registry.cancel(&CancelKey::new("alice", &json!("7"))));

        assert!(!guard.token().is_cancelled());
    }

    #[tokio::test]
    async fn awaiting_a_token_resolves_once_it_is_cancelled() {
        let token = CancelToken::default();
        let waiting = token.clone();
        let handle = tokio::spawn(async move { waiting.cancelled().await });

        token.cancel();

        handle.await.expect("waiter should resolve after cancel");
    }

    #[tokio::test]
    async fn awaiting_an_already_cancelled_token_returns_immediately() {
        let token = CancelToken::default();
        token.cancel();

        token.cancelled().await;
    }

    fn cancellation_of(request_id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": request_id },
        })
    }

    #[tokio::test]
    async fn a_cancellation_notification_cancels_the_callers_request() {
        let registry = Arc::new(CancelRegistry::default());
        let guard = registry.register(CancelKey::new("alice", &json!(7)));

        assert!(handle_notification(
            &registry,
            &cancellation_of(json!(7)),
            "alice"
        ));

        assert!(guard.token().is_cancelled());
    }

    #[tokio::test]
    async fn a_cancellation_cannot_reach_another_identitys_request() {
        let registry = Arc::new(CancelRegistry::default());
        let guard = registry.register(CancelKey::new("alice", &json!(7)));

        handle_notification(&registry, &cancellation_of(json!(7)), "bob");

        assert!(
            !guard.token().is_cancelled(),
            "bob cancelled alice's in-flight request"
        );
    }

    /// Handled-but-unmatched still counts as handled: the notification was
    /// ours to act on, and losing the race with the response is the normal
    /// case, not a protocol error for the caller to see.
    #[tokio::test]
    async fn a_cancellation_for_an_unknown_request_is_still_handled() {
        let registry = Arc::new(CancelRegistry::default());

        assert!(handle_notification(
            &registry,
            &cancellation_of(json!(7)),
            "alice"
        ));
    }

    #[tokio::test]
    async fn a_cancellation_without_a_request_id_is_handled_without_panicking() {
        let registry = Arc::new(CancelRegistry::default());
        let msg = json!({"jsonrpc": "2.0", "method": "notifications/cancelled"});

        assert!(handle_notification(&registry, &msg, "alice"));
    }

    #[tokio::test]
    async fn an_unrelated_notification_is_not_handled() {
        let registry = Arc::new(CancelRegistry::default());
        let msg = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});

        assert!(!handle_notification(&registry, &msg, "alice"));
    }

    /// A request id is routing data, and a client that sends a float or an
    /// object gets the same miss as any other unmatched id.
    #[tokio::test]
    async fn a_non_scalar_request_id_does_not_match_a_tracked_request() {
        let registry = Arc::new(CancelRegistry::default());
        let guard = registry.register(CancelKey::new("alice", &json!(7)));

        handle_notification(&registry, &cancellation_of(json!({"n": 7})), "alice");

        assert!(!guard.token().is_cancelled());
    }

    #[tokio::test]
    async fn a_suppressed_response_is_recognized() {
        assert!(is_suppressed(&suppressed_response(json!(7))));
    }

    #[tokio::test]
    async fn an_ordinary_response_is_not_suppressed() {
        assert!(!is_suppressed(&JsonRpcResponse::success(
            json!(7),
            json!({"content": []})
        )));
    }

    /// A real backend failure must still reach the caller. Only the one
    /// sentinel code is dropped.
    #[tokio::test]
    async fn another_error_code_is_not_suppressed() {
        assert!(!is_suppressed(&JsonRpcResponse::error(
            json!(7),
            crate::protocol::error_codes::INTERNAL_ERROR,
            "backend exploded"
        )));
    }
}
