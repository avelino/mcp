//! Test-only helpers shared across the oauth_as submodules.
//!
//! Centralizes the env-var lock and the `save_disabled` guard so
//! tests that touch process-global state serialize correctly. Without
//! a shared lock, `cargo test` runs the suite in parallel and tests
//! that mutate `MCP_AUTH_SERVER_CONFIG` race the file-roundtrip test
//! in `store.rs` — green locally on a fast machine, red in CI.
//!
//! It also hosts the fake identity-provider server and the throwaway
//! signing keys that `jwks.rs` and `assertion.rs` both need, so the two
//! suites agree on what a well-formed issuer looks like.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey};

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

// ---- identity-assertion fixtures ---------------------------------------

/// P-256 private key in PKCS#8 DER (base64). Generated for this test
/// suite only — it signs nothing outside `cargo test`.
pub(super) const TEST_EC_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy/Nf95vXPfNwVuMG7v26SEO2aBYKBJVG8MvJovHT55OhRANCAASTbaUkNGqrBFUq1M6W4ZJ/psR0QvJJUDm3aojdh2MJYdkosobPunqt4lEYFKLjqvZz/rq5v+ONZ5gWH2hm3mDw";

/// A second, unrelated P-256 key. Used to prove that a signature made
/// outside the published key set is refused.
pub(super) const OTHER_EC_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgK2F9ZqhDX0q2zLnvbjqCs4j9LJToHTgFAbugzzuRTNehRANCAATe80D7Xiv0D0DVgf2X+n4pHTHR9c+NHZbSd4tDKHcOQcKLnv3mBLWg6la8UpEGimzVMMRo2AJ1gc2ZwWlth1Ts";

/// A P-384 key. Its curve is outside the set this AS accepts, so it only
/// ever appears in tests that prove such a key is turned away.
pub(super) const TEST_EC_P384_PKCS8_B64: &str = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDHbTRl7lh3ChKWZ5J9c1QcSdCezloAqkAw6cdHxo953jX9tSabB5PRuohnHuQ8GqahZANiAAQpCmRe8AMbVjy0dtKkgil8KAe/+OrBRljYRalN1lr/bnREqPjJ9m94kpUrEFkSHpvmZxaTmPlgNRPYb5b2fULaE2RW11Zm4A1TxqHn7jj17iOG/0SSB4ccEfWO3+G/FJc=";

pub(super) fn ec_encoding_key(pkcs8_b64: &str) -> EncodingKey {
    EncodingKey::from_ec_der(&STANDARD.decode(pkcs8_b64).unwrap())
}

/// The public half of `pkcs8_b64` as a JWKS entry, tagged `ES256`.
pub(super) fn ec_public_jwk(pkcs8_b64: &str, kid: &str) -> serde_json::Value {
    ec_jwk(pkcs8_b64, kid, Algorithm::ES256, true)
}

/// Same, for a key set that leaves `alg` out — optional per RFC 7517, and
/// plenty of real key sets omit it. `curve_alg` only says how to read the
/// key's curve; it does not reach the published entry.
pub(super) fn ec_public_jwk_without_alg(
    pkcs8_b64: &str,
    kid: &str,
    curve_alg: Algorithm,
) -> serde_json::Value {
    ec_jwk(pkcs8_b64, kid, curve_alg, false)
}

fn ec_jwk(pkcs8_b64: &str, kid: &str, alg: Algorithm, publish_alg: bool) -> serde_json::Value {
    let mut jwk = Jwk::from_encoding_key(&ec_encoding_key(pkcs8_b64), alg).unwrap();
    jwk.common.key_id = Some(kid.to_string());
    if !publish_alg {
        jwk.common.key_algorithm = None;
    }
    serde_json::to_value(jwk).unwrap()
}

/// A fake OpenID provider: `/.well-known/openid-configuration` plus the
/// `jwks_uri` it points at, each counting the requests it served so a
/// test can assert that a fetch did — or did not — happen.
pub(super) struct FakeIssuer {
    pub(super) base: String,
    discovery_hits: Arc<AtomicUsize>,
    jwks_hits: Arc<AtomicUsize>,
    jwks_body: Arc<Mutex<String>>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FakeIssuer {
    pub(super) fn discovery_hits(&self) -> usize {
        self.discovery_hits.load(Ordering::SeqCst)
    }

    pub(super) fn jwks_hits(&self) -> usize {
        self.jwks_hits.load(Ordering::SeqCst)
    }

    /// What the key-set route serves from the next request on — an issuer
    /// that rotated its keys, or one whose CDN started answering with
    /// something else.
    pub(super) fn set_jwks(&self, body: String) {
        *self
            .jwks_body
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = body;
    }
}

/// Serve a discovery document naming `claimed_issuer` (its own base URL
/// when `None`) and a key set holding `keys`.
pub(super) async fn start_fake_issuer(
    claimed_issuer: Option<&str>,
    keys: Vec<serde_json::Value>,
) -> FakeIssuer {
    start_fake_issuer_with_discovery(
        move |base| {
            serde_json::json!({
                "issuer": claimed_issuer.unwrap_or(base),
                "jwks_uri": format!("{base}/jwks"),
            })
            .to_string()
        },
        serde_json::json!({ "keys": keys }).to_string(),
    )
    .await
}

/// Same, but the discovery document is built by the caller — for the
/// cases where it is deliberately malformed.
pub(super) async fn start_fake_issuer_with_discovery(
    discovery: impl FnOnce(&str) -> String,
    jwks_body: String,
) -> FakeIssuer {
    start_fake_issuer_inner(discovery, jwks_body, false).await
}

/// Same key set, named through a path that answers with a redirect to it
/// rather than serving it.
///
/// Both hops are plain HTTP on loopback, which is the shape that matters:
/// a client willing to follow a hop that is not `https` is a client an
/// on-path attacker can walk off TLS, and the keys at the end of that walk
/// are the ones every assertion is verified against.
pub(super) async fn start_fake_issuer_redirecting_to_jwks(
    keys: Vec<serde_json::Value>,
) -> FakeIssuer {
    start_fake_issuer_with_discovery(
        |base| {
            serde_json::json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks-redirect"),
            })
            .to_string()
        },
        serde_json::json!({ "keys": keys }).to_string(),
    )
    .await
}

/// Serves the key set in pieces with **no `Content-Length`**, which is how
/// a `Transfer-Encoding: chunked` response arrives.
///
/// The size of such a body is only knowable by reading it, so this is the
/// only shape that exercises a byte cap's read loop: a declared length can
/// be refused before a byte of the body is touched.
pub(super) async fn start_fake_issuer_with_chunked_jwks(jwks_body: String) -> FakeIssuer {
    start_fake_issuer_inner(
        |base| {
            serde_json::json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") }).to_string()
        },
        jwks_body,
        true,
    )
    .await
}

async fn start_fake_issuer_inner(
    discovery: impl FnOnce(&str) -> String,
    jwks_body: String,
    chunked: bool,
) -> FakeIssuer {
    use axum::{extract::State, response::IntoResponse, routing::get, Router};

    #[derive(Clone)]
    struct S {
        discovery: String,
        jwks: Arc<Mutex<String>>,
        chunked: bool,
        discovery_hits: Arc<AtomicUsize>,
        jwks_hits: Arc<AtomicUsize>,
    }

    async fn discovery_handler(State(s): State<S>) -> impl IntoResponse {
        s.discovery_hits.fetch_add(1, Ordering::SeqCst);
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            s.discovery.clone(),
        )
    }

    async fn jwks_handler(State(s): State<S>) -> axum::response::Response {
        s.jwks_hits.fetch_add(1, Ordering::SeqCst);
        let body = s
            .jwks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let body = if s.chunked {
            // A stream has no size for hyper to declare, so the response
            // goes out chunked and the reader learns the length only by
            // reading. 8 KiB pieces so a body at the cap takes several.
            let pieces: Vec<Result<Vec<u8>, std::io::Error>> = body
                .into_bytes()
                .chunks(8 * 1024)
                .map(|piece| Ok(piece.to_vec()))
                .collect();
            axum::body::Body::from_stream(tokio_stream::iter(pieces))
        } else {
            axum::body::Body::from(body)
        };
        axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .expect("a content-type header and a body is a valid response")
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");

    let discovery_hits = Arc::new(AtomicUsize::new(0));
    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let jwks_body = Arc::new(Mutex::new(jwks_body));
    let state = S {
        discovery: discovery(&base),
        jwks: jwks_body.clone(),
        chunked,
        discovery_hits: discovery_hits.clone(),
        jwks_hits: jwks_hits.clone(),
    };

    /// Moves the URL and nothing else. The `Location` is relative, so it
    /// resolves against whatever origin served it — here, plain HTTP.
    /// `jwks_hits` stays on `/jwks`, so it counts the hop being followed,
    /// not the hop being offered.
    async fn redirect_handler() -> impl IntoResponse {
        axum::response::Redirect::temporary("/jwks")
    }

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery_handler))
        .route("/jwks", get(jwks_handler))
        .route("/jwks-redirect", get(redirect_handler))
        .with_state(state);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    FakeIssuer {
        base,
        discovery_hits,
        jwks_hits,
        jwks_body,
        _shutdown: tx,
    }
}
