//! Public signing keys of the identity providers whose assertions this
//! AS exchanges for access tokens.
//!
//! Keys are only ever taken from the issuer's own OpenID discovery
//! document and the `jwks_uri` it names. The `jwk`, `jku` and `x5u`
//! headers an assertion may carry are deliberately never read: a token
//! that brings its own key is a token that verifies itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, KeyAlgorithm, KeyOperations,
    PublicKeyUse,
};
use jsonwebtoken::{get_current_timestamp, Algorithm, DecodingKey};
use serde::Deserialize;

/// A slow issuer must not hold a `/token` request open: every exchange
/// that misses the cache waits on these two fetches.
///
/// 2s, not 5, because of what is waiting on the other side: Claude's
/// connector documentation gives the discovery, registration and token
/// endpoints 10 seconds each before it reports a connection failure, and a
/// cold-cache exchange spends *both* of these fetches inside one `/token`.
/// At 5s the two alone are the whole budget, before the TLS handshakes,
/// the signature verification and the handler itself — so a cold cache or
/// a merely slow issuer becomes a failure Claude reports and this side
/// never logs.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Compile-time guard on the number above: the two sequential fetches have
/// to leave room inside Claude's 10s for everything else `/token` does.
const _: () = assert!(FETCH_TIMEOUT.as_secs() * 2 < 10);

/// How many redirects a key fetch may be sent on. Enough for the
/// apex-to-CDN shape real issuers use, and well short of `reqwest`'s
/// default ten — every hop is another host answering inside the single
/// [`FETCH_TIMEOUT`] the whole fetch gets.
///
/// Counted the way `reqwest::redirect::Policy::limited` counts: the first
/// entry of `previous()` is the original URL, not a redirect.
const MAX_REDIRECTS: usize = 3;

/// Floor on the cached lifetime, so an issuer advertising `max-age=0`
/// cannot turn every token exchange into two round-trips.
const MIN_KEY_TTL_SECONDS: u64 = 60;

/// How long the next refresh of an issuer waits when that issuer's last
/// one failed.
///
/// A failed refresh arms no cache window — see `refresh` — so a broken
/// issuer is the one case the window does not pace at all: every miss
/// pays for the attempt again, as fast as the misses arrive. This paces
/// them without taking the issuer out of service, which is the trade the
/// doc comment on [`JwksCache::decoding_key`] argues for: an issuer that
/// fixes its document is serving again one short delay later, not one
/// [`MIN_KEY_TTL_SECONDS`] later.
const FAILED_REFRESH_BACKOFF: Duration = Duration::from_millis(200);

/// Compile-time guard on the number above: pacing a broken issuer has to
/// stay an order of magnitude cheaper than waiting out the cache window,
/// or "keep it retryable" is a policy in name only.
const _: () =
    assert!(FAILED_REFRESH_BACKOFF.as_millis() * 10 < MIN_KEY_TTL_SECONDS as u128 * 1_000);

/// Ceiling on the cached lifetime: it bounds how long a key stays usable
/// here after the issuer retires it.
const MAX_KEY_TTL_SECONDS: u64 = 3600;

/// Used when the key set ships no `Cache-Control: max-age`.
const DEFAULT_KEY_TTL_SECONDS: u64 = 300;

/// Ceiling on the entries one key set may hold, so a (compromised) issuer
/// cannot grow this cache without limit. A set above it is refused whole
/// rather than truncated — see `refresh`.
const MAX_KEYS_PER_SET: usize = 50;

/// Ceiling on a discovery or key-set body, enforced while it is still
/// being read. Without it the only bound is `FETCH_TIMEOUT` seconds of
/// the issuer's bandwidth, per exchange in flight, and the body is held
/// whole in memory before anything looks at it. A key set of
/// [`MAX_KEYS_PER_SET`] RSA keys is a few tens of KiB, so a real document
/// is nowhere near this.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// The subset of OpenID Discovery this AS reads. `authorization_endpoint`
/// and `token_endpoint` are absent on purpose — Claude's discovery
/// document does not carry them, and nothing here needs them.
#[derive(Deserialize)]
struct OpenIdDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// A key set read one entry at a time. `jsonwebtoken::jwk::JwkSet` is
/// all-or-nothing, and its types model a fixed set of curves and field
/// shapes, so a single entry it cannot represent would otherwise drop
/// every key alongside it.
#[derive(Deserialize)]
struct RawJwkSet {
    #[serde(default)]
    keys: Vec<serde_json::Value>,
}

struct CachedKey {
    key: DecodingKey,
    alg: Algorithm,
    expires_at_unix: u64,
}

/// Verification keys per `(issuer, kid)`, fetched on demand.
pub struct JwksCache {
    http: reqwest::Client,
    keys: RwLock<HashMap<(String, String), CachedKey>>,
    /// When each issuer's key set was last read successfully. Bounded by the
    /// configured `trustedIssuers`, because that is where the issuer string
    /// comes from — never off an assertion's own claims.
    last_refresh: RwLock<HashMap<String, u64>>,
    /// One gate per issuer: whoever holds it is the only task refreshing
    /// that issuer, so concurrent misses make one pair of fetches between
    /// them rather than one each. It carries the [`Instant`] of that
    /// issuer's last failed refresh, which is what paces the retries a
    /// failure deliberately leaves available.
    ///
    /// Bounded the same way `last_refresh` is, and keyed the same way.
    gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<Instant>>>>>,
}

impl JwksCache {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            keys: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
        }
    }

    /// The key `issuer` published under `kid`, with the algorithm its own
    /// JWKS entry declares.
    ///
    /// A `kid` that is not cached earns a refetch — key sets do gain keys.
    /// What bounds the refetches is the window `refresh` arms on success:
    /// for [`MIN_KEY_TTL_SECONDS`] after a key set was read, a `kid` that
    /// is not in it is refused from the cache without touching the network.
    /// That is what keeps a stream of invented `kid`s from costing the
    /// issuer two GETs each on a path that needs no credential.
    ///
    /// The window only closes once a refresh has *succeeded*, so two
    /// things it cannot pace are coordinated here instead:
    ///
    /// - Concurrent misses. One gate per issuer, taken past the cache
    ///   check, so N requests naming one unseen `kid` make one pair of
    ///   fetches between them instead of N. The exposure is why: this runs
    ///   at assertion check 2, ahead of the signature check at 3, so a
    ///   caller reaches it with no credential at all, and an issuer URL is
    ///   public. [`FETCH_TIMEOUT`] bounds what one fetch costs and nothing
    ///   else bounded how many ran at once.
    /// - A *failed* refresh, which deliberately arms nothing: while an
    ///   issuer serves something this AS cannot use — an empty set, a set
    ///   with no usable key in it, an oversized body, more than
    ///   [`MAX_KEYS_PER_SET`] keys — the window never opens and every miss
    ///   pays for the attempt again. Keeping a broken issuer retryable is
    ///   still worth more than the fetches, so the next attempt is paced by
    ///   [`FAILED_REFRESH_BACKOFF`] rather than refused: an issuer that
    ///   fixes its document is serving again one short delay later, not one
    ///   [`MIN_KEY_TTL_SECONDS`] later.
    pub async fn decoding_key(&self, issuer: &str, kid: &str) -> Result<(DecodingKey, Algorithm)> {
        if let Some(hit) = self.cached(issuer, kid) {
            return Ok(hit);
        }
        // Taken after the hit check, not before, so a cached key is never
        // made to queue behind someone else's refresh.
        let gate = self.gate(issuer);
        let mut last_failure = gate.lock().await;
        // Both checks again: whoever held the gate may have just answered
        // this very question, and waiting on them is the point.
        if let Some(hit) = self.cached(issuer, kid) {
            return Ok(hit);
        }
        if self.refreshed_recently(issuer) {
            bail!("issuer published no usable key for this kid");
        }
        if let Some(remaining) =
            last_failure.and_then(|at| FAILED_REFRESH_BACKOFF.checked_sub(at.elapsed()))
        {
            tokio::time::sleep(remaining).await;
        }
        let refreshed = self.refresh(issuer).await;
        // A refresh that succeeded arms the window above, so only a failure
        // needs pacing of its own.
        *last_failure = refreshed.is_err().then(Instant::now);
        refreshed?;
        self.cached(issuer, kid)
            .ok_or_else(|| anyhow!("issuer published no usable key for this kid"))
    }

    /// The gate for `issuer`, created on first use.
    fn gate(&self, issuer: &str) -> Arc<tokio::sync::Mutex<Option<Instant>>> {
        self.gates
            .lock()
            .unwrap()
            .entry(issuer.to_string())
            .or_default()
            .clone()
    }

    fn cached(&self, issuer: &str, kid: &str) -> Option<(DecodingKey, Algorithm)> {
        let guard = self.keys.read().unwrap();
        let entry = guard.get(&(issuer.to_string(), kid.to_string()))?;
        (entry.expires_at_unix > get_current_timestamp()).then(|| (entry.key.clone(), entry.alg))
    }

    /// Whether `issuer`'s key set was read inside the window. The guard is
    /// taken and dropped here rather than around the caller's `.await`: a
    /// `std::sync` guard held across one makes the future non-`Send`.
    fn refreshed_recently(&self, issuer: &str) -> bool {
        let guard = self.last_refresh.read().unwrap();
        guard
            .get(issuer)
            .is_some_and(|at| at + MIN_KEY_TTL_SECONDS > get_current_timestamp())
    }

    /// Re-read `issuer`'s key set and replace everything cached for it, so
    /// a retired key stops being usable as soon as it leaves the document.
    async fn refresh(&self, issuer: &str) -> Result<()> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let (body, _) = self.fetch(&discovery_url).await?;
        let discovery: OpenIdDiscovery = serde_json::from_str(&body)
            .context("issuer discovery document is not a usable OpenID configuration")?;

        // The document must name the very issuer we asked about. Without
        // this, a host serving someone else's discovery document would
        // decide which keys sign that issuer's users in.
        if discovery.issuer != issuer {
            bail!("issuer discovery document names a different issuer");
        }

        let (body, max_age) = self.fetch(&discovery.jwks_uri).await?;
        let set: RawJwkSet = serde_json::from_str(&body).context("issuer key set is not a JWKS")?;
        // `keys` carries `#[serde(default)]`, so a CDN error page or a
        // maintenance response is a `200` that parses as a valid, empty set.
        // Taken at face value it empties the cache for this issuer, turning
        // a transient answer into a dead grant.
        //
        // The guard on *usable* keys further down would refuse this one too.
        // It is called out here because the distinction is what the operator
        // needs: an empty document is an issuer or CDN problem, a full one
        // with nothing usable is an algorithm mismatch.
        if set.keys.is_empty() {
            bail!("issuer key set published no keys");
        }
        // Checked before anything is parsed per entry. `take` would have
        // bounded the cache while leaving the parse unbounded, and it drops
        // whichever key the exchange actually needed — reported as an
        // unknown `kid`, which is the wrong thing to go debugging.
        if set.keys.len() > MAX_KEYS_PER_SET {
            bail!("issuer key set holds more than {} keys", MAX_KEYS_PER_SET);
        }
        // Parsed before the cache is touched, not while it is being
        // rewritten, so a set that yields nothing usable cannot empty it.
        // Each entry still stands on its own: one key the `jwk` types
        // cannot model — an unlisted curve, a `key_ops` published as a
        // string — must not take down the key the grant actually needs.
        let usable: Vec<(String, DecodingKey, Algorithm)> = set
            .keys
            .into_iter()
            .filter_map(|raw| serde_json::from_value::<Jwk>(raw).ok())
            .filter_map(|jwk| usable_key(&jwk))
            .collect();
        // The same refusal as an empty set, for the same reason and with a
        // likelier trigger: a CDN error body parses as one entry that is
        // not a JWK, and a rotation onto a curve this AS does not accept
        // parses as several. Neither is an instruction to forget the keys
        // that still work. `Err` also leaves the window below unarmed, so
        // the next exchange retries rather than waiting it out.
        if usable.is_empty() {
            bail!("issuer key set published no usable key");
        }

        let expires_at_unix = get_current_timestamp()
            + max_age
                .unwrap_or(DEFAULT_KEY_TTL_SECONDS)
                .clamp(MIN_KEY_TTL_SECONDS, MAX_KEY_TTL_SECONDS);

        let mut guard = self.keys.write().unwrap();
        guard.retain(|(cached_issuer, _), _| cached_issuer != issuer);
        for (kid, key, alg) in usable {
            guard.insert(
                (issuer.to_string(), kid),
                CachedKey {
                    key,
                    alg,
                    expires_at_unix,
                },
            );
        }
        // Released before the next lock is taken, so the two are never held
        // together and there is no order for a future caller to get wrong.
        drop(guard);
        // Recorded only on the way out, so a refusal above — an unreachable
        // issuer, a document naming someone else, an empty set — never opens
        // the window. A failed refresh has to stay retryable.
        self.last_refresh
            .write()
            .unwrap()
            .insert(issuer.to_string(), get_current_timestamp());
        Ok(())
    }

    /// Returns the body and the `max-age` the response asked for.
    ///
    /// Read in chunks against [`MAX_BODY_BYTES`] rather than with `text()`:
    /// the body arrives from a host this process does not control, and
    /// buffering all of it before measuring it is the whole problem.
    async fn fetch(&self, url: &str) -> Result<(String, Option<u64>)> {
        // Before the request, not after: a refusal that has already made
        // the call has already handed an on-path attacker the exchange.
        // Here rather than at the one call site that needs it, so the
        // discovery fetch is covered by the same rule.
        require_https(url)?;
        let mut response = self
            .http
            .get(url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .context("could not reach the issuer")?;
        if !response.status().is_success() {
            bail!("issuer answered {}", response.status());
        }
        let max_age = max_age_seconds(response.headers());
        // The declared length first, because a body that announces its size
        // costs nothing to refuse before any of it is read. The loop then
        // covers the bodies that declare no length at all — chunked, or
        // HTTP/2 without one — where the size is knowable only by reading.
        //
        // A host that *understates* its length needs no cover here: the
        // decoder stops at the figure it was given, so it cannot deliver
        // more than it declared.
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BODY_BYTES as u64)
        {
            bail!("issuer response is larger than {} bytes", MAX_BODY_BYTES);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("could not read the issuer's response")?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                bail!("issuer response is larger than {} bytes", MAX_BODY_BYTES);
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).context("issuer response is not UTF-8")?;
        Ok((body, max_age))
    }
}

/// The HTTP client this cache is meant to run with.
///
/// [`require_https`] refuses a URL that is not `https`, but it only sees
/// the URL this process asks for. A redirect is chosen by the host on the
/// other end, and `reqwest`'s default client follows up to ten of them
/// without caring that a hop leaves TLS — so without a policy, answering
/// the key-set URL with a `307` does exactly what the check refuses to do
/// directly. Refusing the hop means the request is never issued at all.
///
/// Redirects between `https` URLs stay allowed, capped: an issuer moving
/// its key set behind a CDN is ordinary, a chain without end is not.
pub(super) fn https_only_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > MAX_REDIRECTS {
                attempt.error("issuer redirected a key fetch too many times")
            } else if attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.error("issuer redirected a key fetch off https")
            }
        }))
        .build()
        // Only a TLS backend that will not initialize gets here, and this
        // AS cannot verify an assertion without one. Failing at boot beats
        // falling back to a client with no redirect policy, which would
        // drop the protection above silently.
        .expect("a rustls backend is required to fetch issuer signing keys")
}

/// Keys, and the document that names them, may only be fetched over TLS.
///
/// `config.rs` already refuses a trusted issuer that is not `https`, which
/// covers the discovery URL built from it. `jwks_uri` is different: it
/// comes out of that document, so nothing has vouched for it yet.
fn require_https(url: &str) -> Result<()> {
    check_scheme(url, LOOPBACK_HTTP_ALLOWED)
}

/// Whether a plain-HTTP loopback URL may be fetched.
///
/// `true` only in a test build: the suite's fake issuer is an HTTP
/// listener on `127.0.0.1`, so without the allowance no test could reach
/// one. A release build carries `false` and has no way to turn it on.
#[cfg(test)]
const LOOPBACK_HTTP_ALLOWED: bool = true;
#[cfg(not(test))]
const LOOPBACK_HTTP_ALLOWED: bool = false;

/// The rule itself, with the allowance passed in rather than read from
/// the `cfg` above — which is what lets a test assert the behaviour of a
/// build where it is off, and the `cfg` otherwise makes unreachable.
fn check_scheme(url: &str, allow_loopback_http: bool) -> Result<()> {
    let parsed = url::Url::parse(url).context("issuer named a URL that cannot be parsed")?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    // A loopback *IP literal*, never a name: settling whether a name is
    // loopback needs DNS, and a scheme check that waits on a resolver is
    // a scheme check an attacker gets to answer.
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if allow_loopback_http && parsed.scheme() == "http" && loopback {
        return Ok(());
    }
    bail!(
        "issuer key material must be fetched over https, not {}",
        parsed.scheme()
    );
}

/// A JWKS entry this AS is willing to verify an assertion with.
///
/// The accepted set is exactly `{ES256, RS256}`. `alg` is optional in
/// RFC 7517 and real key sets do leave it out, so a key of an accepted
/// type names its own algorithm when it is absent — refusing those would
/// be an outage, not caution.
///
/// `None` for everything else: a key with no `kid` (nothing could select
/// it), one the key set does not publish for verifying signatures, an
/// `alg` outside the two accepted, a curve other than P-256, and any key
/// whose material does not match its `alg` — most importantly a symmetric
/// one, which could forge assertions rather than merely check them.
fn usable_key(jwk: &Jwk) -> Option<(String, DecodingKey, Algorithm)> {
    let kid = jwk.common.key_id.clone()?;
    if !verifies_signatures(&jwk.common) {
        return None;
    }
    let alg = match (jwk.common.key_algorithm, &jwk.algorithm) {
        (Some(KeyAlgorithm::ES256) | None, AlgorithmParameters::EllipticCurve(ec))
            if ec.curve == EllipticCurve::P256 =>
        {
            Algorithm::ES256
        }
        (Some(KeyAlgorithm::RS256) | None, AlgorithmParameters::RSA(_)) => Algorithm::RS256,
        _ => return None,
    };
    Some((kid, DecodingKey::from_jwk(jwk).ok()?, alg))
}

/// Whether the key set says this key may be used to verify a signature.
///
/// RFC 7517 §4.2 and §4.3. `use` holds a single value, so anything other
/// than `sig` is a key published for a different job — `enc` above all,
/// whose private half an issuer may rotate on another schedule and hold
/// to other rules than its signing material. `key_ops` enumerates the
/// operations instead, so it has to list `verify`.
///
/// Neither is required and real key sets omit both, so a key that
/// declares nothing stays usable: making the parameters mandatory would
/// be an outage for issuers doing nothing wrong. The rule only bites
/// where the issuer did say, and said something else.
fn verifies_signatures(common: &CommonParameters) -> bool {
    if common
        .public_key_use
        .as_ref()
        .is_some_and(|declared| *declared != PublicKeyUse::Signature)
    {
        return false;
    }
    common
        .key_operations
        .as_ref()
        .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
}

fn max_age_seconds(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::CACHE_CONTROL)?
        .to_str()
        .ok()?
        .to_ascii_lowercase()
        .split(',')
        .find_map(|directive| directive.trim().strip_prefix("max-age=")?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{
        ec_public_jwk, ec_public_jwk_without_alg, start_fake_issuer,
        start_fake_issuer_redirecting_to_jwks, start_fake_issuer_with_chunked_jwks,
        start_fake_issuer_with_discovery, TEST_EC_P384_PKCS8_B64, TEST_EC_PKCS8_B64,
    };
    use super::*;

    fn cache() -> JwksCache {
        JwksCache::new(reqwest::Client::new())
    }

    #[tokio::test]
    async fn test_discovery_issuer_mismatch_is_rejected() {
        // The document is served by 127.0.0.1 but claims to belong to
        // `https://honest.example`. Trusting it would let whoever controls
        // that host publish the keys we verify assertions with, so the
        // `jwks_uri` it offers must never even be fetched.
        let fake = start_fake_issuer(
            Some("https://honest.example"),
            vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")],
        )
        .await;

        assert!(cache().decoding_key(&fake.base, "k1").await.is_err());
        assert_eq!(fake.jwks_hits(), 0);
    }

    #[tokio::test]
    async fn test_discovery_without_an_issuer_is_rejected() {
        // Nothing to compare `iss` against means the check cannot be made,
        // and a check that cannot be made is a refusal.
        let fake = start_fake_issuer_with_discovery(
            |base| serde_json::json!({ "jwks_uri": format!("{base}/jwks") }).to_string(),
            serde_json::json!({ "keys": [] }).to_string(),
        )
        .await;

        assert!(cache().decoding_key(&fake.base, "k1").await.is_err());
        assert_eq!(fake.jwks_hits(), 0);
    }

    #[tokio::test]
    async fn test_a_plain_http_jwks_uri_is_refused() {
        // `jwks_uri` comes out of the discovery document, and nothing
        // downstream re-checks its scheme. Fetched over plain HTTP, the
        // keys that verify every assertion for this issuer are whatever
        // an on-path attacker decides to serve — that is the signature
        // check itself, not a layer around it.
        //
        // The host is TEST-NET-1 (RFC 5737), so it is both unroutable and
        // outside the loopback allowance the suite's fake issuer uses.
        let fake = start_fake_issuer_with_discovery(
            |base| {
                serde_json::json!({ "issuer": base, "jwks_uri": "http://192.0.2.1/jwks" })
                    .to_string()
            },
            serde_json::json!({ "keys": [] }).to_string(),
        )
        .await;

        let err = cache()
            .decoding_key(&fake.base, "k1")
            .await
            .expect_err("a key set offered over plain http must not be fetched");
        // The message, because `is_err` alone proves nothing here: an
        // unroutable address also fails by timing out, which is the
        // unfixed behaviour — the fetch went out and merely did not
        // arrive. Refused on the scheme means it was never attempted.
        assert!(
            format!("{err:#}").contains("https"),
            "refused for the wrong reason: {err:#}"
        );
        // And it got far enough to read the document that named it.
        assert_eq!(fake.discovery_hits(), 1);
    }

    #[test]
    fn test_the_loopback_allowance_does_not_reach_a_release_build() {
        // Every other test in this file talks to the fake issuer over
        // plain HTTP on loopback, so all of them run with the allowance
        // on and none of them can show what `mcp serve` does. This calls
        // the rule with the constant a release build carries.
        assert!(check_scheme("http://127.0.0.1:8080/jwks", false).is_err());
        assert!(check_scheme("http://[::1]:8080/jwks", false).is_err());

        // And where it does apply it stays narrow: a name is not an
        // address, so it never counts as loopback.
        assert!(check_scheme("http://localhost:8080/jwks", true).is_err());
        assert!(check_scheme("http://127.0.0.1:8080/jwks", true).is_ok());

        // https is what passes, with the allowance either way. A scheme
        // that is neither never does.
        assert!(check_scheme("https://idp.example.com/jwks", false).is_ok());
        assert!(check_scheme("file:///etc/passwd", true).is_err());
    }

    #[tokio::test]
    async fn test_a_redirect_off_https_is_not_followed() {
        // The second way the scheme check above can be walked around: the
        // `jwks_uri` is `https`, passes, and the host answers it with a
        // redirect to plain HTTP. `reqwest`'s default client follows up
        // to ten hops and does not care that one leaves TLS, so the keys
        // at the end of that chain are the ones assertions get verified
        // against.
        let fake =
            start_fake_issuer_redirecting_to_jwks(vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")])
                .await;

        // The default client: the hop is followed and the key is trusted.
        // This half is the finding, kept as the control — without it a
        // broken fixture would make the half below pass for free.
        assert!(JwksCache::new(reqwest::Client::new())
            .decoding_key(&fake.base, "k1")
            .await
            .is_ok());
        assert_eq!(fake.jwks_hits(), 1);

        // The client `mcp serve` builds: the hop is refused, so the key
        // set behind it is never read.
        assert!(JwksCache::new(https_only_client())
            .decoding_key(&fake.base, "k1")
            .await
            .is_err());
        assert_eq!(
            fake.jwks_hits(),
            1,
            "a hop off https must not have been followed"
        );
    }

    #[tokio::test]
    async fn test_key_is_cached_between_calls() {
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cache = cache();

        cache.decoding_key(&fake.base, "k1").await.unwrap();
        cache.decoding_key(&fake.base, "k1").await.unwrap();

        assert_eq!(fake.discovery_hits(), 1);
        assert_eq!(fake.jwks_hits(), 1);
    }

    #[tokio::test]
    async fn test_repeated_unknown_kid_does_not_refetch_within_the_window() {
        // A key set is allowed to gain keys, so a cold cache does fetch for
        // a `kid` it has never seen. What it must not do is fetch again for
        // the next one: without a window, every request carrying an invented
        // `kid` costs the issuer two sequential GETs, for as long as the
        // requests keep coming — and `/token` takes no credential to reach.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cache = cache();

        assert!(cache.decoding_key(&fake.base, "nope").await.is_err());
        assert!(cache.decoding_key(&fake.base, "nope").await.is_err());

        assert_eq!(fake.jwks_hits(), 1);
        assert_eq!(fake.discovery_hits(), 1);
    }

    #[tokio::test]
    async fn test_empty_key_set_does_not_evict_cached_keys() {
        // `keys` defaults to empty, so a CDN error page or a maintenance
        // response is a `200` that parses as a valid, empty key set. Letting
        // it through replaces every good key for the issuer with nothing,
        // which turns a transient blip into a dead grant.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cache = cache();
        cache.decoding_key(&fake.base, "k1").await.unwrap();

        fake.set_jwks(serde_json::json!({}).to_string());
        assert!(cache.refresh(&fake.base).await.is_err());
        assert!(cache.decoding_key(&fake.base, "k1").await.is_ok());
    }

    #[tokio::test]
    async fn test_unusable_key_set_does_not_evict_cached_keys() {
        // The likelier shape of the outage above: the set is not empty, so
        // the empty-set guard misses it, but nothing in it survives
        // `usable_key`. A CDN error body is one such entry; a rotation onto
        // a curve this AS does not accept is several. Taken at face value
        // both empty the cache.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cache = cache();
        cache.decoding_key(&fake.base, "k1").await.unwrap();

        fake.set_jwks(serde_json::json!({ "keys": [{"detail": "upstream error"}] }).to_string());
        assert!(cache.refresh(&fake.base).await.is_err());
        assert!(cache.decoding_key(&fake.base, "k1").await.is_ok());
    }

    #[tokio::test]
    async fn test_a_failed_refresh_leaves_the_window_unarmed() {
        // The second half of the same defect: an unusable set that returned
        // `Ok` armed the window, so recovery waited out
        // `MIN_KEY_TTL_SECONDS` even after the issuer had fixed its
        // document. The next miss has to retry instead.
        let fake =
            start_fake_issuer(None, vec![serde_json::json!({"detail": "upstream error"})]).await;
        let cache = cache();
        assert!(cache.decoding_key(&fake.base, "k1").await.is_err());
        assert_eq!(fake.jwks_hits(), 1);

        fake.set_jwks(
            serde_json::json!({ "keys": [ec_public_jwk(TEST_EC_PKCS8_B64, "k1")] }).to_string(),
        );
        assert!(cache.decoding_key(&fake.base, "k1").await.is_ok());
        assert_eq!(fake.jwks_hits(), 2);
    }

    #[tokio::test]
    async fn test_oversized_body_is_refused() {
        // A body served with a `Content-Length` is refused from the header
        // alone, before any of it is read. This is that branch: axum frames
        // a `String` with an exact length, so the short-circuit fires and
        // the read loop never runs. The chunked case below is the other one.
        let fake = start_fake_issuer(
            None,
            vec![serde_json::json!({
                "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "padding": "A".repeat(MAX_BODY_BYTES)
            })],
        )
        .await;

        assert!(cache().decoding_key(&fake.base, "k1").await.is_err());
    }

    #[tokio::test]
    async fn test_oversized_chunked_body_is_refused() {
        // The branch that actually matters. A chunked response declares no
        // length, so the header short-circuit cannot fire and the read loop
        // is the only thing between the issuer and an unbounded buffer.
        let huge = serde_json::json!({
            "keys": [{ "kty": "EC", "kid": "k1", "padding": "A".repeat(MAX_BODY_BYTES) }]
        });
        let fake = start_fake_issuer_with_chunked_jwks(huge.to_string()).await;

        let err = cache()
            .decoding_key(&fake.base, "k1")
            .await
            .expect_err("a body over the cap must not be read whole");
        // The message, because "refused" is not the property under test:
        // this body would also be refused for having no usable key, and
        // that refusal would mean it had been buffered and parsed first.
        assert!(
            format!("{err:#}").contains("larger than"),
            "refused for the wrong reason: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_key_set_above_the_entry_cap_is_refused() {
        // Refused whole rather than truncated: truncating drops whichever
        // key the exchange needed and reports it as an unknown `kid`.
        let mut keys: Vec<serde_json::Value> = (0..MAX_KEYS_PER_SET)
            .map(|i| ec_public_jwk(TEST_EC_PKCS8_B64, &format!("k{i}")))
            .collect();
        let fake = start_fake_issuer(None, keys.clone()).await;
        assert!(cache().decoding_key(&fake.base, "k0").await.is_ok());

        keys.push(ec_public_jwk(TEST_EC_PKCS8_B64, "one-too-many"));
        let fake = start_fake_issuer(None, keys).await;
        assert!(cache().decoding_key(&fake.base, "k0").await.is_err());
    }

    #[tokio::test]
    async fn test_hs_key_in_jwks_is_refused() {
        // A symmetric key can be used to *forge* a token, not just verify
        // one, so one must never become a `DecodingKey` here — whether the
        // key set labels it `HS256` or dresses it up as `ES256`.
        let fake = start_fake_issuer(
            None,
            vec![
                serde_json::json!({ "kty": "oct", "alg": "HS256", "kid": "sym", "k": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0" }),
                serde_json::json!({ "kty": "oct", "alg": "ES256", "kid": "liar", "k": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0" }),
            ],
        )
        .await;
        let cache = cache();

        assert!(cache.decoding_key(&fake.base, "sym").await.is_err());
        assert!(cache.decoding_key(&fake.base, "liar").await.is_err());
    }

    #[tokio::test]
    async fn test_ec_p256_key_without_alg_is_accepted_as_es256() {
        // `alg` is optional in RFC 7517. Refusing a key set that omits it
        // would take the grant down for an issuer doing nothing wrong, so
        // a P-256 key names its own algorithm.
        let fake = start_fake_issuer(
            None,
            vec![ec_public_jwk_without_alg(
                TEST_EC_PKCS8_B64,
                "k1",
                Algorithm::ES256,
            )],
        )
        .await;

        let (_, alg) = cache().decoding_key(&fake.base, "k1").await.unwrap();
        assert_eq!(alg, Algorithm::ES256);
    }

    #[tokio::test]
    async fn test_ec_key_on_another_curve_without_alg_is_refused() {
        // Deriving the algorithm from the key must not widen the accepted
        // set: P-384 is still outside it, with or without `alg`.
        let fake = start_fake_issuer(
            None,
            vec![ec_public_jwk_without_alg(
                TEST_EC_P384_PKCS8_B64,
                "k384",
                Algorithm::ES384,
            )],
        )
        .await;

        assert!(cache().decoding_key(&fake.base, "k384").await.is_err());
    }

    #[tokio::test]
    async fn test_one_unusable_key_does_not_take_down_the_set() {
        // Same failure mode as a missing `alg`, one level up: a key the
        // `jwk` types cannot model must cost its own entry and nothing
        // else.
        //
        // `sloppy` is the entry that actually exercises the parsing:
        // `key_ops` published as a string instead of an array is a real
        // publisher slip, and it makes a whole-set `JwkSet` deserialize
        // fail, taking the good key with it.
        //
        // `exotic` does not. An unmodelled curve was the first guess at a
        // trigger and it is the wrong one: `AlgorithmParameters` is
        // untagged with an `Other` variant that absorbs any object, so
        // the key parses fine and `usable_key` is what drops it, for not
        // being P-256. It stays here to pin that second behaviour.
        let fake = start_fake_issuer(
            None,
            vec![
                serde_json::json!({
                    "kty": "EC", "crv": "P-256", "kid": "sloppy", "key_ops": "verify",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }),
                serde_json::json!({
                    "kty": "EC", "crv": "secp256k1", "kid": "exotic", "alg": "ES256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }),
                ec_public_jwk(TEST_EC_PKCS8_B64, "good"),
            ],
        )
        .await;
        let cache = cache();

        let (_, alg) = cache.decoding_key(&fake.base, "good").await.unwrap();
        assert_eq!(alg, Algorithm::ES256);
        assert!(cache.decoding_key(&fake.base, "sloppy").await.is_err());
        assert!(cache.decoding_key(&fake.base, "exotic").await.is_err());
    }

    #[tokio::test]
    async fn test_rs256_key_is_accepted() {
        // RS256 is the second algorithm the grant accepts; without this the
        // allowlist could narrow to ES256 unnoticed.
        let fake = start_fake_issuer(
            None,
            vec![rsa_jwk("rsa-1", serde_json::json!({ "alg": "RS256" }))],
        )
        .await;

        let (_, alg) = cache().decoding_key(&fake.base, "rsa-1").await.unwrap();
        assert_eq!(alg, jsonwebtoken::Algorithm::RS256);
    }

    /// The public half of a throwaway RSA key as a JWKS entry, with
    /// `extra`'s members merged in — so a test can publish `use`,
    /// `key_ops` or `alg` on it without restating the modulus.
    fn rsa_jwk(kid: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut jwk = serde_json::json!({
            "kty": "RSA",
            "kid": kid,
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        });
        let entry = jwk.as_object_mut().unwrap();
        for (name, value) in extra.as_object().unwrap() {
            entry.insert(name.clone(), value.clone());
        }
        jwk
    }

    #[tokio::test]
    async fn test_a_key_published_for_encryption_never_verifies_an_assertion() {
        // RFC 7517 §4.2 and §4.3. One key set carrying both an encryption
        // key and a signing key is an ordinary shape — an issuer that
        // publishes everything at one `jwks_uri`. Read without `use` and
        // `key_ops`, the two are indistinguishable whenever `alg` is
        // omitted, which RFC 7517 allows: the encryption key becomes a
        // `DecodingKey` that verifies identity assertions, and its private
        // half is held under whatever rules the issuer applies to
        // decryption material rather than to signing material.
        let fake = start_fake_issuer(
            None,
            vec![
                rsa_jwk("enc-only", serde_json::json!({ "use": "enc" })),
                // The same key naming an algorithm. `alg` is not what
                // decides this: it answers *how* to verify, never
                // *whether* the issuer published the key for verifying,
                // so an encryption key that also carries `alg` was
                // accepted by exactly the same path.
                rsa_jwk(
                    "enc-with-alg",
                    serde_json::json!({ "alg": "RS256", "use": "enc" }),
                ),
                rsa_jwk(
                    "cannot-verify",
                    serde_json::json!({ "key_ops": ["encrypt", "wrapKey"] }),
                ),
                rsa_jwk(
                    "signing",
                    serde_json::json!({ "use": "sig", "key_ops": ["verify"] }),
                ),
            ],
        )
        .await;
        let cache = cache();

        for kid in ["enc-only", "enc-with-alg"] {
            assert!(
                cache.decoding_key(&fake.base, kid).await.is_err(),
                "{kid}: a key published for encryption was accepted as a verification key"
            );
        }
        assert!(
            cache
                .decoding_key(&fake.base, "cannot-verify")
                .await
                .is_err(),
            "a key whose key_ops exclude verification was accepted as a verification key"
        );
        // And the right one out of the same set is still chosen.
        let (_, alg) = cache.decoding_key(&fake.base, "signing").await.unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[tokio::test]
    async fn test_a_key_declaring_neither_use_nor_key_ops_is_still_accepted() {
        // Both parameters are optional and plenty of real key sets carry
        // neither, so reading them must not become a requirement to
        // publish them — that would be an outage for every issuer doing
        // nothing wrong. `use: "sig"` alone and `key_ops: ["verify"]`
        // alone are the other two shapes in the field.
        let fake = start_fake_issuer(
            None,
            vec![
                rsa_jwk("bare", serde_json::json!({})),
                rsa_jwk("use-only", serde_json::json!({ "use": "sig" })),
                rsa_jwk(
                    "ops-only",
                    serde_json::json!({ "key_ops": ["verify", "sign"] }),
                ),
                ec_public_jwk(TEST_EC_PKCS8_B64, "ec-bare"),
            ],
        )
        .await;
        let cache = cache();

        for kid in ["bare", "use-only", "ops-only"] {
            let (_, alg) = cache
                .decoding_key(&fake.base, kid)
                .await
                .unwrap_or_else(|e| panic!("{kid} should still be usable: {e:#}"));
            assert_eq!(alg, Algorithm::RS256);
        }
        let (_, alg) = cache.decoding_key(&fake.base, "ec-bare").await.unwrap();
        assert_eq!(alg, Algorithm::ES256);
    }

    #[tokio::test]
    async fn test_concurrent_misses_for_one_issuer_make_one_pair_of_fetches() {
        // Reachable before anything has been authenticated: `decoding_key`
        // runs at assertion check 2, ahead of the signature check at 3, and
        // the issuer URL it is called with is not a secret. Without
        // coalescing, N requests naming one unseen `kid` are N discovery
        // GETs and N key-set GETs aimed at the identity provider —
        // `FETCH_TIMEOUT` bounds what each one costs, never how many of
        // them run at once.
        const CALLERS: usize = 8;
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cache = Arc::new(cache());
        // Every caller is inside `decoding_key` before any of them has an
        // answer, which is the arrival pattern the defect needs.
        let gun = Arc::new(tokio::sync::Barrier::new(CALLERS));

        let mut callers = Vec::new();
        for _ in 0..CALLERS {
            let (cache, gun, issuer) = (cache.clone(), gun.clone(), fake.base.clone());
            callers.push(tokio::spawn(async move {
                gun.wait().await;
                cache.decoding_key(&issuer, "k1").await.map(|_| ())
            }));
        }
        for caller in callers {
            caller.await.unwrap().unwrap();
        }

        assert_eq!(
            fake.discovery_hits(),
            1,
            "concurrent misses for one issuer each ran their own discovery fetch"
        );
        assert_eq!(
            fake.jwks_hits(),
            1,
            "concurrent misses for one issuer each ran their own key-set fetch"
        );
    }

    #[tokio::test]
    async fn test_a_failing_issuer_is_paced_but_stays_retryable() {
        // The case the gate alone does not close. A failed refresh arms no
        // window on purpose, so callers that queue behind each other would
        // otherwise go straight back to the issuer the moment the one
        // before them gave up — serialized, but at no lower a rate.
        const CALLERS: u32 = 3;
        let fake =
            start_fake_issuer(None, vec![serde_json::json!({"detail": "upstream error"})]).await;
        let cache = Arc::new(cache());
        let started = Instant::now();

        let mut callers = Vec::new();
        for _ in 0..CALLERS {
            let (cache, issuer) = (cache.clone(), fake.base.clone());
            callers.push(tokio::spawn(async move {
                cache.decoding_key(&issuer, "k1").await.map(|_| ())
            }));
        }
        for caller in callers {
            assert!(caller.await.unwrap().is_err());
        }

        // Retryable, which is the policy the doc comment on `decoding_key`
        // argues for: an issuer that fixes its document is served again on
        // the next miss. The pacing must not quietly become a lockout.
        assert_eq!(
            fake.jwks_hits(),
            CALLERS as usize,
            "a broken issuer stopped being retried"
        );
        // Paced: the first attempt waits for nothing, every one after it
        // waits out the backoff armed by the failure before it.
        assert!(
            started.elapsed() >= FAILED_REFRESH_BACKOFF * (CALLERS - 1),
            "retries after a failed refresh were not paced: {:?}",
            started.elapsed()
        );
    }
}
