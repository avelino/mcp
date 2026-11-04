//! Validation of ID-JAG identity assertions
//! (draft-ietf-oauth-identity-assertion-authz-grant).
//!
//! A client presents an assertion signed by a trusted identity provider
//! and gets an access token back with no consent screen, so everything
//! standing between a stranger and a session happens in this file. Each
//! check below is numbered after the order the grant's documentation
//! requires; the order is load-bearing, not cosmetic.

use jsonwebtoken::dangerous::insecure_decode_claims;
use jsonwebtoken::{decode, decode_header, get_current_timestamp, Algorithm, Validation};
use serde::Deserialize;

use super::config::{OAuthAsConfig, TrustedIssuer};
use super::jwks::JwksCache;
use super::state::{AsState, JtiRefusal};

/// The only `typ` an identity assertion may carry. `jsonwebtoken` does
/// not look at `typ`, so nothing checks it unless this file does.
pub const ID_JAG_TYP: &str = "oauth-id-jag+jwt";

/// Clock skew tolerated on every time claim.
const MAX_CLOCK_SKEW_SECONDS: u64 = 60;

/// Ceiling on how far ahead `exp` may sit.
///
/// Every accepted `jti` is remembered until its `exp`, so an assertion
/// expiring in the year 3000 would be a cache entry `gc_expired` never
/// reclaims. An ID-JAG is short-lived by design — Claude's expires in
/// under a minute — so this is set far above any plausible real lifetime:
/// it exists to bound the replay cache, not to second-guess the issuer.
const MAX_ASSERTION_LIFETIME_SECONDS: u64 = 3600;

/// Who the assertion vouches for, once it has been believed.
#[derive(Debug)]
pub struct ValidatedAssertion {
    pub subject: String,
    pub roles: Vec<String>,
}

/// `aud` arrives as a bare string or as an array holding one entry.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    /// `None` unless the assertion names exactly one audience: more than
    /// one means it was not minted for this AS alone.
    fn single(&self) -> Option<&str> {
        match self {
            Audience::One(one) => Some(one),
            Audience::Many(many) => match many.as_slice() {
                [one] => Some(one),
                _ => None,
            },
        }
    }
}

#[derive(Deserialize)]
struct AssertionClaims {
    iss: String,
    #[serde(default)]
    aud: Option<Audience>,
    /// Picks the workspace when several share one issuer URL.
    #[serde(default)]
    aud_tenant: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

/// Decide whether `assertion` genuinely vouches for someone this AS will
/// issue a token to. Every `Err` is an `invalid_grant`; the string is the
/// `error_description`.
pub async fn validate(
    assertion: &str,
    request_client_id: &str,
    cfg: &OAuthAsConfig,
    jwks: &JwksCache,
    state: &AsState,
) -> Result<ValidatedAssertion, String> {
    let header = decode_header(assertion).map_err(|_| "assertion header is malformed")?;

    // Part of check 3, pulled forward: the algorithm is pinned before any
    // network call, so an assertion offering HS256 — which would verify
    // against this AS's own secret — never even reaches the key fetch.
    // `alg: none` fails earlier still, since it does not parse into
    // `Algorithm` at all.
    if !matches!(header.alg, Algorithm::ES256 | Algorithm::RS256) {
        return Err("assertion alg must be ES256 or RS256".to_string());
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or("assertion header carries no kid")?;

    // Read but not believed: these claims only choose which issuer entry
    // and which key apply. Everything is re-read from the verified
    // payload below.
    let unverified: AssertionClaims =
        insecure_decode_claims(assertion).map_err(|_| "assertion payload is malformed")?;

    // Check 0 — which trusted issuer this assertion belongs to. Decided
    // on an unverified payload, so it settles nothing but which key to
    // ask for; both checks run again below on the signed payload.
    let key_issuer = cfg
        .resolve_issuer(&unverified.iss, unverified.aud_tenant.as_deref())
        .map_err(|why| format!("assertion {why}"))?;

    // Check 1 — `iss` is the entry's issuer as an exact string. A prefix
    // or host match would admit another customer's users. `resolve_issuer`
    // already compares byte for byte; repeating it keeps the rule true
    // here even if that function's matching ever changes.
    if unverified.iss != key_issuer.issuer {
        return Err("assertion iss does not match the trusted issuer".to_string());
    }

    // Check 2 — the key comes from the issuer's own discovery document.
    // The `jwk`, `jku` and `x5u` headers of the assertion are ignored.
    // The URL is built from the configured issuer, equal to `iss` by the
    // check above, so no part of this fetch is attacker-shaped.
    let (key, key_alg) = match jwks.decoding_key(&key_issuer.issuer, kid).await {
        Ok(resolved) => resolved,
        Err(e) => {
            // Unreachable issuer, a discovery document naming someone
            // else, a key set that is not a JWKS, no usable key for this
            // kid — all one message to the client on purpose, so whoever
            // is on call needs the real reason here.
            tracing::warn!(
                issuer = %key_issuer.issuer,
                kid = %kid,
                error = format!("{e:#}"),
                "could not resolve the signing key for an identity assertion"
            );
            return Err("assertion signing key could not be resolved".to_string());
        }
    };
    if header.alg != key_alg {
        return Err("assertion alg does not match its signing key".to_string());
    }

    // Check 3 — the signature. Claim validation stays off here so the
    // remaining checks run below in the documented order, each with its
    // own refusal reason.
    let mut validation = Validation::new(key_alg);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = decode::<AssertionClaims>(assertion, &key, &validation)
        .map_err(|_| "assertion signature is invalid")?
        .claims;

    // Checks 0 and 1 again, now on the payload the signature covers. The
    // allowed domains and the roles below come from this entry, so the
    // unverified read must not be what chose it.
    //
    // Measured caveat, so nobody reads more into this than it earns: both
    // reads deserialize the same bytes into the same struct, so today this
    // re-read is behaviourally identical to reusing `key_issuer` and no
    // test can tell them apart. It is here for the day they can diverge —
    // a separate struct for the unverified read, or a parser change — at
    // which point an unsigned `aud_tenant` would otherwise pick the role
    // set. `test_roles_and_domains_come_from_the_resolved_tenant` covers
    // the tenant -> privilege mapping, not this re-read.
    let trusted = cfg
        .resolve_issuer(&claims.iss, claims.aud_tenant.as_deref())
        .map_err(|why| format!("assertion {why}"))?;
    if claims.iss != trusted.issuer {
        return Err("assertion iss does not match the trusted issuer".to_string());
    }

    // Check 4 — type.
    if header.typ.as_deref() != Some(ID_JAG_TYP) {
        return Err(format!("assertion typ must be {ID_JAG_TYP}"));
    }

    // Check 5 — audience is this AS.
    let aud = claims
        .aud
        .as_ref()
        .and_then(Audience::single)
        .ok_or("assertion aud is missing or names more than one audience")?;
    // Trimmed on both sides, the same way the metadata, authorize, token
    // and JWKS paths trim it: the issuer the IdP read from our metadata is
    // already the trimmed form, so a configured trailing slash would refuse
    // every assertion. `trim_end_matches` strips a run, so trailing slashes
    // are forgiven, not a single one; everything before them is still an
    // exact string match.
    if aud.trim_end_matches('/') != cfg.issuer_url.trim_end_matches('/') {
        return Err("assertion aud is not this authorization server".to_string());
    }

    // Check 6 — the assertion names the client presenting it.
    if claims.client_id.as_deref() != Some(request_client_id) {
        return Err("assertion client_id does not match the request".to_string());
    }

    // Check 7 — a subject is present.
    if claims.sub.as_deref().is_none_or(str::is_empty) {
        return Err("assertion carries no sub".to_string());
    }

    // Check 8 — time.
    let now = get_current_timestamp();
    let exp = claims.exp.ok_or("assertion carries no exp")?;
    if exp.saturating_add(MAX_CLOCK_SKEW_SECONDS) <= now {
        return Err("assertion has expired".to_string());
    }
    if exp > now.saturating_add(MAX_ASSERTION_LIFETIME_SECONDS) {
        return Err("assertion exp is too far in the future".to_string());
    }
    let iat = claims.iat.ok_or("assertion carries no iat")?;
    if iat > now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
        return Err("assertion iat is in the future".to_string());
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(MAX_CLOCK_SKEW_SECONDS))
    {
        return Err("assertion is not valid yet".to_string());
    }

    // Identity. This AS has no user database, so `sub` resolves against
    // nothing and the email is the subject; the domain allowlist is the
    // control that makes that safe, which is why a missing email is a
    // refusal rather than a fallback to `sub`.
    let subject = subject_email(&claims, trusted)?;

    // Check 9 — replay, last of all, so an assertion refused above never
    // burns the `jti` of one that would have been accepted. Remembered
    // past `exp` plus the skew granted at check 8, so the entry outlives
    // every moment the assertion is still usable. Any failure refuses:
    // an unknown replay status is never treated as "not replayed".
    let jti = match claims.jti.as_deref() {
        Some(jti) if !jti.is_empty() => jti,
        _ => return Err("assertion carries no jti".to_string()),
    };
    // Namespaced by `trusted.issuer`, which came from the signed payload: one
    // issuer's `jti` is only unique within that issuer (RFC 7519 §4.1.7), and
    // reading the namespace off the unverified claims would let the presenter
    // pick which one to burn.
    if let Err(refusal) = state.remember_jti(
        &trusted.issuer,
        jti,
        exp.saturating_add(MAX_CLOCK_SKEW_SECONDS),
    ) {
        // One string to the client for both, so nobody can probe the
        // cache's state by watching the wording change. The *levels*
        // differ, because the causes do: a replayed `jti` is ordinary — a
        // client that re-POSTs `/token` after a timeout, or a proxy that
        // retries, presents the same assertion twice — and reporting that
        // at `warn!` would bury the cap refusal, which is the one an
        // operator has to act on, in a stream of benign ones.
        //
        // Two calls rather than a computed level: `tracing` fixes the
        // level at compile time.
        match refusal {
            JtiRefusal::AlreadyUsed => tracing::debug!(
                issuer = %trusted.issuer,
                jti = %jti,
                reason = %refusal,
                "refused to redeem an identity assertion"
            ),
            JtiRefusal::CacheFull => tracing::warn!(
                issuer = %trusted.issuer,
                jti = %jti,
                reason = %refusal,
                "refused to redeem an identity assertion"
            ),
        }
        return Err("assertion was refused by replay protection".to_string());
    }

    Ok(ValidatedAssertion {
        subject,
        // Roles come from this operator's configuration, never from the
        // assertion: a group claim minted by someone else's identity
        // provider would be privilege escalation by their configuration.
        roles: trusted.roles.clone(),
    })
}

/// The `email` claim lowercased, once its domain is one the issuer is
/// allowed to vouch for. The domain is compared whole — a suffix match
/// would make `evilexample.com` pass for `example.com`.
fn subject_email(claims: &AssertionClaims, trusted: &TrustedIssuer) -> Result<String, String> {
    let email = match claims.email.as_deref() {
        Some(email) if !email.is_empty() => email,
        _ => return Err("assertion carries no email".to_string()),
    };
    // Refused before anything normalizes it: `to_lowercase` folds U+212A
    // (KELVIN SIGN) onto ASCII `k`, so `ban\u{212A}.com` would arrive at the
    // comparison below as `bank.com`. Restricted to ASCII,
    // `to_ascii_lowercase` is injective up to ASCII case, which is the only
    // collapse left and exactly the one `eq_ignore_ascii_case` below already
    // performs. So no two domains that differ by more than case can
    // normalize together.
    if !email.is_ascii() {
        return Err("assertion email must be ascii".to_string());
    }
    let email = email.to_ascii_lowercase();
    let domain = match email.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => domain,
        _ => return Err("assertion email is malformed".to_string()),
    };
    if !trusted
        .allowed_email_domains
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(domain))
    {
        return Err("assertion email domain is not allowed for this issuer".to_string());
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::super::config::{OAuthAsConfig, TrustedIssuer};
    use super::super::state::AsState;
    use super::super::test_helpers::{
        ec_encoding_key, ec_public_jwk, start_fake_issuer, OTHER_EC_PKCS8_B64, TEST_EC_PKCS8_B64,
    };
    use super::*;

    use jsonwebtoken::{encode, get_current_timestamp, EncodingKey, Header};
    use serde_json::json;

    const AS_URL: &str = "https://mcp.example.com";
    const AS_SECRET: &str = "as-secret-as-secret-as-secret-32";
    const CLIENT_ID: &str = "claude-enterprise";

    fn jwks() -> JwksCache {
        JwksCache::new(reqwest::Client::new())
    }

    /// The fake issuer speaks plain HTTP on loopback. `validate` never
    /// looks at the scheme — `OAuthAsConfig::validate` is what requires
    /// https at boot — so a trusted entry can point straight at it.
    fn trusted(issuer: &str, tenant: Option<&str>) -> TrustedIssuer {
        TrustedIssuer {
            issuer: issuer.to_string(),
            tenant_id: tenant.map(str::to_string),
            allowed_email_domains: vec!["example.com".to_string()],
            roles: vec!["ema-user".to_string()],
        }
    }

    fn config(trusted_issuers: Vec<TrustedIssuer>) -> OAuthAsConfig {
        OAuthAsConfig {
            issuer_url: AS_URL.to_string(),
            jwt_secret: AS_SECRET.to_string(),
            trusted_user_header: "x-forwarded-user".to_string(),
            trusted_groups_header: "x-forwarded-groups".to_string(),
            trusted_source_cidrs: vec!["127.0.0.1/32".to_string()],
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 2_592_000,
            authorization_code_ttl_seconds: 60,
            scopes_supported: vec![],
            redirect_uri_allowlist: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
            injected_roles: vec![],
            trusted_issuers,
            static_clients: vec![],
        }
    }

    /// A well-formed ID-JAG payload. `groups` is there on purpose: a
    /// third party's idea of what roles a user holds must never be read.
    fn claims(issuer: &str) -> serde_json::Value {
        let now = get_current_timestamp();
        json!({
            "iss": issuer,
            "aud": AS_URL,
            "sub": "user-1",
            "client_id": CLIENT_ID,
            "email": "Alice@Example.com",
            "jti": "jti-1",
            "iat": now,
            "exp": now + 300,
            "groups": ["admins"],
        })
    }

    fn sign(pkcs8_b64: &str, typ: &str, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.to_string());
        header.kid = Some(kid.to_string());
        encode(&header, claims, &ec_encoding_key(pkcs8_b64)).unwrap()
    }

    /// The happy path, end to end, so each refusal test differs from a
    /// working exchange by exactly the thing it is about.
    async fn valid_setup() -> (super::super::test_helpers::FakeIssuer, OAuthAsConfig) {
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![trusted(&fake.base, None)]);
        (fake, cfg)
    }

    #[tokio::test]
    async fn test_valid_assertion_yields_email_subject_and_config_roles() {
        let (fake, cfg) = valid_setup().await;
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));

        let out = validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
            .await
            .unwrap();

        assert_eq!(out.subject, "alice@example.com");
        assert_eq!(out.roles, vec!["ema-user".to_string()]);
    }

    #[tokio::test]
    async fn test_unregistered_issuer_is_refused() {
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![trusted("https://elsewhere.example.com", None)]);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
        // The issuer is settled before any key is fetched.
        assert_eq!(fake.discovery_hits(), 0);
    }

    #[tokio::test]
    async fn test_aud_tenant_pointing_at_a_workspace_with_another_issuer_is_refused() {
        // `aud_tenant` names a workspace that belongs to a different
        // issuer. Honouring it would let one customer's identity provider
        // mint users into another customer's workspace.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![
            trusted(&fake.base, Some("tenant-a")),
            trusted("https://elsewhere.example.com", Some("tenant-b")),
        ]);
        let mut payload = claims(&fake.base);
        payload["aud_tenant"] = json!("tenant-b");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_roles_and_domains_come_from_the_resolved_tenant() {
        // Two workspaces behind one issuer, with different roles and
        // different allowed domains. Without this, every trusted entry in
        // the suite carries the same roles and the same domains, so the
        // tenant -> privileges mapping is invisible and a resolution that
        // picked the wrong entry would break no test at all.
        //
        // What this does NOT cover, measured rather than assumed: it does
        // not protect the re-resolution on the signed payload. Reverting
        // that to reuse the entry picked from the unverified read keeps
        // this test green, because both reads deserialize the same bytes.
        // See the comment at that call site for why it is still there.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![
            TrustedIssuer {
                issuer: fake.base.clone(),
                tenant_id: Some("tenant-a".to_string()),
                allowed_email_domains: vec!["a.example.com".to_string()],
                roles: vec!["role-a".to_string()],
            },
            TrustedIssuer {
                issuer: fake.base.clone(),
                tenant_id: Some("tenant-b".to_string()),
                allowed_email_domains: vec!["b.example.com".to_string()],
                roles: vec!["role-b".to_string()],
            },
        ]);

        let mut payload = claims(&fake.base);
        payload["aud_tenant"] = json!("tenant-b");
        payload["email"] = json!("User@B.Example.com");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);
        let out = validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
            .await
            .unwrap();
        assert_eq!(out.roles, vec!["role-b".to_string()]);
        assert_eq!(out.subject, "user@b.example.com");

        // And the domain allowlist is scoped to the same entry: tenant-a
        // does not get to vouch for tenant-b's users.
        let mut payload = claims(&fake.base);
        payload["aud_tenant"] = json!("tenant-a");
        payload["email"] = json!("user@b.example.com");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);
        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_exp_too_far_in_the_future_is_refused() {
        // Every accepted `jti` is remembered until its `exp`, so an
        // assertion good for a decade would be a cache entry the GC never
        // reclaims.
        let (fake, cfg) = valid_setup().await;
        let mut payload = claims(&fake.base);
        payload["exp"] = json!(get_current_timestamp() + 86_400 * 2);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_issuer_registered_twice_without_aud_tenant_is_refused() {
        // Two workspaces behind one issuer URL and nothing says which one:
        // picking either would be a guess about who the user is.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![
            trusted(&fake.base, Some("tenant-a")),
            trusted(&fake.base, Some("tenant-b")),
        ]);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));

        let err = validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "assertion issuer requires a tenant the assertion does not name"
        );
    }

    #[tokio::test]
    async fn test_assertion_without_aud_tenant_does_not_inherit_a_tenants_roles() {
        // The privilege half of the tenant finding, end to end on the
        // signed path. One entry, tenanted, carrying the roles and the
        // domains of that workspace. An assertion that names no tenant
        // used to resolve to it and walk out with `tenant-a-admin` and
        // `tenant-a.example` — a workspace's privileges handed to an
        // assertion that identified no workspace.
        //
        // Signed by the issuer's real key, with every other check
        // passing, so the refusal can only come from the resolution.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![TrustedIssuer {
            issuer: fake.base.clone(),
            tenant_id: Some("tenant-a".to_string()),
            allowed_email_domains: vec!["tenant-a.example".to_string()],
            roles: vec!["tenant-a-admin".to_string()],
        }]);
        let mut payload = claims(&fake.base);
        payload["email"] = json!("alice@tenant-a.example");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        let err = validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "assertion issuer requires a tenant the assertion does not name"
        );

        // Naming the tenant is what earns the roles, and still does.
        payload["aud_tenant"] = json!("tenant-a");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);
        let out = validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
            .await
            .unwrap();
        assert_eq!(out.roles, vec!["tenant-a-admin".to_string()]);
    }

    #[tokio::test]
    async fn test_replayed_assertion_is_refused() {
        let (fake, cfg) = valid_setup().await;
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));
        let state = AsState::default();
        let cache = jwks();

        assert!(validate(&token, CLIENT_ID, &cfg, &cache, &state)
            .await
            .is_ok());
        assert!(validate(&token, CLIENT_ID, &cfg, &cache, &state)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_a_full_replay_cache_is_not_reported_as_a_replay() {
        // `remember_jti` has two refusals — this `jti` was redeemed, or the
        // cache is at its cap — and the client has to get one message for
        // both. Wording that moved with the cause would be a probe for the
        // cache's state, and a user whose fresh assertion was turned away
        // by the cap must not be told it had already been used.
        let (fake, cfg) = valid_setup().await;
        let state = AsState::default();
        let cache = jwks();

        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));
        validate(&token, CLIENT_ID, &cfg, &cache, &state)
            .await
            .unwrap();
        let replay_refusal = validate(&token, CLIENT_ID, &cfg, &cache, &state)
            .await
            .unwrap_err();

        // Live entries, so the cap branch's own sweep cannot reclaim them.
        // One short of the cap, because the exchange above already holds a
        // slot — fill the last one and this loop refuses itself.
        let exp = get_current_timestamp() + 600;
        for i in 0..super::super::state::MAX_SEEN_JTI - 1 {
            state
                .remember_jti(&fake.base, &format!("filler-{i}"), exp)
                .unwrap();
        }
        let mut fresh = claims(&fake.base);
        fresh["jti"] = json!("never-seen-before");
        let cap_refusal = validate(
            &sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &fresh),
            CLIENT_ID,
            &cfg,
            &cache,
            &state,
        )
        .await
        .unwrap_err();

        // The defect this pins is not that the two differ — the mapping it
        // replaced made them identical by discarding the cause. It is that
        // the one message they share used to be a false statement about a
        // never-seen assertion.
        assert!(
            !cap_refusal.contains("already"),
            "a fresh assertion refused by the cap is reported as a replay: {cap_refusal}"
        );
        assert_eq!(
            cap_refusal, replay_refusal,
            "the wording must not say which of the two refusals it was"
        );
    }

    #[tokio::test]
    async fn test_same_jti_from_two_issuers_does_not_collide() {
        // RFC 7519 §4.1.7 only promises a `jti` is unique per issuer, so two
        // trusted IdPs picking the same one is ordinary rather than hostile.
        // Keyed on the `jti` alone, whichever assertion lost the race locks
        // the other customer's user out until the entry expires.
        //
        // Measured caveat, in the same spirit as the one at the re-resolution
        // above: this pins the namespacing, not where the namespace is read
        // from. Keying on `key_issuer` instead of `trusted` keeps it green,
        // because both reads resolve to the same entry. The signed-payload
        // requirement is documented on `remember_jti`.
        let a = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let b = start_fake_issuer(None, vec![ec_public_jwk(OTHER_EC_PKCS8_B64, "k1")]).await;
        let cfg = config(vec![trusted(&a.base, None), trusted(&b.base, None)]);
        let state = AsState::default();
        let cache = jwks();

        // Same `jti` in both: `claims` hard-codes it.
        let from_a = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&a.base));
        let from_b = sign(OTHER_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&b.base));

        validate(&from_a, CLIENT_ID, &cfg, &cache, &state)
            .await
            .unwrap();
        validate(&from_b, CLIENT_ID, &cfg, &cache, &state)
            .await
            .unwrap();

        // And the replay guard still bites inside one issuer's namespace.
        assert!(validate(&from_a, CLIENT_ID, &cfg, &cache, &state)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_wrong_audience_is_refused() {
        // An assertion minted for another resource server must not be
        // redeemable here.
        let (fake, cfg) = valid_setup().await;
        let mut payload = claims(&fake.base);
        payload["aud"] = json!("https://other-mcp.example.com");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_aud_matches_issuer_url_with_trailing_slash() {
        // A trailing slash on `issuerUrl` is a supported shape, and every
        // other point in the AS trims it — so the metadata an IdP reads
        // advertises the trimmed form and the `aud` it mints has no slash.
        // Comparing the raw strings refuses every assertion such a deploy
        // ever receives, with a message pointing at the audience.
        let (fake, mut cfg) = valid_setup().await;
        cfg.issuer_url = format!("{AS_URL}/");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));

        validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_aud_as_single_element_array_is_accepted() {
        let (fake, cfg) = valid_setup().await;
        let mut payload = claims(&fake.base);
        payload["aud"] = json!([AS_URL]);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);
        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_ok()
        );

        // More than one audience is not "this AS", it is "this AS among
        // others" — the assertion was not minted for us alone.
        let mut payload = claims(&fake.base);
        payload["aud"] = json!([AS_URL, "https://other-mcp.example.com"]);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);
        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_email_outside_allowed_domains_is_refused() {
        let (fake, cfg) = valid_setup().await;
        for email in ["alice@other.example.net", "alice@notexample.com"] {
            let mut payload = claims(&fake.base);
            payload["email"] = json!(email);
            let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);
            assert!(
                validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                    .await
                    .is_err(),
                "{email} should not be allowed"
            );
        }
    }

    #[tokio::test]
    async fn test_non_ascii_email_is_refused() {
        // U+212A KELVIN SIGN lowercases to ASCII `k` under full Unicode
        // folding, so `ban\u{212A}.com` normalizes into `bank.com` and walks
        // straight through the domain allowlist — the one control that makes
        // "email as subject" safe. Refusing non-ASCII before normalizing
        // closes the class, not just this character.
        let fake = start_fake_issuer(None, vec![ec_public_jwk(TEST_EC_PKCS8_B64, "k1")]).await;
        let mut entry = trusted(&fake.base, None);
        entry.allowed_email_domains = vec!["bank.com".to_string()];
        let cfg = config(vec![entry]);
        let mut payload = claims(&fake.base);
        payload["email"] = json!("alice@ban\u{212A}.com");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_missing_sub_is_refused() {
        // Nothing downstream reads `sub` today — the subject is the email —
        // so without this test the check could be dropped in a refactor
        // with no signal, and it starts mattering again the day `sub` is
        // used for IdP account linking.
        let (fake, cfg) = valid_setup().await;
        let mut payload = claims(&fake.base);
        payload.as_object_mut().unwrap().remove("sub");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_missing_email_is_refused() {
        // There is no user database to resolve a `sub` against, so an
        // assertion with no email has no identity we can act on. Falling
        // back to `sub` would also skip the domain allowlist entirely.
        let (fake, cfg) = valid_setup().await;
        let mut payload = claims(&fake.base);
        payload.as_object_mut().unwrap().remove("email");
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_hs256_assertion_signed_with_as_secret_is_refused() {
        // Key confusion: the AS's own HMAC secret is known to this process,
        // so an HS256 assertion would verify against it. The algorithm is
        // pinned before anything else happens.
        let (fake, cfg) = valid_setup().await;
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(ID_JAG_TYP.to_string());
        header.kid = Some("k1".to_string());
        let token = encode(
            &header,
            &claims(&fake.base),
            &EncodingKey::from_secret(AS_SECRET.as_bytes()),
        )
        .unwrap();

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
        assert_eq!(fake.discovery_hits(), 0);
        assert_eq!(fake.jwks_hits(), 0);
    }

    #[tokio::test]
    async fn test_alg_none_assertion_is_refused() {
        // The classic unsigned-token attack: a header saying there is no
        // signature, and a payload that would otherwise be perfect.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let (fake, cfg) = valid_setup().await;
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "alg": "none", "typ": ID_JAG_TYP, "kid": "k1" }).to_string(),
        );
        let payload = URL_SAFE_NO_PAD.encode(claims(&fake.base).to_string());
        let token = format!("{header}.{payload}.");

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
        assert_eq!(fake.discovery_hits(), 0);
    }

    #[tokio::test]
    async fn test_assertion_signed_by_another_key_is_refused() {
        // Right issuer, right `kid`, wrong private key.
        let (fake, cfg) = valid_setup().await;
        let token = sign(OTHER_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_wrong_typ_header_is_refused() {
        // A plain `JWT` reaching this grant is some other token being
        // replayed as an identity assertion.
        let (fake, cfg) = valid_setup().await;
        let token = sign(TEST_EC_PKCS8_B64, "JWT", "k1", &claims(&fake.base));

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_client_id_claim_must_match_request() {
        // The assertion was minted for one client; another client must not
        // be able to redeem it.
        let (fake, cfg) = valid_setup().await;
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &claims(&fake.base));

        assert!(validate(
            &token,
            "some-other-client",
            &cfg,
            &jwks(),
            &AsState::default()
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_expired_assertion_is_refused() {
        let (fake, cfg) = valid_setup().await;
        let now = get_current_timestamp();
        let mut payload = claims(&fake.base);
        payload["iat"] = json!(now - 600);
        payload["exp"] = json!(now - 120);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_iat_in_the_future_is_refused() {
        let (fake, cfg) = valid_setup().await;
        let now = get_current_timestamp();
        let mut payload = claims(&fake.base);
        payload["iat"] = json!(now + 120);
        payload["exp"] = json!(now + 600);
        let token = sign(TEST_EC_PKCS8_B64, ID_JAG_TYP, "k1", &payload);

        assert!(
            validate(&token, CLIENT_ID, &cfg, &jwks(), &AsState::default())
                .await
                .is_err()
        );
    }
}
