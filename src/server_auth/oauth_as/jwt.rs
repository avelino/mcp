//! HS256 JWT signing and verification for the OAuth Authorization
//! Server. Keeping the crypto pinned to one algorithm here means the
//! handlers never have to think about algorithm negotiation — and
//! more importantly, never accept `alg: none` or any algorithm we
//! didn't choose.

use anyhow::{bail, Context, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use super::types::JwtClaims;

/// Sign `claims` with HS256 using `secret`. The header is fixed to
/// `{ "alg": "HS256", "typ": "JWT" }` — there is no negotiation.
pub fn sign(claims: &JwtClaims, secret: &[u8]) -> Result<String> {
    let header = Header::new(Algorithm::HS256);
    encode(&header, claims, &EncodingKey::from_secret(secret)).context("failed to sign JWT")
}

/// Verify a bearer-style JWT and return its claims if valid.
///
/// Validation order matches RFC 7519 §7:
/// 1. Header alg must be HS256 — anything else (including `none`) is
///    rejected before signature verification.
/// 2. Signature is verified against `secret`.
/// 3. `iss` must equal `expected_issuer`.
/// 4. `aud` must equal `expected_audience` (single value, no arrays
///    in v1).
/// 5. `exp` and `nbf` are checked against current time with the
///    library's default 60-second leeway.
pub fn verify(
    token: &str,
    secret: &[u8],
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<JwtClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);

    let data = decode::<JwtClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .context("JWT verification failed")?;

    // Defense in depth: the `jsonwebtoken` crate already rejects
    // header.alg mismatches via `Validation::new(HS256)`, but assert
    // explicitly so a future upgrade can't silently widen the contract.
    if data.header.alg != Algorithm::HS256 {
        bail!("JWT header rejected: alg must be HS256");
    }

    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn fresh_claims(iss: &str, aud: &str, sub: &str) -> JwtClaims {
        let n = now();
        JwtClaims {
            iss: iss.to_string(),
            aud: aud.to_string(),
            sub: sub.to_string(),
            groups: vec!["dev".to_string()],
            iat: n,
            nbf: n,
            exp: n + 3600,
            jti: "test-jti".to_string(),
        }
    }

    fn secret() -> [u8; 32] {
        [b'k'; 32]
    }

    fn other_secret() -> [u8; 32] {
        [b'q'; 32]
    }

    #[test]
    fn test_sign_then_verify_roundtrip() {
        let claims = fresh_claims("https://mcp.example.com", "client-1", "alice");
        let token = sign(&claims, &secret()).unwrap();
        let got = verify(&token, &secret(), "https://mcp.example.com", "client-1").unwrap();
        assert_eq!(got.sub, "alice");
        assert_eq!(got.groups, vec!["dev".to_string()]);
    }

    #[test]
    fn test_verify_rejects_wrong_secret() {
        // Bypass guard: signature must verify against the configured
        // secret, never accepted on a different one.
        let claims = fresh_claims("https://mcp.example.com", "client-1", "alice");
        let token = sign(&claims, &secret()).unwrap();
        assert!(verify(
            &token,
            &other_secret(),
            "https://mcp.example.com",
            "client-1"
        )
        .is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_issuer() {
        let claims = fresh_claims("https://attacker.example.com", "client-1", "alice");
        let token = sign(&claims, &secret()).unwrap();
        assert!(verify(&token, &secret(), "https://mcp.example.com", "client-1").is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_audience() {
        // Privilege boundary: a token issued for client A must NOT
        // validate when presented to client B's session.
        let claims = fresh_claims("https://mcp.example.com", "client-A", "alice");
        let token = sign(&claims, &secret()).unwrap();
        assert!(verify(&token, &secret(), "https://mcp.example.com", "client-B").is_err());
    }

    #[test]
    fn test_verify_rejects_expired() {
        let mut claims = fresh_claims("https://mcp.example.com", "client-1", "alice");
        // Push exp far enough into the past to beat the default 60s
        // leeway in `Validation`.
        let n = now();
        claims.iat = n - 7200;
        claims.nbf = n - 7200;
        claims.exp = n - 3600;
        let token = sign(&claims, &secret()).unwrap();
        assert!(verify(&token, &secret(), "https://mcp.example.com", "client-1").is_err());
    }

    #[test]
    fn test_verify_rejects_alg_none_attack() {
        // Bypass guard: classic `alg: none` attack must not work —
        // the verifier is pinned to HS256 and ignores the header alg
        // field for algorithm selection.
        // We craft a token manually with the alg=none header.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let claims = fresh_claims("https://mcp.example.com", "client-1", "alice");
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let forged = format!("{header}.{payload}.");
        assert!(verify(&forged, &secret(), "https://mcp.example.com", "client-1").is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_payload() {
        // Modifying any byte of the payload must invalidate the
        // signature.
        let claims = fresh_claims("https://mcp.example.com", "client-1", "alice");
        let token = sign(&claims, &secret()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        // Replace payload with a different (valid base64url) string.
        let tampered_payload = "eyJpc3MiOiJodHRwczovL21jcC5leGFtcGxlLmNvbSIsImF1ZCI6ImNsaWVudC1BIiwic3ViIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTksIm5iZiI6MCwiaWF0IjowLCJqdGkiOiJ0IiwiZ3JvdXBzIjpbXX0";
        parts[1] = tampered_payload;
        let forged = parts.join(".");
        assert!(verify(&forged, &secret(), "https://mcp.example.com", "client-1").is_err());
    }
}
