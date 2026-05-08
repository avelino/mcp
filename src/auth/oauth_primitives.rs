//! Shared OAuth 2.0 primitives — PKCE (RFC 7636), random opaque
//! identifiers, and the SHA-256 + base64url-no-pad helper that backs
//! `code_challenge` derivation.
//!
//! Both the *client* flow (`super::oauth`, `mcp` authenticating against
//! a remote MCP server) and the *server* flow (`crate::server_auth::oauth_as`,
//! `mcp serve` acting as an OAuth Authorization Server) call into these
//! helpers. Keeping them in one module avoids two-implementation drift
//! and centralizes the crypto choices (charset, length, hashing) that
//! must agree across both sides.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngExt;
use sha2::{Digest, Sha256};

/// Charset for opaque random tokens — the unreserved set from RFC 3986
/// (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`). Identical to the PKCE
/// `code_verifier` charset (RFC 7636 §4.1), so the same generator backs
/// both verifiers and arbitrary opaque IDs (authorization codes, DCR
/// `client_id`, JWT `jti`, etc.) without re-encoding.
const TOKEN_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// Generate a fresh PKCE `(code_verifier, code_challenge)` pair.
///
/// Verifier is 43 bytes from [`TOKEN_CHARSET`] — the minimum length
/// allowed by RFC 7636 §4.1 and the one Claude uses too. Challenge is
/// `BASE64URL(SHA-256(verifier))` with no padding (the `S256` method).
/// The `plain` method is intentionally not provided.
pub(crate) fn generate_pkce() -> (String, String) {
    let verifier = generate_random_string(43);
    let challenge = s256_challenge(&verifier);
    (verifier, challenge)
}

/// Compute the PKCE `S256` challenge from a verifier — used by the
/// authorization server to recompute and compare against the challenge
/// stored at `/authorize` time when the client presents the verifier
/// at `/token`.
pub(crate) fn s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Generate `len` chars of opaque random token from [`TOKEN_CHARSET`].
/// Suitable for PKCE verifiers, OAuth authorization codes, DCR
/// `client_id` values, and JWT `jti` claims.
pub(crate) fn generate_random_string(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..TOKEN_CHARSET.len());
            TOKEN_CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pkce() {
        let (verifier, challenge) = generate_pkce();
        assert!(verifier.len() >= 43);
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));

        // Challenge must be deterministic from verifier.
        assert_eq!(challenge, s256_challenge(&verifier));
    }

    #[test]
    fn test_s256_challenge_is_deterministic() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // Spot value matches the canonical example in RFC 7636 Appendix B.
        assert_eq!(
            s256_challenge(v),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn test_generate_random_string_length_and_charset() {
        let s = generate_random_string(32);
        assert_eq!(s.len(), 32);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));
    }

    #[test]
    fn test_generate_random_string_uniqueness() {
        // Not a cryptographic guarantee, but a sanity check: 64 bytes
        // from a 66-char alphabet should collide with negligible
        // probability across 100 draws.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            assert!(seen.insert(generate_random_string(64)));
        }
    }
}
