//! Redirect URI matcher for the OAuth Authorization Server.
//!
//! Two layers of validation, both required:
//! 1. The URI must be in the operator's allowlist (`oauthAs.redirectUriAllowlist`).
//! 2. The URI must also have been registered by the client via DCR.
//!
//! Matching against the allowlist supports a single trailing `*`
//! wildcard so deployments can paste ChatGPT-style
//! `https://chat.openai.com/aip/*/oauth/callback` without enumerating
//! every assistant id. Anchored prefix-only — `*` in the middle is
//! rejected because it muddles open-redirect analysis.
//!
//! HTTP redirect URIs are rejected unless they target loopback. This
//! prevents a registered client from quietly downgrading to plain
//! HTTP at runtime.

use anyhow::{bail, Result};
use url::Url;

/// True iff `candidate` matches `pattern`. Pattern may end with `*`
/// to match any suffix.
fn matches_pattern(candidate: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        candidate.starts_with(prefix)
    } else {
        candidate == pattern
    }
}

/// Validate a redirect URI for use in an OAuth flow. Returns `Ok(())`
/// when the URI passes both the allowlist and the security checks.
pub fn validate(uri: &str, allowlist: &[String]) -> Result<()> {
    let parsed = Url::parse(uri).map_err(|_| anyhow::anyhow!("invalid redirect_uri: {uri}"))?;

    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        bail!("redirect_uri scheme must be http or https: {uri}");
    }
    if scheme == "http" {
        // Loopback only — this is the OAuth-spec carve-out for
        // native apps and dev clients. Anything else over plain
        // HTTP is rejected.
        let host = parsed.host_str().unwrap_or("");
        let is_loopback = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
        if !is_loopback {
            bail!("redirect_uri uses plain http on non-loopback host: {uri}");
        }
    }

    if !allowlist.iter().any(|p| matches_pattern(uri, p)) {
        bail!("redirect_uri not in allowlist: {uri}");
    }

    // Reject any pattern that has `*` in the middle (was let through
    // by `matches_pattern` only as a trailing wildcard). Defense
    // against operator typos that would relax matching unexpectedly.
    if allowlist
        .iter()
        .any(|p| p.contains('*') && !p.ends_with('*'))
    {
        bail!("redirect_uri allowlist patterns may only use trailing '*'");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_exact_match_allowed() {
        let allow = vec!["https://claude.ai/api/mcp/auth_callback".to_string()];
        assert!(validate("https://claude.ai/api/mcp/auth_callback", &allow).is_ok());
    }

    #[test]
    fn test_trailing_wildcard_match() {
        let allow = vec!["https://chat.openai.com/aip/*".to_string()];
        assert!(validate(
            "https://chat.openai.com/aip/g-abc123/oauth/callback",
            &allow
        )
        .is_ok());
    }

    #[test]
    fn test_outside_allowlist_rejected() {
        let allow = vec!["https://claude.ai/api/mcp/auth_callback".to_string()];
        assert!(validate("https://attacker.example.com/cb", &allow).is_err());
    }

    #[test]
    fn test_http_loopback_allowed() {
        let allow = vec!["http://localhost:1234/cb".to_string()];
        assert!(validate("http://localhost:1234/cb", &allow).is_ok());
    }

    #[test]
    fn test_http_non_loopback_rejected_even_if_in_allowlist() {
        // Defense against an operator allowlisting an http:// URL by
        // mistake — must still be rejected at validation time.
        let allow = vec!["http://intranet.example.com/cb".to_string()];
        assert!(validate("http://intranet.example.com/cb", &allow).is_err());
    }

    #[test]
    fn test_non_http_scheme_rejected() {
        let allow = vec!["custom://nope".to_string()];
        assert!(validate("custom://nope", &allow).is_err());
        assert!(validate("javascript:alert(1)", &allow).is_err());
    }

    #[test]
    fn test_malformed_uri_rejected() {
        let allow = vec!["https://example.com/cb".to_string()];
        assert!(validate("not a uri", &allow).is_err());
    }

    #[test]
    fn test_middle_wildcard_pattern_rejected() {
        // `*` only at the end. Catches operator typos that would
        // otherwise widen the matcher unpredictably.
        let allow = vec!["https://*.example.com/cb".to_string()];
        // A request that matches the literal prefix would get past
        // `matches_pattern`, but `validate` flags the bad pattern.
        let res = validate("https://*.example.com/cb", &allow);
        assert!(res.is_err());
    }
}
