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

/// Validate that an allowlist pattern is well-formed. Used both at
/// boot (so misconfiguration fails fast) and at request time. Only
/// trailing `*` wildcards are accepted.
pub(crate) fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.contains('*') && !pattern.ends_with('*') {
        bail!("redirect_uri allowlist patterns may only use trailing '*': {pattern}");
    }
    // The non-wildcard prefix must be a parseable http(s) URL on its
    // own. This catches operator typos like `https//example.com/cb`
    // (missing colon) or schemes other than http/https before any
    // request hits the server.
    let prefix = pattern.trim_end_matches('*');
    let parsed = Url::parse(prefix).map_err(|_| {
        anyhow::anyhow!("redirect_uri allowlist pattern is not a valid URL: {pattern}")
    })?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        bail!("redirect_uri allowlist pattern scheme must be http or https: {pattern}");
    }
    Ok(())
}

/// Validate a redirect URI for use in an OAuth flow. Returns `Ok(())`
/// when the URI passes both the allowlist and the security checks.
pub fn validate(uri: &str, allowlist: &[String]) -> Result<()> {
    let parsed = Url::parse(uri).map_err(|_| anyhow::anyhow!("invalid redirect_uri: {uri}"))?;

    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        bail!("redirect_uri scheme must be http or https: {uri}");
    }
    // RFC 6749 §3.1.2: redirect_uri MUST NOT include a fragment
    // component. Also, `build_redirect` would compose the response
    // URL incorrectly if a fragment were present.
    if parsed.fragment().is_some() {
        bail!("redirect_uri must not contain a fragment: {uri}");
    }
    if scheme == "http" {
        // Loopback only — this is the OAuth-spec carve-out for
        // native apps and dev clients. Anything else over plain
        // HTTP is rejected.
        //
        // Avoid string-based host comparison (it stumbles on
        // `[::1]` vs `::1`, percent-encoding, IDN). `Url::host()`
        // gives the structured host so IPv4/IPv6 loopback checks
        // delegate to the standard library.
        let is_loopback = match parsed.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if !is_loopback {
            bail!("redirect_uri uses plain http on non-loopback host: {uri}");
        }
    }

    // Defense in depth: every pattern must be well-formed even if
    // [`OAuthAsConfig::validate`] already vetted them at boot.
    for pattern in allowlist {
        validate_pattern(pattern)?;
    }

    if !allowlist.iter().any(|p| matches_pattern(uri, p)) {
        bail!("redirect_uri not in allowlist: {uri}");
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
    fn test_http_ipv6_loopback_allowed() {
        // Regression for code review on PR #91: `Url::host_str` returns
        // `"::1"` (no brackets) for `http://[::1]/...`, so an earlier
        // version that compared against `"[::1]"` would reject valid
        // IPv6 loopback redirects.
        let allow = vec!["http://[::1]:9000/cb".to_string()];
        assert!(validate("http://[::1]:9000/cb", &allow).is_ok());
    }

    #[test]
    fn test_redirect_uri_with_fragment_rejected() {
        // RFC 6749 §3.1.2: redirect_uri MUST NOT contain a fragment.
        let allow = vec!["https://example.com/cb".to_string()];
        let err = validate("https://example.com/cb#hash", &allow).unwrap_err();
        assert!(err.to_string().contains("fragment"));
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
