use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use url::Url;

use super::hints;
use super::oauth_primitives::{generate_pkce, generate_random_string};
use super::store::{self, to_stored_tokens};

const DEFAULT_CALLBACK_PORT_START: u16 = 8085;
const DEFAULT_CALLBACK_PORT_END: u16 = 8099;

/// MCP revision advertised to the authorization server's metadata endpoint.
///
/// Deliberately pinned, and deliberately *not* `protocol::PROTOCOL_VERSION`:
/// the peer here is an OAuth authorization server, not an MCP server, and
/// nothing in an RFC 8414 metadata response depends on our revision. An AS
/// that validates this header does so against the revisions it knows, so
/// advertising a newer one buys nothing and costs a `400` — after which
/// discovery silently degrades to guessed endpoints. `2025-03-26` is the
/// revision whose authorization spec introduced the header, and the value
/// this client has always sent.
const AS_METADATA_PROTOCOL_VERSION: &str = "2025-03-26";

fn parse_port_spec(val: &str) -> (u16, u16) {
    if val == "0" {
        return (0, 0);
    }
    if let Some((start, end)) = val.split_once('-') {
        if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
            if s <= e {
                return (s, e);
            }
        }
    }
    if let Ok(port) = val.parse::<u16>() {
        return (port, port);
    }
    (DEFAULT_CALLBACK_PORT_START, DEFAULT_CALLBACK_PORT_END)
}

fn callback_port_range() -> (u16, u16) {
    match std::env::var("MCP_OAUTH_CALLBACK_PORT") {
        Ok(val) => parse_port_spec(&val),
        Err(_) => (DEFAULT_CALLBACK_PORT_START, DEFAULT_CALLBACK_PORT_END),
    }
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthServerMetadata {
    /// RFC 8414 `issuer`. Mandatory in that RFC but missing from plenty of
    /// hand-rolled metadata documents, so discovery backfills the auth
    /// origin we derived. Two things depend on it: keying client
    /// registrations (SEP-2352) and validating the RFC 9207 `iss`
    /// authorization-response parameter.
    #[serde(default)]
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// Run the full OAuth 2.0 Authorization Code + PKCE flow.
pub async fn run_oauth_flow(server_url: &str) -> Result<String> {
    let key = store::server_key(server_url);

    tracing::info!(server = %key, "authenticating");

    let metadata = discover_auth_server(&key).await?;

    // Bind callback listener BEFORE client registration so the redirect_uri
    // in the registration request matches the actual port we're listening on.
    let (listener, port) = bind_callback_listener().await?;
    let redirect_uri = format!("http://localhost:{port}/callback");

    let client = match get_or_register_client(&key, &metadata, &redirect_uri).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = format!("{e:#}"), "OAuth registration not available");
            return hints::prompt_for_token(server_url);
        }
    };
    let client_id = client.registration.client_id.clone();

    let (code_verifier, code_challenge) = generate_pkce();
    let state = generate_random_string(32);

    let scopes = metadata.scopes_supported.join(" ");
    let mut auth_url = Url::parse(&metadata.authorization_endpoint)?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state);
    if !scopes.is_empty() {
        auth_url.query_pairs_mut().append_pair("scope", &scopes);
    }

    tracing::info!("opening browser for authorization");
    tracing::info!(url = %auth_url, "if browser doesn't open, visit this URL");
    let _ = open::that(auth_url.as_str());

    let code = wait_for_callback(listener, &state, &metadata.issuer).await?;

    tracing::info!("exchanging authorization code for tokens");
    let http = reqwest::Client::new();
    let resp = http
        .post(&metadata.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &code_verifier),
        ])
        .send()
        .await
        .context("token exchange request failed")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("token exchange failed: {text}");
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .context("failed to parse token response")?;
    let tokens = to_stored_tokens(&token_resp);
    let access_token = tokens.access_token.clone();

    // The exchange succeeded, so this issuer really is the authorization
    // server behind `key` — only now may a deferred legacy adoption touch
    // the store.
    let adopt = client
        .adopt_under_issuer
        .then_some(client.registration.clone());
    persist_flow_result(&key, &metadata.issuer, tokens, adopt)?;

    tracing::info!("authenticated successfully");
    Ok(access_token)
}

/// Persist what a successful flow produced: the tokens, plus any deferred
/// adoption of a pre-SEP-2352 credential under the now-proven issuer.
fn persist_flow_result(
    server_key_str: &str,
    issuer: &str,
    tokens: store::StoredTokens,
    adopt: Option<store::ClientRegistration>,
) -> Result<()> {
    let mut auth_store = store::load_auth_store()?;
    if let Some(reg) = adopt {
        auth_store.set_client(issuer, server_key_str, reg);
    }
    auth_store.tokens.insert(server_key_str.to_string(), tokens);
    store::save_auth_store(&auth_store)
}

/// Try to refresh tokens. Returns new access token on success.
pub async fn try_refresh(server_key_str: &str, refresh_token: &str) -> Result<String> {
    let metadata = discover_auth_server(server_key_str).await?;
    let auth_store = store::load_auth_store()?;

    // Same issuer binding as registration: a refresh must never be sent
    // with a client_id minted by a different authorization server.
    let reg = auth_store
        .client_for(&metadata.issuer, server_key_str)
        .context("no client registration found")?;

    let http = reqwest::Client::new();
    let resp = http
        .post(&metadata.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", reg.client_id.as_str()),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        bail!("token refresh failed: {}", resp.status());
    }

    let token_resp: TokenResponse = resp.json().await?;
    let tokens = to_stored_tokens(&token_resp);
    let access_token = tokens.access_token.clone();

    let mut auth_store = store::load_auth_store()?;
    auth_store.tokens.insert(server_key_str.to_string(), tokens);
    store::save_auth_store(&auth_store)?;

    Ok(access_token)
}

// --- Discovery ---

async fn discover_auth_server(server_url: &str) -> Result<AuthServerMetadata> {
    let http = reqwest::Client::new();
    let base = Url::parse(server_url)?;
    let origin = format!(
        "{}://{}",
        base.scheme(),
        base.host_str().unwrap_or("localhost")
    );

    let resource_url = format!("{origin}/.well-known/oauth-protected-resource");
    let auth_server_origin = if let Ok(resp) = http.get(&resource_url).send().await {
        if resp.status().is_success() {
            if let Ok(resource) = resp.json::<ProtectedResourceMetadata>().await {
                resource
                    .authorization_servers
                    .first()
                    .map(|s| s.trim_end_matches('/').to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let auth_origin = auth_server_origin.as_deref().unwrap_or(&origin);

    if let Some(metadata) = fetch_as_metadata(&http, auth_origin).await? {
        return Ok(metadata);
    }

    // Nothing usable came back, so guess RFC 8414's default endpoint layout
    // under the auth origin. `validated_issuer` still runs: an identifier
    // that normalizes to nothing is no identity at all, whichever path
    // produced it.
    Ok(AuthServerMetadata {
        issuer: validated_issuer("", auth_origin)?,
        authorization_endpoint: format!("{auth_origin}/authorize"),
        token_endpoint: format!("{auth_origin}/token"),
        registration_endpoint: Some(format!("{auth_origin}/register")),
        scopes_supported: vec![],
    })
}

/// RFC 8414 §3.3 — the `issuer` inside a metadata document MUST be identical
/// to the identifier used to build the well-known URL it was fetched from.
/// Returns the issuer to record for this authorization server.
///
/// Without this check the RFC 9207 `iss` comparison is self-referential: a
/// hostile MCP server names an authorization server of its choosing, that
/// server's document declares whatever issuer it likes, and the callback
/// echoes it back — every comparison passes. The same value is also the key
/// client registrations are filed under, so an unvalidated issuer is a write
/// primitive over another authorization server's stored registration.
///
/// An *absent* `issuer` is the legacy path: hand-rolled metadata documents
/// routinely omit the field and RFC 8414 leaves us no identity to reject on,
/// so those keep working under the origin we fetched from. A *present* and
/// different issuer is fatal.
fn validated_issuer(declared: &str, fetched_from: &str) -> Result<String> {
    // Normalize first, then require non-empty. `"/"` and `"///"` are
    // non-empty strings that normalize away to nothing: they collide with
    // every other empty issuer on the store key, and would let an `iss=`
    // callback pass as a match.
    let expected = store::issuer_key(fetched_from);
    if expected.is_empty() {
        bail!("authorization server identifier {fetched_from:?} is not a usable issuer");
    }

    if declared.is_empty() {
        return Ok(fetched_from.to_string());
    }
    if store::issuer_key(declared) != expected {
        bail!(
            "authorization server metadata declares issuer {declared:?} \
             but was fetched from {fetched_from:?}"
        );
    }
    Ok(declared.to_string())
}

/// Fetch and validate the RFC 8414 metadata document for `auth_origin`.
///
/// `Ok(None)` means the document was unreachable, rejected, or unreadable —
/// the caller degrades to guessed endpoints. `Err` means the document was
/// read and must not be used (issuer validation failed): degrading there
/// would hand the attacker the endpoints they wanted anyway.
async fn fetch_as_metadata(
    http: &reqwest::Client,
    auth_origin: &str,
) -> Result<Option<AuthServerMetadata>> {
    let well_known_url = format!("{auth_origin}/.well-known/oauth-authorization-server");
    let resp = http
        .get(&well_known_url)
        .header(
            crate::protocol::HEADER_MCP_PROTOCOL_VERSION,
            AS_METADATA_PROTOCOL_VERSION,
        )
        .send()
        .await;

    // Every degradation below is logged: falling back to fabricated
    // endpoints silently is how a plain `400` turns into an unexplained
    // authorization failure much later in the flow.
    match resp {
        Ok(resp) if resp.status().is_success() => match resp.json::<AuthServerMetadata>().await {
            Ok(mut metadata) => {
                metadata.issuer = validated_issuer(&metadata.issuer, auth_origin)?;
                Ok(Some(metadata))
            }
            Err(e) => {
                tracing::warn!(
                    url = %well_known_url,
                    error = %e,
                    "authorization server metadata is unreadable; guessing endpoints"
                );
                Ok(None)
            }
        },
        Ok(resp) => {
            tracing::warn!(
                url = %well_known_url,
                status = %resp.status(),
                "authorization server metadata request rejected; guessing endpoints"
            );
            Ok(None)
        }
        Err(e) => {
            tracing::warn!(
                url = %well_known_url,
                error = %e,
                "authorization server metadata unreachable; guessing endpoints"
            );
            Ok(None)
        }
    }
}

// --- Client Registration ---

/// Client credential to run a flow with.
#[derive(Debug)]
struct ResolvedClient {
    registration: store::ClientRegistration,
    /// Set when the credential came from the pre-SEP-2352 server-URL-keyed
    /// map, i.e. it still needs binding to an issuer. The binding is
    /// deferred to `persist_flow_result` — see `get_or_register_client`.
    adopt_under_issuer: bool,
}

async fn get_or_register_client(
    server_key_str: &str,
    metadata: &AuthServerMetadata,
    redirect_uri: &str,
) -> Result<ResolvedClient> {
    let auth_store = store::load_auth_store()?;
    if let Some(reg) = auth_store
        .client_for(&metadata.issuer, server_key_str)
        .cloned()
    {
        // A hit that fell through to the legacy server-URL-keyed map is a
        // credential we have no issuer for. It authenticates exactly as it
        // did before, but the store is NOT rewritten here: at this point
        // `metadata.issuer` is only a claim, and persisting it would let any
        // server that names an issuer overwrite that issuer's registration.
        // Adoption waits until the token exchange proves the claim.
        let adopt_under_issuer = !auth_store
            .clients
            .contains_key(&store::issuer_key(&metadata.issuer))
            && auth_store.legacy_clients.contains_key(server_key_str);
        return Ok(ResolvedClient {
            registration: reg,
            adopt_under_issuer,
        });
    }

    let reg_endpoint = metadata
        .registration_endpoint
        .as_deref()
        .context("server does not support dynamic client registration")?;

    let http = reqwest::Client::new();
    let body = serde_json::json!({
        "client_name": "mcp",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        // SEP-837: omitting this defaults to "web" under OIDC, which
        // forbids the http://localhost redirect this CLI listens on.
        // Non-OIDC authorization servers ignore the field.
        "application_type": "native"
    });

    let resp = http
        .post(reg_endpoint)
        .json(&body)
        .send()
        .await
        .context("client registration request failed")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("client registration failed: {text}");
    }

    let reg_resp: serde_json::Value = resp.json().await?;
    let client_id = reg_resp["client_id"]
        .as_str()
        .context("registration response missing client_id")?
        .to_string();

    let client_secret = reg_resp["client_secret"].as_str().map(|s| s.to_string());
    let registration = store::ClientRegistration {
        client_id,
        client_secret,
    };

    // A freshly minted credential is bound to the issuer that minted it, so
    // recording it now overwrites nothing: the lookup above already proved
    // this issuer had no registration.
    let mut auth_store = store::load_auth_store()?;
    auth_store.set_client(&metadata.issuer, server_key_str, registration.clone());
    store::save_auth_store(&auth_store)?;

    Ok(ResolvedClient {
        registration,
        adopt_under_issuer: false,
    })
}

// --- Callback server ---

async fn bind_callback_listener() -> Result<(TcpListener, u16)> {
    let (start, end) = callback_port_range();
    if start == 0 {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        return Ok((listener, port));
    }
    for port in start..=end {
        if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{port}")).await {
            return Ok((listener, port));
        }
    }
    bail!("could not bind to any port in range {start}-{end}");
}

/// RFC 9207 §2.4 — compare the `iss` authorization-response parameter
/// against the issuer recorded from this authorization server's validated
/// metadata document.
///
/// Byte-exact comparison of the form-urlencoded-decoded value. MCP
/// 2026-07-28 authorization: "Compare to the recorded issuer using simple
/// string comparison (RFC3986 Section 6.2.1)" and "clients MUST NOT apply
/// scheme or host case folding, default-port elision, trailing-slash, or
/// percent-encoding normalization (RFC 3986 Sections 6.2.2-6.2.3) before
/// comparison".
///
/// This is deliberately stricter than `store::issuer_key`, which keys stored
/// registrations: the spec constrains *that* only to "keyed by the
/// authorization server's `issuer` identifier", with no comparison rule, so
/// the store keeps absorbing a trailing slash and an auth.json written by an
/// earlier build keeps authenticating. The two rules are not the same rule.
///
/// An `expected` that carries no identity — empty, or only slashes — means
/// discovery never established an issuer, so there is nothing to validate
/// against and a present `iss` cannot be trusted. Without that guard a
/// recorded `"/"` would be matched by `iss=/`.
fn issuer_matches(received: &str, expected: &str) -> bool {
    !expected.trim_end_matches('/').is_empty() && received == expected
}

async fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
    expected_issuer: &str,
) -> Result<String> {
    let (mut stream, _) = listener
        .accept()
        .await
        .context("failed to accept callback connection")?;

    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .context("failed to read callback request")?;

    let request = String::from_utf8_lossy(&buf[..n]);

    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");

    let full_url = format!("http://localhost{path}");
    let url = Url::parse(&full_url)?;
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();

    if let Some(error) = params.get("error") {
        let desc = params.get("error_description").cloned().unwrap_or_default();
        send_callback_response(&mut stream, "Authorization failed. You can close this tab.").await;
        bail!("authorization error: {error} — {desc}");
    }

    let state = params
        .get("state")
        .context("callback missing state parameter")?;
    if state != expected_state {
        send_callback_response(
            &mut stream,
            "Authorization failed (invalid state). You can close this tab.",
        )
        .await;
        bail!("state mismatch in OAuth callback");
    }

    // RFC 9207: when the AS returns `iss` it MUST identify the AS we
    // started the flow with, otherwise the code may have been injected by
    // a different (attacker-controlled) AS — the mix-up attack. An absent
    // `iss` is the legacy path: authorization servers predating RFC 9207
    // never send it and must keep working.
    if let Some(iss) = params.get("iss") {
        if !issuer_matches(iss, expected_issuer) {
            send_callback_response(
                &mut stream,
                "Authorization failed (issuer mismatch). You can close this tab.",
            )
            .await;
            bail!("issuer mismatch in OAuth callback: expected {expected_issuer:?}, got {iss:?}");
        }
    }

    let code = params
        .get("code")
        .context("callback missing code parameter")?
        .to_string();

    send_callback_response(
        &mut stream,
        "Authorization successful! You can close this tab and return to the terminal.",
    )
    .await;

    Ok(code)
}

async fn send_callback_response(stream: &mut tokio::net::TcpStream, message: &str) {
    use tokio::io::AsyncWriteExt;
    let body = format!("<html><body><h2>{message}</h2></body></html>");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // PKCE / random-string tests live with the helpers in
    // `super::oauth_primitives` — see `src/auth/oauth_primitives.rs`.

    #[test]
    fn test_parse_port_spec_single_port() {
        assert_eq!(parse_port_spec("9000"), (9000, 9000));
    }

    #[test]
    fn test_parse_port_spec_range() {
        assert_eq!(parse_port_spec("9000-9010"), (9000, 9010));
    }

    #[test]
    fn test_parse_port_spec_os_assigned() {
        assert_eq!(parse_port_spec("0"), (0, 0));
    }

    #[test]
    fn test_parse_port_spec_invalid_fallback() {
        assert_eq!(
            parse_port_spec("not-a-port"),
            (DEFAULT_CALLBACK_PORT_START, DEFAULT_CALLBACK_PORT_END)
        );
    }

    #[test]
    fn test_parse_port_spec_inverted_range_fallback() {
        // end < start should fall back to defaults
        assert_eq!(
            parse_port_spec("9010-9000"),
            (DEFAULT_CALLBACK_PORT_START, DEFAULT_CALLBACK_PORT_END)
        );
    }

    #[test]
    fn test_auth_server_metadata_deserialization() {
        let json = serde_json::json!({
            "authorization_endpoint": "https://mcp.sentry.dev/oauth/authorize",
            "token_endpoint": "https://mcp.sentry.dev/oauth/token",
            "registration_endpoint": "https://mcp.sentry.dev/oauth/register",
            "scopes_supported": ["org:read", "project:write"]
        });
        let metadata: AuthServerMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(
            metadata.authorization_endpoint,
            "https://mcp.sentry.dev/oauth/authorize"
        );
        assert_eq!(metadata.scopes_supported.len(), 2);
        // No `issuer` in the document: discovery backfills the auth origin,
        // so at parse time the field is simply empty.
        assert!(metadata.issuer.is_empty());
    }

    #[test]
    fn test_auth_server_metadata_reads_issuer() {
        let json = serde_json::json!({
            "issuer": "https://auth.sentry.dev",
            "authorization_endpoint": "https://mcp.sentry.dev/oauth/authorize",
            "token_endpoint": "https://mcp.sentry.dev/oauth/token"
        });
        let metadata: AuthServerMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(metadata.issuer, "https://auth.sentry.dev");
    }

    // --- RFC 9207 `iss` validation ---

    #[test]
    fn test_issuer_matches_only_on_byte_exact_equality() {
        // The only accepted case: the decoded `iss` is the recorded issuer,
        // byte for byte. Every spelling below is fine *because both sides
        // agree* — none of them is normalized into agreement.
        for issuer in [
            "https://as.example.com",
            "https://as.example.com/",
            "https://as.example.com:443",
            "https://as.example.com/tenant1",
            "https://AS.example.com",
            "https://as.example%2Ecom",
            "https://as.exämple.com",
        ] {
            assert!(
                issuer_matches(issuer, issuer),
                "iss {issuer:?} must match itself"
            );
        }
    }

    #[test]
    fn test_issuer_matches_applies_no_rfc3986_normalization() {
        // MCP 2026-07-28: clients "MUST NOT apply scheme or host case
        // folding, default-port elision, trailing-slash, or percent-encoding
        // normalization ... before comparison". Each pair below is equal
        // under one of those normalizations and must still be rejected — in
        // both directions, since a client that normalizes does so on the
        // received value, the recorded one, or both.
        for (a, b) in [
            // trailing slash
            ("https://as.example.com/", "https://as.example.com"),
            (
                "https://as.example.com/tenant1/",
                "https://as.example.com/tenant1",
            ),
            // scheme / host case folding
            ("https://AS.example.com", "https://as.example.com"),
            ("HTTPS://as.example.com", "https://as.example.com"),
            // default-port elision
            ("https://as.example.com:443", "https://as.example.com"),
            ("http://as.example.com:80", "http://as.example.com"),
            // percent-encoding
            ("https://as.example%2Ecom", "https://as.example.com"),
            ("https://as.example.com/a%2Fb", "https://as.example.com/a/b"),
            (
                "https://as.example.com/%7Euser",
                "https://as.example.com/~user",
            ),
            // unicode: percent-encoded UTF-8 and punycode are the same host
            // after normalization, and must not be treated as such here
            ("https://as.exämple.com", "https://as.ex%C3%A4mple.com"),
            ("https://as.exämple.com", "https://as.xn--exmple-cua.com"),
        ] {
            assert!(
                !issuer_matches(a, b),
                "iss {a:?} must be rejected against {b:?}"
            );
            assert!(
                !issuer_matches(b, a),
                "iss {b:?} must be rejected against {a:?}"
            );
        }
    }

    #[test]
    fn test_issuer_matches_rejects_every_other_difference() {
        // Each of these is a distinct authorization server. Accepting any
        // of them would reopen the RFC 9207 mix-up attack.
        let expected = "https://as.example.com";
        for received in [
            "https://evil.example.com",
            "http://as.example.com",                    // downgraded scheme
            "https://AS.example.com",                   // case
            "https://as.example.com/tenant",            // extra path
            "https://as.example.com.evil.test",         // suffix
            "https://evil.test/https://as.example.com", // embedded
            "https://аs.example.com",                   // cyrillic homoglyph
            " https://as.example.com",                  // leading whitespace
            "",                                         // empty value
        ] {
            assert!(
                !issuer_matches(received, expected),
                "iss {received:?} must be rejected against {expected:?}"
            );
        }
    }

    #[test]
    fn test_issuer_matches_rejects_when_no_issuer_was_recorded() {
        // Discovery failed to establish an issuer — there is nothing to
        // validate against, so a present `iss` cannot be trusted.
        assert!(!issuer_matches("https://as.example.com", ""));
        assert!(!issuer_matches("", ""));
    }

    #[test]
    fn test_issuer_matches_rejects_expected_issuers_that_carry_no_identity() {
        // `"/"` is a non-empty string that identifies no authorization
        // server. Byte-exact comparison alone would let a recorded `"/"` be
        // matched by `iss=/`, so the "was an issuer ever recorded?" guard
        // has to look past the slashes.
        for expected in ["/", "//", "///"] {
            for received in ["", "/", "///", "https://as.example.com"] {
                assert!(
                    !issuer_matches(received, expected),
                    "iss {received:?} must be rejected against expected {expected:?}"
                );
            }
        }
    }

    // --- RFC 8414 §3.3 metadata issuer validation ---

    #[test]
    fn test_validated_issuer_accepts_a_document_that_names_its_own_origin() {
        assert_eq!(
            validated_issuer("https://as.example.com", "https://as.example.com").unwrap(),
            "https://as.example.com"
        );
        // A trailing slash on either side is the one difference RFC 8414
        // issuers routinely disagree on; `issuer_key` absorbs it.
        assert!(validated_issuer("https://as.example.com/", "https://as.example.com").is_ok());
        assert!(validated_issuer("https://as.example.com", "https://as.example.com/").is_ok());
    }

    #[test]
    fn test_validated_issuer_backfills_a_document_that_omits_it() {
        // Backwards compat: hand-rolled metadata documents routinely omit
        // `issuer`. RFC 8414 leaves nothing to reject on, so those keep
        // working under the origin they were fetched from.
        assert_eq!(
            validated_issuer("", "https://as.example.com").unwrap(),
            "https://as.example.com"
        );
    }

    #[test]
    fn test_validated_issuer_rejects_a_document_naming_someone_else() {
        // The spec's own example: a document served by the attacker that
        // claims to be the honest authorization server.
        let err = validated_issuer("https://honest.example", "https://attacker.example")
            .unwrap_err()
            .to_string();
        assert!(err.contains("honest.example"), "unexpected error: {err}");
        assert!(err.contains("attacker.example"), "unexpected error: {err}");
    }

    #[test]
    fn test_validated_issuer_rejects_every_near_miss() {
        // Anything but a trailing slash identifies a different AS. Accepting
        // one would make the RFC 9207 `iss` check self-referential and hand
        // over the store key another issuer's registration lives under.
        let fetched_from = "https://as.example.com";
        for declared in [
            "https://evil.example.com",
            "http://as.example.com",                    // downgraded scheme
            "https://AS.example.com",                   // case folding
            "https://as.example.com/tenant",            // extra path
            "https://as.example.com.evil.test",         // suffix
            "https://as.example.com:443",               // default-port elision
            "https://evil.test/https://as.example.com", // embedded
            "https://аs.example.com",                   // cyrillic homoglyph
            "https://as.example%2Ecom",                 // percent encoding
            " https://as.example.com",                  // leading whitespace
            "https://as.example.com ",                  // trailing whitespace
        ] {
            assert!(
                validated_issuer(declared, fetched_from).is_err(),
                "issuer {declared:?} must be rejected for a document from {fetched_from:?}"
            );
        }
    }

    #[test]
    fn test_validated_issuer_rejects_identifiers_that_normalize_to_empty() {
        // These reach us from the MCP server's own protected-resource
        // document, so they are attacker-controlled. An issuer that
        // normalizes to nothing is no identity: it collides with every
        // other empty issuer on the store key.
        for fetched_from in ["", "/", "//", "///"] {
            assert!(
                validated_issuer("", fetched_from).is_err(),
                "auth origin {fetched_from:?} must not be usable as an issuer"
            );
            assert!(
                validated_issuer("https://as.example.com", fetched_from).is_err(),
                "auth origin {fetched_from:?} must not validate any declared issuer"
            );
        }
        // ...and neither may the document declare one.
        assert!(validated_issuer("/", "https://as.example.com").is_err());
    }

    // --- Authorization server metadata fetch ---

    /// Canned RFC 8414 metadata endpoint, so discovery can be exercised over
    /// a real HTTP round trip.
    struct FakeAs {
        base: String,
        /// `MCP-Protocol-Version` value the AS saw on the last request.
        seen_version: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        _shutdown: tokio::sync::oneshot::Sender<()>,
    }

    /// Serve `body(base)` from `/.well-known/oauth-authorization-server`.
    /// The body is built from the bound base URL so a document can name the
    /// very origin it is served from.
    async fn start_fake_as(
        status: axum::http::StatusCode,
        body: impl FnOnce(&str) -> String,
    ) -> FakeAs {
        use axum::{extract::State, http::HeaderMap, response::IntoResponse, routing::get, Router};

        #[derive(Clone)]
        struct S {
            status: axum::http::StatusCode,
            body: String,
            seen: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        }

        async fn well_known(State(s): State<S>, headers: HeaderMap) -> impl IntoResponse {
            *s.seen.lock().unwrap() = headers
                .get(crate::protocol::HEADER_MCP_PROTOCOL_VERSION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            (
                s.status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                s.body.clone(),
            )
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let app = Router::new()
            .route("/.well-known/oauth-authorization-server", get(well_known))
            .with_state(S {
                status,
                body: body(&base),
                seen: seen.clone(),
            });

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .ok();
        });

        FakeAs {
            base,
            seen_version: seen,
            _shutdown: tx,
        }
    }

    /// RFC 8414 document declaring `issuer` (when `Some`) and endpoints
    /// under `base`.
    fn as_document(issuer: Option<&str>, base: &str) -> String {
        let mut doc = serde_json::json!({
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
        });
        if let Some(issuer) = issuer {
            doc["issuer"] = serde_json::json!(issuer);
        }
        doc.to_string()
    }

    #[tokio::test]
    async fn test_as_metadata_naming_its_own_origin_is_accepted() {
        let fake = start_fake_as(axum::http::StatusCode::OK, |base| {
            as_document(Some(base), base)
        })
        .await;

        let metadata = fetch_as_metadata(&reqwest::Client::new(), &fake.base)
            .await
            .unwrap()
            .expect("a document naming its own origin is valid");
        assert_eq!(metadata.issuer, fake.base);
    }

    #[tokio::test]
    async fn test_as_metadata_with_a_foreign_issuer_is_fatal() {
        // The document is served by 127.0.0.1 but claims to be
        // `https://honest.example`. RFC 8414 §3.3 says it MUST NOT be used —
        // and degrading to guessed endpoints would hand over the very
        // endpoints the attacker wanted, so this is an error, not a
        // fallback.
        let fake = start_fake_as(axum::http::StatusCode::OK, |_| {
            as_document(Some("https://honest.example"), "https://honest.example")
        })
        .await;

        let err = fetch_as_metadata(&reqwest::Client::new(), &fake.base)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("honest.example"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_as_metadata_without_an_issuer_is_backfilled() {
        // Backwards compat: a document that omits `issuer` still works, and
        // the origin it came from becomes the recorded issuer.
        let fake = start_fake_as(axum::http::StatusCode::OK, |_| {
            as_document(None, "https://as.example.com")
        })
        .await;

        let metadata = fetch_as_metadata(&reqwest::Client::new(), &fake.base)
            .await
            .unwrap()
            .expect("document should be usable");
        assert_eq!(metadata.issuer, fake.base);
        assert_eq!(metadata.token_endpoint, "https://as.example.com/token");
    }

    #[tokio::test]
    async fn test_as_metadata_rejection_degrades_to_guessed_endpoints() {
        // An AS answering 4xx is not an attack, just a server that dislikes
        // the request. Keep the pre-existing fallback — but the caller must
        // be told it happened rather than reading `Err`.
        let fake = start_fake_as(axum::http::StatusCode::BAD_REQUEST, |_| "{}".to_string()).await;
        assert!(fetch_as_metadata(&reqwest::Client::new(), &fake.base)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_as_metadata_unreadable_body_degrades_to_guessed_endpoints() {
        let fake = start_fake_as(axum::http::StatusCode::OK, |_| {
            "not json at all".to_string()
        })
        .await;
        assert!(fetch_as_metadata(&reqwest::Client::new(), &fake.base)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_as_metadata_request_pins_the_protocol_version_header() {
        // Sending the current MCP revision gets a strict AS to answer 400,
        // which silently degraded discovery to fabricated endpoints. The
        // header is pinned to the revision that defined it.
        let fake = start_fake_as(axum::http::StatusCode::OK, |_| {
            as_document(None, "https://as.example.com")
        })
        .await;
        let _ = fetch_as_metadata(&reqwest::Client::new(), &fake.base).await;

        assert_eq!(
            fake.seen_version.lock().unwrap().as_deref(),
            Some(AS_METADATA_PROTOCOL_VERSION)
        );
        assert_ne!(
            AS_METADATA_PROTOCOL_VERSION,
            crate::protocol::PROTOCOL_VERSION
        );
    }

    // --- Deferred adoption of pre-SEP-2352 credentials ---

    /// Point the auth store at a temp `auth.json` holding `content`.
    /// Caller must hold `store::ENV_LOCK` and an `EnvGuard`.
    fn auth_file(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, content).unwrap();
        std::env::remove_var(store::AUTH_CONFIG_ENV);
        std::env::set_var(store::AUTH_PATH_ENV, path.to_str().unwrap());
        (dir, path)
    }

    fn metadata_for(issuer: &str) -> AuthServerMetadata {
        AuthServerMetadata {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            // `None` keeps every test below off the network: a miss fails
            // instead of attempting dynamic client registration.
            registration_endpoint: None,
            scopes_supported: vec![],
        }
    }

    /// Run `fut` on a private current-thread runtime. Plain `#[test]` (not
    /// `#[tokio::test]`) so the env lock is never held across an `.await`.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    const LEGACY_STORE: &str =
        r#"{"clients":{"https://mcp.example.com":{"client_id":"cid-legacy"}},"tokens":{}}"#;

    #[test]
    fn test_legacy_credential_authenticates_without_touching_the_store() {
        // Two guarantees at once. Compat: an auth.json written by a
        // pre-SEP-2352 build still yields its credential, no user action.
        // Security: nothing is written back, because at this point the
        // issuer is only a claim by the MCP server — persisting it would let
        // any server overwrite that issuer's stored registration.
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        let (_dir, path) = auth_file(LEGACY_STORE);
        let before = std::fs::read(&path).unwrap();

        let resolved = block_on(get_or_register_client(
            "https://mcp.example.com",
            &metadata_for("https://attacker.example"),
            "http://localhost:8085/callback",
        ))
        .unwrap();

        assert_eq!(resolved.registration.client_id, "cid-legacy");
        assert!(resolved.adopt_under_issuer);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "an unproven issuer must not mutate the auth store"
        );
    }

    #[test]
    fn test_inline_deployments_also_defer_adoption() {
        // `MCP_AUTH_CONFIG` re-seeds — and re-migrates — the store on every
        // process start, so for those deployments the legacy fallback is
        // live on every run rather than once. An unproven issuer must not
        // rewrite the in-memory store either.
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        std::env::remove_var(store::AUTH_PATH_ENV);
        std::env::set_var(store::AUTH_CONFIG_ENV, LEGACY_STORE);

        let resolved = block_on(get_or_register_client(
            "https://mcp.example.com",
            &metadata_for("https://attacker.example"),
            "http://localhost:8085/callback",
        ))
        .unwrap();
        assert_eq!(resolved.registration.client_id, "cid-legacy");

        let after = store::load_auth_store().unwrap();
        assert!(
            after.clients.is_empty(),
            "an unproven issuer must not be recorded"
        );
        assert_eq!(
            after.legacy_clients["https://mcp.example.com"].client_id,
            "cid-legacy"
        );
    }

    #[test]
    fn test_issuer_keyed_credential_is_not_flagged_for_adoption() {
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        let (_dir, _path) = auth_file(
            r#"{"version":1,"clients":{"https://as.example.com":{"client_id":"cid-bound"}},"tokens":{}}"#,
        );

        let resolved = block_on(get_or_register_client(
            "https://mcp.example.com",
            &metadata_for("https://as.example.com"),
            "http://localhost:8085/callback",
        ))
        .unwrap();

        assert_eq!(resolved.registration.client_id, "cid-bound");
        assert!(!resolved.adopt_under_issuer);
    }

    #[test]
    fn test_no_credential_is_handed_to_a_server_it_was_not_written_for() {
        // Bypass attempt: the legacy map is keyed by MCP server URL, so a
        // second server must not inherit the first one's credential — with
        // or without a matching issuer claim.
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        let (_dir, _path) = auth_file(LEGACY_STORE);

        for issuer in ["https://as.example.com", "https://mcp.example.com"] {
            let err = block_on(get_or_register_client(
                "https://other.example.com",
                &metadata_for(issuer),
                "http://localhost:8085/callback",
            ))
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("dynamic client registration"),
                "unexpected error for issuer {issuer:?}: {err}"
            );
        }
    }

    #[test]
    fn test_issuer_keyed_credential_never_crosses_issuers() {
        // Privilege escalation attempt: AS-B claims the flow, AS-A's
        // credential must stay put.
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        let (_dir, _path) = auth_file(
            r#"{"version":1,"clients":{"https://as-a.example.com":{"client_id":"cid-a"}},"tokens":{}}"#,
        );

        let err = block_on(get_or_register_client(
            "https://mcp.example.com",
            &metadata_for("https://as-b.example.com"),
            "http://localhost:8085/callback",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("dynamic client registration"), "got: {err}");
    }

    fn tokens(access: &str) -> store::StoredTokens {
        store::StoredTokens {
            access_token: access.to_string(),
            refresh_token: None,
            expires_at: None,
        }
    }

    #[test]
    fn test_persist_adopts_the_legacy_credential_once_the_exchange_succeeds() {
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        let (_dir, _path) = auth_file(LEGACY_STORE);

        persist_flow_result(
            "https://mcp.example.com",
            "https://as.example.com",
            tokens("tok"),
            Some(store::ClientRegistration {
                client_id: "cid-legacy".to_string(),
                client_secret: None,
            }),
        )
        .unwrap();

        let reloaded = store::load_auth_store().unwrap();
        assert_eq!(
            reloaded.clients["https://as.example.com"].client_id,
            "cid-legacy"
        );
        assert!(reloaded.legacy_clients.is_empty());
        assert_eq!(
            reloaded.tokens["https://mcp.example.com"].access_token,
            "tok"
        );
        // Now bound: a different AS forces a fresh registration.
        assert!(reloaded
            .client_for("https://as-b.example.com", "https://mcp.example.com")
            .is_none());
    }

    #[test]
    fn test_persist_without_adoption_leaves_registrations_untouched() {
        let _lock = store::ENV_LOCK.lock().unwrap();
        let _guard = store::EnvGuard::capture();
        let (_dir, _path) = auth_file(LEGACY_STORE);

        persist_flow_result(
            "https://mcp.example.com",
            "https://as.example.com",
            tokens("tok"),
            None,
        )
        .unwrap();

        let reloaded = store::load_auth_store().unwrap();
        assert!(reloaded.clients.is_empty());
        assert_eq!(
            reloaded.legacy_clients["https://mcp.example.com"].client_id,
            "cid-legacy"
        );
        assert_eq!(
            reloaded.tokens["https://mcp.example.com"].access_token,
            "tok"
        );
    }

    /// Drive `wait_for_callback` over a real loopback socket with the
    /// given callback query string.
    async fn callback_with(
        query: &str,
        expected_state: &str,
        expected_issuer: &str,
    ) -> Result<String> {
        use tokio::io::AsyncWriteExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let query = query.to_string();
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let req = format!("GET /callback?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            stream.write_all(req.as_bytes()).await.unwrap();
            // Hold the connection open until the CLI replies, otherwise
            // the write side closes before it can respond.
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink).await;
        });

        wait_for_callback(listener, expected_state, expected_issuer).await
    }

    #[tokio::test]
    async fn test_callback_accepts_matching_iss() {
        let code = callback_with(
            "code=the-code&state=st&iss=https%3A%2F%2Fas.example.com",
            "st",
            "https://as.example.com",
        )
        .await
        .unwrap();
        assert_eq!(code, "the-code");
    }

    #[tokio::test]
    async fn test_callback_accepts_absent_iss() {
        // Backwards compat: authorization servers predating RFC 9207 never
        // send `iss`. Absence is the legacy path, never an error.
        let code = callback_with("code=the-code&state=st", "st", "https://as.example.com")
            .await
            .unwrap();
        assert_eq!(code, "the-code");
    }

    #[tokio::test]
    async fn test_callback_rejects_mismatched_iss() {
        let err = callback_with(
            "code=the-code&state=st&iss=https%3A%2F%2Fevil.example.com",
            "st",
            "https://as.example.com",
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("issuer mismatch"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_callback_rejects_iss_differing_only_by_normalization() {
        // End to end, after form-urlencoded decoding: a trailing slash, a
        // default port and a case-folded host are each a mismatch. The
        // decision lands in `wait_for_callback`, not just in the helper.
        for iss in [
            "https%3A%2F%2Fas.example.com%2F",
            "https%3A%2F%2Fas.example.com%3A443",
            "https%3A%2F%2FAS.example.com",
        ] {
            let err = callback_with(
                &format!("code=the-code&state=st&iss={iss}"),
                "st",
                "https://as.example.com",
            )
            .await
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("issuer mismatch"),
                "iss {iss:?} must be rejected: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn test_callback_rejects_empty_iss() {
        // `?iss=` is malformed, not absent — it must not be waved through.
        let err = callback_with(
            "code=the-code&state=st&iss=",
            "st",
            "https://as.example.com",
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("issuer mismatch"));
    }

    #[tokio::test]
    async fn test_callback_rejects_iss_when_issuer_unknown() {
        let err = callback_with(
            "code=the-code&state=st&iss=https%3A%2F%2Fas.example.com",
            "st",
            "",
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("issuer mismatch"));
    }

    #[tokio::test]
    async fn test_callback_rejects_state_mismatch_before_looking_at_iss() {
        // Regression guard: adding the `iss` check must not weaken the
        // pre-existing CSRF binding on `state`.
        let err = callback_with(
            "code=the-code&state=attacker&iss=https%3A%2F%2Fas.example.com",
            "st",
            "https://as.example.com",
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("state mismatch"));
    }

    #[tokio::test]
    async fn test_callback_rejects_error_response() {
        let err = callback_with(
            "error=access_denied&state=st",
            "st",
            "https://as.example.com",
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("access_denied"));
    }

    #[tokio::test]
    async fn test_callback_rejects_missing_code_with_valid_iss() {
        let err = callback_with(
            "state=st&iss=https%3A%2F%2Fas.example.com",
            "st",
            "https://as.example.com",
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("missing code"));
    }
}
