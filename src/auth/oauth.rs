use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use url::Url;

use super::hints;
use super::store::{self, to_stored_tokens};

const DEFAULT_CALLBACK_PORT_START: u16 = 8085;
const DEFAULT_CALLBACK_PORT_END: u16 = 8099;

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

    let client_id = match get_or_register_client(&key, &metadata, &redirect_uri).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = format!("{e:#}"), "OAuth registration not available");
            return hints::prompt_for_token(server_url);
        }
    };

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

    let code = wait_for_callback(listener, &state).await?;

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

    let mut auth_store = store::load_auth_store()?;
    auth_store.tokens.insert(key.clone(), tokens);
    store::save_auth_store(&auth_store)?;

    tracing::info!("authenticated successfully");
    Ok(access_token)
}

/// Try to refresh tokens. Returns new access token on success.
pub async fn try_refresh(server_key_str: &str, refresh_token: &str) -> Result<String> {
    let metadata = discover_auth_server(server_key_str).await?;
    let auth_store = store::load_auth_store()?;

    let reg = auth_store
        .clients
        .get(server_key_str)
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
    let well_known_url = format!("{auth_origin}/.well-known/oauth-authorization-server");
    let resp = http
        .get(&well_known_url)
        .header("MCP-Protocol-Version", "2025-03-26")
        .send()
        .await;

    if let Ok(resp) = resp {
        if resp.status().is_success() {
            if let Ok(metadata) = resp.json::<AuthServerMetadata>().await {
                return Ok(metadata);
            }
        }
    }

    Ok(AuthServerMetadata {
        authorization_endpoint: format!("{auth_origin}/authorize"),
        token_endpoint: format!("{auth_origin}/token"),
        registration_endpoint: Some(format!("{auth_origin}/register")),
        scopes_supported: vec![],
    })
}

// --- Client Registration ---

async fn get_or_register_client(
    server_key_str: &str,
    metadata: &AuthServerMetadata,
    redirect_uri: &str,
) -> Result<String> {
    let auth_store = store::load_auth_store()?;
    if let Some(reg) = auth_store.clients.get(server_key_str) {
        return Ok(reg.client_id.clone());
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
        "token_endpoint_auth_method": "none"
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

    let mut auth_store = store::load_auth_store()?;
    auth_store.clients.insert(
        server_key_str.to_string(),
        store::ClientRegistration {
            client_id: client_id.clone(),
            client_secret,
        },
    );
    store::save_auth_store(&auth_store)?;

    Ok(client_id)
}

// --- PKCE ---

fn generate_pkce() -> (String, String) {
    let verifier = generate_random_string(43);
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn generate_random_string(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
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

async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
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

    #[test]
    fn test_generate_pkce() {
        let (verifier, challenge) = generate_pkce();
        assert!(verifier.len() >= 43);
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let expected = URL_SAFE_NO_PAD.encode(hash);
        assert_eq!(challenge, expected);
    }

    #[test]
    fn test_generate_random_string() {
        let s = generate_random_string(32);
        assert_eq!(s.len(), 32);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));
    }

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
    }
}
