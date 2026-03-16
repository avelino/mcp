mod hints;
pub mod oauth;
pub mod store;

use anyhow::{Context, Result};
use store::{server_key, load_auth_store};

/// Get a saved token without triggering any OAuth flow.
pub fn get_saved_token(server_url: &str) -> Result<String> {
    let key = server_key(server_url);
    let auth_store = load_auth_store()?;
    let tokens = auth_store
        .tokens
        .get(&key)
        .context("no saved token")?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expired = tokens.expires_at.is_some_and(|exp| now >= exp);
    if expired {
        anyhow::bail!("token expired");
    }

    Ok(tokens.access_token.clone())
}

/// Get a valid access token for the server, running OAuth flow if needed.
pub async fn get_token(server_url: &str) -> Result<String> {
    let key = server_key(server_url);

    let auth_store = load_auth_store()?;
    if let Some(tokens) = auth_store.tokens.get(&key) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired = tokens.expires_at.is_some_and(|exp| now >= exp);

        if !expired {
            return Ok(tokens.access_token.clone());
        }

        if let Some(ref refresh_token) = tokens.refresh_token {
            if let Ok(access_token) = oauth::try_refresh(&key, refresh_token).await {
                return Ok(access_token);
            }
        }
    }

    oauth::run_oauth_flow(server_url).await
}
