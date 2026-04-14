use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::auth;
use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

use super::Transport;

pub struct HttpTransport {
    client: Client,
    url: String,
    /// Headers can be mutated on 401 retry (we strip stale Authorization).
    headers: Mutex<HashMap<String, String>>,
    session_id: Mutex<Option<String>>,
    bearer_token: Mutex<Option<String>>,
}

impl HttpTransport {
    pub fn new(url: &str, headers: &HashMap<String, String>) -> Result<Self> {
        let timeout_secs: u64 = std::env::var("MCP_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        Ok(Self {
            client,
            url: url.to_string(),
            headers: Mutex::new(headers.clone()),
            session_id: Mutex::new(None),
            bearer_token: Mutex::new(None),
        })
    }

    /// Load any previously saved token (does NOT trigger OAuth flow).
    pub fn load_saved_token(&self) {
        if self.has_valid_auth_header() || self.bearer_token.lock().unwrap().is_some() {
            return;
        }
        if let Ok(token) = auth::get_saved_token(&self.url) {
            *self.bearer_token.lock().unwrap() = Some(token);
        }
    }

    fn has_valid_auth_header(&self) -> bool {
        let headers = self.headers.lock().unwrap();
        for key in ["Authorization", "authorization"] {
            if let Some(val) = headers.get(key) {
                let token_part = val.strip_prefix("Bearer ").unwrap_or(val);
                if !token_part.trim().is_empty() {
                    return true;
                }
            }
        }
        false
    }

    fn build_request(&self, body: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        {
            let headers = self.headers.lock().unwrap();
            for (key, value) in headers.iter() {
                // Skip empty auth headers (unset env vars)
                if key.eq_ignore_ascii_case("authorization") {
                    let token_part = value.strip_prefix("Bearer ").unwrap_or(value);
                    if token_part.trim().is_empty() {
                        continue;
                    }
                }
                req = req.header(key, value);
            }
        }

        // Add bearer token if we have one and no valid user-provided Authorization
        if !self.has_valid_auth_header() {
            if let Some(ref token) = *self.bearer_token.lock().unwrap() {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
        }

        if let Some(ref session_id) = *self.session_id.lock().unwrap() {
            req = req.header("Mcp-Session-Id", session_id);
        }

        req.body(body.to_string())
    }

    fn capture_session_id(&self, resp: &reqwest::Response) {
        if let Some(session_id) = resp.headers().get("mcp-session-id") {
            *self.session_id.lock().unwrap() =
                Some(session_id.to_str().unwrap_or_default().to_string());
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        let body = serde_json::to_string(msg)?;

        let resp = self
            .build_request(&body)
            .send()
            .await
            .context("failed to send HTTP request")?;

        self.capture_session_id(&resp);
        let status = resp.status();

        // Handle 401: try OAuth and retry once
        if status == reqwest::StatusCode::UNAUTHORIZED {
            if self.has_valid_auth_header() {
                tracing::warn!("server returned 401 — token may be expired or invalid");
            }
            tracing::info!("starting authentication");
            // Clear config auth header so OAuth token takes precedence on retry
            {
                let mut headers = self.headers.lock().unwrap();
                headers.remove("Authorization");
                headers.remove("authorization");
            }
            *self.bearer_token.lock().unwrap() = None;
            let token = auth::get_token(&self.url).await?;
            *self.bearer_token.lock().unwrap() = Some(token);

            // Retry request with new token
            let resp = self
                .build_request(&body)
                .send()
                .await
                .context("failed to retry HTTP request after auth")?;

            self.capture_session_id(&resp);
            let status = resp.status();
            let text = resp.text().await.context("failed to read HTTP response")?;

            if !status.is_success() {
                bail!("HTTP error {status}: {text}");
            }

            return parse_response(&text);
        }

        let text = resp.text().await.context("failed to read HTTP response")?;

        if !status.is_success() {
            bail!("HTTP error {status}: {text}");
        }

        parse_response(&text)
    }

    async fn notify(&self, msg: &JsonRpcNotification) -> Result<()> {
        let body = serde_json::to_string(msg)?;
        let resp = self
            .build_request(&body)
            .send()
            .await
            .context("failed to send HTTP notification")?;

        self.capture_session_id(&resp);
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn parse_response(text: &str) -> Result<JsonRpcResponse> {
    if text.starts_with("data:") || text.contains("\ndata:") {
        let last_data = text
            .lines()
            .rev()
            .find(|l| l.starts_with("data:"))
            .context("no data in SSE response")?;
        let json = last_data.trim_start_matches("data:").trim();
        serde_json::from_str(json).context("failed to parse SSE JSON response")
    } else {
        serde_json::from_str(text).context("failed to parse JSON response")
    }
}
