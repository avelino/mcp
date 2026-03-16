use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;

use crate::auth;
use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

use super::Transport;

pub struct HttpTransport {
    client: Client,
    url: String,
    headers: HashMap<String, String>,
    session_id: Option<String>,
    bearer_token: Option<String>,
}

impl HttpTransport {
    pub fn new(url: &str, headers: &HashMap<String, String>) -> Result<Self> {
        let client = Client::new();
        Ok(Self {
            client,
            url: url.to_string(),
            headers: headers.clone(),
            session_id: None,
            bearer_token: None,
        })
    }

    /// Load any previously saved token (does NOT trigger OAuth flow).
    pub fn load_saved_token(&mut self) {
        if self.has_valid_auth_header() || self.bearer_token.is_some() {
            return;
        }
        if let Ok(token) = auth::get_saved_token(&self.url) {
            self.bearer_token = Some(token);
        }
    }

    fn has_valid_auth_header(&self) -> bool {
        for key in ["Authorization", "authorization"] {
            if let Some(val) = self.headers.get(key) {
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

        for (key, value) in &self.headers {
            // Skip empty auth headers (unset env vars)
            if key.eq_ignore_ascii_case("authorization") {
                let token_part = value.strip_prefix("Bearer ").unwrap_or(value);
                if token_part.trim().is_empty() {
                    continue;
                }
            }
            req = req.header(key, value);
        }

        // Add bearer token if we have one and no valid user-provided Authorization
        if !self.has_valid_auth_header() {
            if let Some(ref token) = self.bearer_token {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
        }

        if let Some(ref session_id) = self.session_id {
            req = req.header("Mcp-Session-Id", session_id);
        }

        req.body(body.to_string())
    }

    fn capture_session_id(&mut self, resp: &reqwest::Response) {
        if let Some(session_id) = resp.headers().get("mcp-session-id") {
            self.session_id = Some(session_id.to_str().unwrap_or_default().to_string());
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(&mut self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
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
                eprintln!("Server returned 401 — token from config may be expired or invalid.");
            }
            eprintln!("Starting authentication...");
            // Clear config auth header so OAuth token takes precedence on retry
            self.headers.remove("Authorization");
            self.headers.remove("authorization");
            self.bearer_token = None;
            let token = auth::get_token(&self.url).await?;
            self.bearer_token = Some(token);

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

    async fn notify(&mut self, msg: &JsonRpcNotification) -> Result<()> {
        let body = serde_json::to_string(msg)?;
        let resp = self
            .build_request(&body)
            .send()
            .await
            .context("failed to send HTTP notification")?;

        self.capture_session_id(&resp);
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
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
