use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::auth;
use crate::protocol::{
    self, header_value, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, HEADER_MCP_METHOD,
    HEADER_MCP_NAME, HEADER_MCP_PROTOCOL_VERSION,
};

use super::Transport;

/// The 2026-07-28 request-metadata headers for one outgoing message.
///
/// Grouped rather than passed as five positional arguments because they are
/// all derived from the same message and are only ever set together.
struct RequestMeta<'a> {
    method: &'a str,
    /// `params.name` / `params.uri` — absent for methods addressing no single
    /// primitive.
    name: Option<&'a str>,
    /// Value of `_meta`'s `io.modelcontextprotocol/protocolVersion`, read from
    /// the body we are about to send. `None` on the legacy path.
    protocol_version: Option<&'a str>,
    /// Already-encoded `Mcp-Param-{Name}` headers from `x-mcp-header`.
    params: &'a [(String, String)],
}

impl<'a> RequestMeta<'a> {
    /// Derive the metadata headers from a request body.
    fn of(method: &'a str, params: Option<&'a Value>, name: Option<&'a str>) -> Self {
        Self {
            method,
            name,
            protocol_version: protocol::request_protocol_version(params),
            params: &[],
        }
    }
}

pub struct HttpTransport {
    client: Client,
    url: String,
    /// Headers can be mutated on 401 retry (we strip stale Authorization).
    headers: Mutex<HashMap<String, String>>,
    session_id: Mutex<Option<String>>,
    bearer_token: Mutex<Option<String>>,
    /// Set once the client negotiates a revision. `false` until then, so an
    /// un-negotiated transport behaves exactly like it did pre-2026-07-28.
    stateless: AtomicBool,
}

impl HttpTransport {
    pub fn new(url: &str, headers: &HashMap<String, String>) -> Result<Self> {
        let timeout_secs: u64 = std::env::var("MCP_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            // An MCP endpoint answers JSON-RPC directly; it never redirects.
            // A 3xx here is an auth gateway (Cloudflare Access, an SSO proxy)
            // bouncing us to a login page. Following it lands on a 200 full of
            // HTML, which used to surface as "failed to parse JSON response:
            // expected value at line 1 column 1" — true, useless, and several
            // layers away from "your VPN is disconnected". Stop at the
            // redirect so the error can say what actually happened.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url: url.to_string(),
            headers: Mutex::new(headers.clone()),
            session_id: Mutex::new(None),
            bearer_token: Mutex::new(None),
            stateless: AtomicBool::new(false),
        })
    }

    fn is_stateless(&self) -> bool {
        self.stateless.load(Ordering::Relaxed)
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

    /// Build the POST for `body`.
    ///
    /// `Mcp-Method`, `Mcp-Name` and `MCP-Protocol-Version` are all
    /// 2026-07-28 request metadata, and all three ride on the same gate: we
    /// send them only when *this* message is on the new revision — either the
    /// transport negotiated it, or the body itself declares it in `_meta`.
    ///
    /// The backwards-compatibility contract is that an older peer sees the
    /// exact bytes it saw before this revision existed, and it applies to the
    /// routing pair too: `serve::proxy::backend_tool_call_params` strips
    /// `_meta` from a backend call for precisely that reason, so emitting
    /// 2026-07-28 headers on the same hop would contradict it. It is also what
    /// makes `serve::http::status_for_response`'s "-32020 is unreachable for a
    /// legacy peer" true rather than aspirational.
    ///
    /// Deriving the gate from the body — not from negotiated state alone — is
    /// what keeps the negotiation traffic routable: the `server/discover`
    /// probe runs before negotiation finishes but carries `_meta`, so it still
    /// goes out fully labelled. The spec also *requires* the version header to
    /// equal `_meta`'s `io.modelcontextprotocol/protocolVersion` and rejects a
    /// mismatch with `400` + `-32020`; reading both from the same body makes
    /// them agree by construction.
    ///
    /// `Mcp-Param-*` is gated one layer up, in `McpClient::param_headers`,
    /// which knows the tool annotations these come from.
    fn build_request(&self, body: &str, meta: &RequestMeta<'_>) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if self.is_stateless() || meta.protocol_version.is_some() {
            if let Some(value) = header_value(meta.method) {
                req = req.header(HEADER_MCP_METHOD, value);
            }
            if let Some(value) = meta.name.and_then(header_value) {
                req = req.header(HEADER_MCP_NAME, value);
            }
            if let Some(version) = meta.protocol_version {
                req = req.header(HEADER_MCP_PROTOCOL_VERSION, version);
            }
        }
        for (name, value) in meta.params {
            req = req.header(name, value);
        }

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

        // `Mcp-Session-Id` was removed in 2026-07-28 — sessions are gone, not
        // renamed. Keep sending it only while we speak an older revision.
        if !self.is_stateless() {
            if let Some(ref session_id) = *self.session_id.lock().unwrap() {
                req = req.header("Mcp-Session-Id", session_id);
            }
        }

        // W3C traceparent/tracestate so the upstream MCP backend can
        // continue the trace. Skip the allocation entirely when telemetry
        // is disabled or the operator opted out — this is the proxy's
        // hottest path.
        if crate::telemetry::should_inject_traceparent() {
            let mut otel_headers = HashMap::<String, String>::new();
            crate::telemetry::inject_traceparent(&mut otel_headers);
            for (k, v) in otel_headers {
                req = req.header(k, v);
            }
        }

        req.body(body.to_string())
    }

    fn capture_session_id(&self, resp: &reqwest::Response) {
        if self.is_stateless() {
            return;
        }
        if let Some(session_id) = resp.headers().get("mcp-session-id") {
            *self.session_id.lock().unwrap() =
                Some(session_id.to_str().unwrap_or_default().to_string());
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        self.request_with_headers(msg, &[]).await
    }

    async fn request_with_headers(
        &self,
        msg: &JsonRpcRequest,
        extra_headers: &[(String, String)],
    ) -> Result<JsonRpcResponse> {
        let body = serde_json::to_string(msg)?;
        let mcp_name = protocol::mcp_name_for(&msg.method, msg.params.as_ref());
        let meta = RequestMeta {
            params: extra_headers,
            ..RequestMeta::of(&msg.method, msg.params.as_ref(), mcp_name.as_deref())
        };

        let resp = self
            .build_request(&body, &meta)
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
                .build_request(&body, &meta)
                .send()
                .await
                .context("failed to retry HTTP request after auth")?;

            self.capture_session_id(&resp);
            let status = resp.status();
            let location = header_str(&resp, reqwest::header::LOCATION);
            let text = resp.text().await.context("failed to read HTTP response")?;

            if !status.is_success() {
                return Err(http_error(status, location.as_deref(), &text));
            }

            return parse_response(&text);
        }

        let location = header_str(&resp, reqwest::header::LOCATION);
        let text = resp.text().await.context("failed to read HTTP response")?;

        if !status.is_success() {
            return Err(http_error(status, location.as_deref(), &text));
        }

        parse_response(&text)
    }

    async fn notify(&self, msg: &JsonRpcNotification) -> Result<()> {
        let body = serde_json::to_string(msg)?;
        let mcp_name = protocol::mcp_name_for(&msg.method, msg.params.as_ref());
        let meta = RequestMeta::of(&msg.method, msg.params.as_ref(), mcp_name.as_deref());
        let resp = self
            .build_request(&body, &meta)
            .send()
            .await
            .context("failed to send HTTP notification")?;

        self.capture_session_id(&resp);
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }

    fn set_protocol_version(&self, version: &str) {
        self.stateless
            .store(protocol::is_stateless_version(version), Ordering::Relaxed);
    }
}

/// Read a response header as a `String`, when it is present and printable.
fn header_str(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers().get(name)?.to_str().ok().map(str::to_string)
}

/// Turn a non-success response into an error a person can act on.
///
/// A redirect is the case worth naming: an MCP endpoint answers JSON-RPC
/// directly, so a 3xx means an auth gateway intercepted the request and is
/// pointing at a login page. The body is HTML nobody wants echoed, and the
/// `Location` host is the actual clue.
fn http_error(status: reqwest::StatusCode, location: Option<&str>, body: &str) -> anyhow::Error {
    if status.is_redirection() {
        let target = location
            .and_then(|l| reqwest::Url::parse(l).ok())
            .and_then(|u| u.host_str().map(str::to_string));
        return match target {
            Some(host) => anyhow::anyhow!(
                "HTTP {status}: the endpoint redirected to {host} instead of answering. \
                 That is an auth gateway, not an MCP server — check that your VPN or SSO \
                 session is active."
            ),
            None => anyhow::anyhow!(
                "HTTP {status}: the endpoint redirected instead of answering, which means \
                 an auth gateway intercepted the request"
            ),
        };
    }
    // Keep the body for real API errors, but do not paste a login page into
    // the log.
    let snippet: String = body.chars().take(400).collect();
    anyhow::anyhow!("HTTP error {status}: {snippet}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{MAX_HEADER_VALUE_LEN, PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY};
    use serde_json::json;

    /// An auth gateway (Cloudflare Access, an SSO proxy) answers a redirect
    /// instead of JSON-RPC. Following it lands on a login page and the parse
    /// error blames the JSON, several layers away from the real cause, so the
    /// redirect has to be named where it happens.
    #[test]
    fn a_redirect_says_it_is_an_auth_gateway() {
        let err = http_error(
            reqwest::StatusCode::FOUND,
            Some(
                "https://buserbrasil.cloudflareaccess.com/cdn-cgi/access/login/mcp.buser.io?kid=x",
            ),
            "<html><head><title>302 Found</title></head></html>",
        )
        .to_string();

        assert!(err.contains("302"), "{err}");
        assert!(err.contains("buserbrasil.cloudflareaccess.com"), "{err}");
        assert!(err.contains("auth gateway"), "{err}");
        // The login page itself is noise, and can be large.
        assert!(!err.contains("<html>"), "{err}");
    }

    #[test]
    fn a_redirect_without_a_location_still_names_the_cause() {
        let err = http_error(reqwest::StatusCode::TEMPORARY_REDIRECT, None, "").to_string();
        assert!(err.contains("auth gateway"), "{err}");
    }

    /// A real API error still carries its body, or debugging a 4xx from the
    /// backend gets harder rather than easier.
    #[test]
    fn a_normal_http_error_keeps_its_body() {
        let err = http_error(
            reqwest::StatusCode::BAD_REQUEST,
            None,
            r#"{"error":"tool not found"}"#,
        )
        .to_string();
        assert!(err.contains("400"), "{err}");
        assert!(err.contains("tool not found"), "{err}");
    }

    /// An error body is truncated: a gateway can answer a megabyte of HTML and
    /// that has no business in a log line.
    #[test]
    fn an_oversized_error_body_is_truncated() {
        let err = http_error(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            None,
            &"x".repeat(10_000),
        )
        .to_string();
        assert!(err.len() < 600, "error was {} chars", err.len());
    }

    fn transport() -> HttpTransport {
        HttpTransport::new("http://localhost:9/mcp", &HashMap::new()).unwrap()
    }

    /// A transport that has negotiated 2026-07-28 — the only peer that is
    /// sent the request-metadata headers at all.
    fn stateless_transport() -> HttpTransport {
        let t = transport();
        t.set_protocol_version(PROTOCOL_VERSION);
        t
    }

    /// Build the POST the way [`Transport::request`] does and hand back its
    /// headers, so tests assert on what actually goes on the wire.
    fn headers_for(t: &HttpTransport, req: &JsonRpcRequest) -> reqwest::header::HeaderMap {
        headers_with_params(t, req, &[])
    }

    /// Same, plus the `Mcp-Param-*` headers the client would have computed
    /// from the tool's `x-mcp-header` annotations.
    fn headers_with_params(
        t: &HttpTransport,
        req: &JsonRpcRequest,
        params: &[(String, String)],
    ) -> reqwest::header::HeaderMap {
        let body = serde_json::to_string(req).unwrap();
        let name = protocol::mcp_name_for(&req.method, req.params.as_ref());
        let meta = RequestMeta {
            params,
            ..RequestMeta::of(&req.method, req.params.as_ref(), name.as_deref())
        };
        t.build_request(&body, &meta)
            .build()
            .expect("request must be buildable")
            .headers()
            .clone()
    }

    /// A stateless request body, carrying the `_meta` the client attaches.
    fn stateless_params(mut params: serde_json::Value, version: &str) -> serde_json::Value {
        params["_meta"] = json!({ protocol::meta_keys::PROTOCOL_VERSION: version });
        params
    }

    fn header(map: &reqwest::header::HeaderMap, key: &str) -> Option<String> {
        map.get(key).map(|v| v.to_str().unwrap().to_string())
    }

    // --- Mcp-Method / Mcp-Name ---

    #[test]
    fn routing_headers_name_the_targeted_primitive() {
        let t = stateless_transport();
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"})));
        let h = headers_for(&t, &req);

        assert_eq!(header(&h, HEADER_MCP_METHOD).as_deref(), Some("tools/call"));
        assert_eq!(header(&h, HEADER_MCP_NAME).as_deref(), Some("search"));
    }

    #[test]
    fn routing_headers_use_the_uri_for_resources() {
        let t = stateless_transport();
        let req = JsonRpcRequest::new(1, "resources/read", Some(json!({"uri": "file:///a/b"})));
        let h = headers_for(&t, &req);

        assert_eq!(
            header(&h, HEADER_MCP_METHOD).as_deref(),
            Some("resources/read")
        );
        assert_eq!(header(&h, HEADER_MCP_NAME).as_deref(), Some("file:///a/b"));
    }

    /// The routing pair is 2026-07-28 metadata, so it rides on the same gate
    /// as `MCP-Protocol-Version`: a peer that never agreed to the revision
    /// must see the bytes it saw before the revision existed. Sending it
    /// anyway is what contradicted `backend_tool_call_params` — which strips
    /// `_meta` from the very same hop for the very same reason.
    #[test]
    fn legacy_peers_receive_no_routing_headers() {
        let t = transport();
        let reqs = || {
            [
                JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "search"}))),
                JsonRpcRequest::new(2, "resources/read", Some(json!({"uri": "file:///a"}))),
                JsonRpcRequest::new(3, "tools/list", None),
                JsonRpcRequest::new(
                    4,
                    "initialize",
                    Some(json!({"protocolVersion": "2024-11-05"})),
                ),
            ]
        };
        // Un-negotiated (the handshake itself) and negotiated-legacy alike.
        for version in [None, Some(PROTOCOL_VERSION_LEGACY), Some("2024-11-05")] {
            if let Some(v) = version {
                t.set_protocol_version(v);
            }
            for req in reqs() {
                let h = headers_for(&t, &req);
                for name in [
                    HEADER_MCP_METHOD,
                    HEADER_MCP_NAME,
                    HEADER_MCP_PROTOCOL_VERSION,
                ] {
                    assert!(
                        h.get(name).is_none(),
                        "{version:?} {} leaked {name}",
                        req.method
                    );
                }
            }
        }

        // Non-vacuity: the same requests on a 2026-07-28 transport DO carry
        // the routing pair, so the loop above is not passing by accident.
        let new = stateless_transport();
        for req in reqs() {
            assert!(
                headers_for(&new, &req).get(HEADER_MCP_METHOD).is_some(),
                "{} lost its routing header on the new revision",
                req.method
            );
        }
    }

    /// Methods that address no single primitive get the method header only —
    /// an empty `Mcp-Name` would be a lie, not a default.
    #[test]
    fn list_methods_send_no_name_header() {
        let t = stateless_transport();
        for method in ["tools/list", "prompts/list", "resources/list", "initialize"] {
            let req = JsonRpcRequest::new(1, method, None);
            let h = headers_for(&t, &req);
            assert_eq!(header(&h, HEADER_MCP_METHOD).as_deref(), Some(method));
            assert!(h.get(HEADER_MCP_NAME).is_none(), "{method} sent a name");
        }
    }

    /// A tool name with a newline in it is a header-injection vector and an
    /// instant `reqwest` build failure. It must neither panic nor break the
    /// request.
    #[test]
    fn header_hostile_names_do_not_break_the_request() {
        let t = stateless_transport();
        for hostile in [
            "evil\r\nX-Injected: 1",
            "line\nbreak",
            "null\0byte",
            "emoji 🚀 tool",
            "acentuação",
            "tab\there",
        ] {
            let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": hostile})));
            let h = headers_for(&t, &req);
            let sent = header(&h, HEADER_MCP_NAME).expect("a name header is still sent");
            assert!(
                sent.is_ascii() && !sent.contains(['\r', '\n']),
                "{hostile:?} produced unsafe header value {sent:?}"
            );
            assert!(
                h.get("x-injected").is_none(),
                "{hostile:?} injected a header"
            );
        }
    }

    /// A pathological name is dropped rather than truncated: a truncated name
    /// would route to the wrong place, which is worse than no name.
    #[test]
    fn oversized_names_are_dropped_not_truncated() {
        let t = stateless_transport();
        let huge = "a".repeat(MAX_HEADER_VALUE_LEN + 1);
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": huge})));
        let h = headers_for(&t, &req);

        assert!(h.get(HEADER_MCP_NAME).is_none());
        // The request itself still goes out.
        assert_eq!(header(&h, HEADER_MCP_METHOD).as_deref(), Some("tools/call"));
    }

    // --- Mcp-Session-Id across revisions ---

    /// `Mcp-Session-Id` is how every backend in the wild tracks us today. An
    /// un-negotiated transport, and a legacy-negotiated one, must keep
    /// sending it.
    #[test]
    fn session_id_is_sent_on_the_legacy_path() {
        let t = transport();
        *t.session_id.lock().unwrap() = Some("sess-123".to_string());

        let req = JsonRpcRequest::new(1, "tools/list", None);
        assert_eq!(
            header(&headers_for(&t, &req), "Mcp-Session-Id").as_deref(),
            Some("sess-123"),
            "an un-negotiated transport must behave exactly like today"
        );

        t.set_protocol_version(PROTOCOL_VERSION_LEGACY);
        assert_eq!(
            header(&headers_for(&t, &req), "Mcp-Session-Id").as_deref(),
            Some("sess-123")
        );
        for old in ["2025-06-18", "2024-11-05"] {
            t.set_protocol_version(old);
            assert!(
                headers_for(&t, &req).get("Mcp-Session-Id").is_some(),
                "{old} still has sessions"
            );
        }
    }

    /// 2026-07-28 removed sessions outright — the header must stop, not be
    /// renamed or emptied.
    #[test]
    fn session_id_stops_once_stateless() {
        let t = transport();
        *t.session_id.lock().unwrap() = Some("sess-123".to_string());
        t.set_protocol_version(PROTOCOL_VERSION);

        let req = JsonRpcRequest::new(1, "tools/list", None);
        assert!(headers_for(&t, &req).get("Mcp-Session-Id").is_none());
    }

    // --- MCP-Protocol-Version ---

    /// The spec makes the header mandatory on every POST and requires it to
    /// equal `_meta`'s `protocolVersion`. Deriving it from the body is what
    /// makes the two agree by construction.
    #[test]
    fn protocol_version_header_mirrors_the_body_meta() {
        let t = transport();
        let req = JsonRpcRequest::new(
            1,
            "tools/call",
            Some(stateless_params(json!({"name": "x"}), PROTOCOL_VERSION)),
        );
        let h = headers_for(&t, &req);

        assert_eq!(
            header(&h, HEADER_MCP_PROTOCOL_VERSION).as_deref(),
            Some(PROTOCOL_VERSION)
        );
        assert_eq!(
            h[HEADER_MCP_PROTOCOL_VERSION],
            req.params.as_ref().unwrap()["_meta"][protocol::meta_keys::PROTOCOL_VERSION]
                .as_str()
                .unwrap(),
            "a mismatch here is a -32020 HeaderMismatch from the server"
        );
    }

    /// The probe runs before negotiation finishes, so the transport has no
    /// negotiated version to report — the body's `_meta` is the only source
    /// that can be right, and it is.
    #[test]
    fn discovery_probe_carries_the_protocol_version_header() {
        let t = transport();
        assert!(
            !t.is_stateless(),
            "probe runs on an un-negotiated transport"
        );

        let req = JsonRpcRequest::new(
            1,
            "server/discover",
            Some(stateless_params(json!({}), PROTOCOL_VERSION)),
        );
        let h = headers_for(&t, &req);
        assert_eq!(
            header(&h, HEADER_MCP_PROTOCOL_VERSION).as_deref(),
            Some(PROTOCOL_VERSION)
        );
        // Gating the routing pair on the revision must not make the
        // negotiation traffic itself unroutable: the probe declares the
        // revision in its body, so it is labelled like any other new-revision
        // message.
        assert_eq!(
            header(&h, HEADER_MCP_METHOD).as_deref(),
            Some("server/discover")
        );
    }

    /// Backwards compatibility: a legacy request carries no `_meta`, so it
    /// carries no version header either — the exact bytes an older peer saw
    /// before this revision existed. 2025-06-18 does define the header, but
    /// adding it to a peer that never agreed to it is the change this project
    /// refuses to make.
    #[test]
    fn legacy_requests_send_no_protocol_version_header() {
        let t = transport();
        for version in [PROTOCOL_VERSION_LEGACY, "2025-06-18", "2024-11-05"] {
            t.set_protocol_version(version);
            for req in [
                JsonRpcRequest::new(1, "tools/list", None),
                JsonRpcRequest::new(2, "tools/call", Some(json!({"name": "x"}))),
                JsonRpcRequest::new(3, "initialize", Some(json!({"protocolVersion": version}))),
            ] {
                assert!(
                    headers_for(&t, &req)
                        .get(HEADER_MCP_PROTOCOL_VERSION)
                        .is_none(),
                    "{version} {} must stay byte-identical",
                    req.method
                );
            }
        }
    }

    // --- Mcp-Param-* (x-mcp-header) ---

    #[test]
    fn param_headers_are_mirrored_onto_the_request() {
        let t = transport();
        let req = JsonRpcRequest::new(
            1,
            "tools/call",
            Some(stateless_params(
                json!({"name": "execute_sql", "arguments": {"region": "us-west1"}}),
                PROTOCOL_VERSION,
            )),
        );
        let h = headers_with_params(
            &t,
            &req,
            &[("Mcp-Param-Region".to_string(), "us-west1".to_string())],
        );

        assert_eq!(header(&h, "Mcp-Param-Region").as_deref(), Some("us-west1"));
        // The standard headers still go out alongside them.
        assert_eq!(header(&h, HEADER_MCP_NAME).as_deref(), Some("execute_sql"));
    }

    /// The values arrive already encoded by `protocol::header_value`, so a
    /// hostile one cannot inject a header even at this layer.
    #[test]
    fn encoded_param_headers_cannot_inject() {
        let t = transport();
        let hostile = header_value("evil\r\nX-Injected: 1").expect("encodable");
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "t"})));
        let h = headers_with_params(&t, &req, &[("Mcp-Param-Evil".to_string(), hostile)]);

        assert!(h.get("x-injected").is_none());
        let sent = header(&h, "Mcp-Param-Evil").expect("the header still goes out");
        assert!(sent.is_ascii() && !sent.contains(['\r', '\n']));
    }

    #[test]
    fn set_protocol_version_tracks_statelessness() {
        let t = transport();
        assert!(!t.is_stateless(), "default must be the legacy behavior");

        t.set_protocol_version(PROTOCOL_VERSION);
        assert!(t.is_stateless());

        // Negotiating back down (a reconnect to an older peer) must restore
        // the legacy behavior rather than latch.
        t.set_protocol_version(PROTOCOL_VERSION_LEGACY);
        assert!(!t.is_stateless());
    }
}
