//! End-to-end test for the OAuth Authorization Server.
//!
//! Spins up a real axum server on a free localhost port, mounts the
//! AS sub-router AND a mock `/mcp` endpoint that reproduces what
//! `serve::http::mcp_handler` does w.r.t. authentication: extract
//! credentials, run them through the configured `ProviderChain`,
//! and (optionally) consult the ACL on the resulting identity.
//!
//! The whole point of this file is to exercise the cross-provider
//! contract: a single `mcp serve` instance must accept BOTH static
//! bearer tokens (local dev) AND OAuth-issued JWTs (Claude.ai web)
//! at the same `/mcp` endpoint, with ACL discriminating per role.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use reqwest::Client;
use serde_json::Value;

use crate::server_auth::{
    self,
    acl::{self, AclConfig},
    AuthIdentity, AuthProvider, BearerToken, Credentials, ProviderChain,
};

use super::{config::OAuthAsConfig, AsState, OAuthAsAuth};

#[derive(Clone)]
struct McpState {
    auth_provider: Arc<dyn AuthProvider>,
    acl: Option<AclConfig>,
}

fn extract_creds(headers: &HeaderMap) -> Credentials {
    let mut c = Credentials::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            c.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    c
}

async fn mock_mcp(
    State(state): State<McpState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let creds = extract_creds(&headers);
    let identity: AuthIdentity = match state.auth_provider.authenticate(&creds).await {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response();
        }
    };

    // Body is JSON-RPC-ish: {"method": "tools/call", "params": {"name": "..."}}
    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let tool_name = req
        .pointer("/params/name")
        .and_then(|v| v.as_str())
        .unwrap_or("tools/list");

    if let Some(acl_cfg) = &state.acl {
        let decision = acl::is_tool_allowed(&identity, tool_name, acl_cfg, None);
        if !decision.allowed {
            return (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "error": "acl_deny",
                    "subject": identity.subject,
                    "tool": tool_name,
                })),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "ok": true,
            "subject": identity.subject,
            "roles": identity.roles,
            "tool": tool_name,
        })),
    )
        .into_response()
}

struct Harness {
    base: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Harness {
    async fn start(
        cfg: Arc<OAuthAsConfig>,
        state: Arc<AsState>,
        chain: Arc<dyn AuthProvider>,
        acl: Option<AclConfig>,
    ) -> Self {
        let mcp_state = McpState {
            auth_provider: chain,
            acl,
        };
        let app = super::router(cfg.clone(), state.clone()).merge(
            Router::new()
                .route("/mcp", post(mock_mcp))
                .with_state(mcp_state),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .ok();
        });

        // Give the server a tick to come up.
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            base,
            _shutdown: tx,
        }
    }
}

fn cfg_for_e2e() -> Arc<OAuthAsConfig> {
    Arc::new(OAuthAsConfig {
        issuer_url: "http://127.0.0.1".to_string(), // overridden below per-test
        jwt_secret: "k".repeat(32),
        trusted_user_header: "x-forwarded-user".to_string(),
        trusted_groups_header: "x-forwarded-groups".to_string(),
        trusted_source_cidrs: vec!["127.0.0.0/8".to_string()],
        access_token_ttl_seconds: 3600,
        refresh_token_ttl_seconds: 2_592_000,
        authorization_code_ttl_seconds: 60,
        scopes_supported: vec!["mcp".to_string()],
        redirect_uri_allowlist: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
        injected_roles: vec!["oauth-user".to_string()],
    })
}

use super::test_helpers::InlineSaveGuard;

fn build_chain(
    cfg: Arc<OAuthAsConfig>,
    state: Arc<AsState>,
    static_bearer: Option<HashMap<String, BearerToken>>,
) -> Arc<dyn AuthProvider> {
    let mut providers: Vec<Arc<dyn AuthProvider>> = Vec::new();
    if let Some(tokens) = static_bearer {
        providers.push(Arc::new(server_auth::BearerTokenAuth::new(tokens)));
    }
    providers.push(Arc::new(OAuthAsAuth::new(cfg, state)));
    Arc::new(ProviderChain::new(providers))
}

async fn run_oauth_flow(client: &Client, base: &str) -> (String, String) {
    use crate::auth::oauth_primitives::generate_pkce;

    // 1. DCR.
    let dcr: Value = client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = dcr["client_id"].as_str().unwrap().to_string();

    // 2. Authorize (no redirect-following — we want to read the
    // Location header).
    let (verifier, challenge) = generate_pkce();
    let no_redirect_client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let auth_resp = no_redirect_client
        .get(format!("{base}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", "csrf-state"),
            ("scope", "mcp"),
        ])
        .header("X-Forwarded-User", "alice@example.com")
        .header("X-Forwarded-Groups", "dev")
        .send()
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), 303, "expected 303 redirect");
    let loc = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let url = url::Url::parse(&loc).unwrap();
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();

    // 3. Token exchange.
    let tok: Value = client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access = tok["access_token"].as_str().unwrap().to_string();
    (client_id, access)
}

#[tokio::test]
async fn e2e_static_bearer_path_authenticates() {
    let _g = InlineSaveGuard::acquire();
    let cfg = cfg_for_e2e();
    let state = Arc::new(AsState::default());

    let mut tokens = HashMap::new();
    tokens.insert(
        "tok-local-dev".to_string(),
        BearerToken::Extended {
            subject: "avelino".to_string(),
            roles: vec!["admin".to_string()],
        },
    );
    let chain = build_chain(cfg.clone(), state.clone(), Some(tokens));

    let harness = Harness::start(cfg, state, chain, None).await;
    let client = Client::new();

    let resp = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", "Bearer tok-local-dev")
        .json(&serde_json::json!({"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["subject"], "avelino");
}

#[tokio::test]
async fn e2e_oauth_flow_then_call_mcp() {
    let _g = InlineSaveGuard::acquire();
    let cfg = cfg_for_e2e();
    let state = Arc::new(AsState::default());
    let chain = build_chain(cfg.clone(), state.clone(), None);

    let harness = Harness::start(cfg, state, chain, None).await;
    let client = Client::new();
    let (_, access) = run_oauth_flow(&client, &harness.base).await;

    let resp = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["subject"], "alice@example.com");
    let roles: Vec<String> = serde_json::from_value(body["roles"].clone()).unwrap();
    assert!(roles.contains(&"oauth-user".to_string()));
}

#[tokio::test]
async fn e2e_both_providers_coexist_in_same_instance() {
    // The exact scenario from issue #90: dev-local static bearer
    // and Claude.ai-web OAuth JWT must both authenticate against
    // /mcp on the same running instance.
    let _g = InlineSaveGuard::acquire();
    let cfg = cfg_for_e2e();
    let state = Arc::new(AsState::default());
    let mut tokens = HashMap::new();
    tokens.insert(
        "tok-local-dev".to_string(),
        BearerToken::Extended {
            subject: "avelino".to_string(),
            roles: vec!["admin".to_string()],
        },
    );
    let chain = build_chain(cfg.clone(), state.clone(), Some(tokens));

    let harness = Harness::start(cfg, state, chain, None).await;
    let client = Client::new();

    // Path A: static bearer.
    let resp_a = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", "Bearer tok-local-dev")
        .json(&serde_json::json!({"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a.status(), 200);
    assert_eq!(resp_a.json::<Value>().await.unwrap()["subject"], "avelino");

    // Path B: OAuth flow on the same instance, no restart.
    let (_, access) = run_oauth_flow(&client, &harness.base).await;
    let resp_b = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), 200);
    assert_eq!(
        resp_b.json::<Value>().await.unwrap()["subject"],
        "alice@example.com"
    );

    // Path A again — proves no state leaked between the two calls.
    let resp_a2 = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", "Bearer tok-local-dev")
        .json(&serde_json::json!({"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a2.status(), 200);
}

#[tokio::test]
async fn e2e_acl_discriminates_oauth_vs_admin_roles() {
    // Cross-test ACL × OAuth (the second briefing requirement):
    // OAuth-authenticated identity carries `oauth-user` role (via
    // injectedRoles); ACL grants `oauth-user` only `sentry__*`.
    // Static-bearer identity carries `admin` and gets `*`.
    let _g = InlineSaveGuard::acquire();
    let cfg = cfg_for_e2e();
    let state = Arc::new(AsState::default());
    let mut tokens = HashMap::new();
    tokens.insert(
        "tok-local-dev".to_string(),
        BearerToken::Extended {
            subject: "avelino".to_string(),
            roles: vec!["admin".to_string()],
        },
    );
    let chain = build_chain(cfg.clone(), state.clone(), Some(tokens));

    // Legacy ACL schema — first-match-wins, no ToolContext required.
    // The role-based schema is functionally richer but needs server
    // alias context that this in-process harness doesn't surface; for
    // exercising the cross-provider × per-role discrimination the
    // briefing requires, the legacy schema is the right tool.
    let acl_json = r#"{
        "default": "deny",
        "rules": [
            {"roles": ["admin"],      "tools": ["*"],          "policy": "allow"},
            {"roles": ["oauth-user"], "tools": ["sentry__*"],  "policy": "allow"}
        ]
    }"#;
    let acl: AclConfig = serde_json::from_str(acl_json).unwrap();

    let harness = Harness::start(cfg, state, chain, Some(acl)).await;
    let client = Client::new();

    let (_, access) = run_oauth_flow(&client, &harness.base).await;
    // OAuth user calling sentry__* — allowed.
    let allowed: Value = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({
            "method":"tools/call",
            "params":{"name":"sentry__list_issues"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        allowed["ok"], true,
        "sentry tool must be allowed: {allowed}"
    );

    // OAuth user calling github__create_issue — denied.
    let denied: Value = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({
            "method":"tools/call",
            "params":{"name":"github__create_issue"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(denied["error"], "acl_deny");

    // Static-bearer (admin) calling the same denied tool — allowed.
    let admin_ok: Value = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", "Bearer tok-local-dev")
        .json(&serde_json::json!({
            "method":"tools/call",
            "params":{"name":"github__create_issue"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admin_ok["ok"], true, "admin must bypass tool deny");
}

#[tokio::test]
async fn e2e_mcp_rejects_invalid_jwt() {
    let _g = InlineSaveGuard::acquire();
    let cfg = cfg_for_e2e();
    let state = Arc::new(AsState::default());
    let chain = build_chain(cfg.clone(), state.clone(), None);

    let harness = Harness::start(cfg, state, chain, None).await;
    let client = Client::new();

    let resp = client
        .post(format!("{}/mcp", harness.base))
        .header("Authorization", "Bearer not.a.real.jwt")
        .json(&serde_json::json!({"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn e2e_well_known_endpoints_advertise_full_metadata() {
    let _g = InlineSaveGuard::acquire();
    let cfg = cfg_for_e2e();
    let state = Arc::new(AsState::default());
    let chain = build_chain(cfg.clone(), state.clone(), None);

    let harness = Harness::start(cfg, state, chain, None).await;
    let client = Client::new();

    let pr: Value = client
        .get(format!(
            "{}/.well-known/oauth-protected-resource",
            harness.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(pr["authorization_servers"].is_array());

    let asm: Value = client
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            harness.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asm["code_challenge_methods_supported"][0], "S256");
    assert!(asm["registration_endpoint"]
        .as_str()
        .unwrap()
        .ends_with("/register"));
}
